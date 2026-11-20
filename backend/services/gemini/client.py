"""
Kali AI - Gemini API Client
Integrates with Google's Gemini API using native function/tool calling.
Provides an intelligent, context-aware demo client when no API key is configured.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.core.config import get_settings
from backend.models.schemas import ToolDefinition

logger = logging.getLogger(__name__)


def _build_function_declarations(tools: list[ToolDefinition]) -> list[dict[str, Any]]:
    """Convert ToolDefinitions into Gemini-compatible function declarations."""
    declarations = []
    for tool in tools:
        declarations.append({
            "name": tool.id,
            "description": tool.description,
            "parameters": tool.input_schema,
        })
    return declarations


class AIResponse:
    """Wraps an AI response which may contain text and/or a function call."""

    def __init__(
        self,
        text: str = "",
        function_call: dict[str, Any] | None = None,
        finish_reason: str = "stop",
        demo: bool = False,
        plan_text: str | None = None,
    ):
        self.text = text
        self.function_call = function_call  # {"name": "tool_id", "args": {...}}
        self.finish_reason = finish_reason
        self.demo = demo
        self.plan_text = plan_text

    @property
    def has_function_call(self) -> bool:
        return self.function_call is not None

    def __repr__(self) -> str:
        if self.has_function_call:
            return f"AIResponse(function_call={self.function_call['name']}, text={self.text[:40]})"
        return f"AIResponse(text={self.text[:80]}...)"


class GeminiClient:
    """Wraps google-genai SDK for real Gemini API function calling."""

    def __init__(self) -> None:
        settings = get_settings()
        self._model_name = settings.GEMINI_MODEL

        from google import genai
        self._client = genai.Client(api_key=settings.GEMINI_API_KEY)
        self._genai = genai

        logger.info("GeminiClient initialized with model=%s", self._model_name)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        from google.genai import types
        import asyncio

        func_decls = _build_function_declarations(tools)

        gemini_tools = [types.Tool(function_declarations=[
            types.FunctionDeclaration(
                name=fd["name"],
                description=fd["description"],
                parameters=fd["parameters"],
            )
            for fd in func_decls
        ])] if func_decls else []

        contents = []
        for msg in messages:
            role = msg["role"]
            if role == "system":
                continue

            if role == "function_result":
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part.from_function_response(
                        name=msg["name"],
                        response=msg["content"],
                    )],
                ))
            elif role == "model_function_call":
                contents.append(types.Content(
                    role="model",
                    parts=[types.Part.from_function_call(
                        name=msg["name"],
                        args=msg["args"],
                    )],
                ))
            else:
                gemini_role = "user" if role == "user" else "model"
                contents.append(types.Content(
                    role=gemini_role,
                    parts=[types.Part.from_text(text=msg["content"])],
                ))

        config = types.GenerateContentConfig(
            system_instruction=system_prompt if system_prompt else None,
            tools=gemini_tools if gemini_tools else None,
            temperature=0.2,
        )

        try:
            response = await asyncio.to_thread(
                self._client.models.generate_content,
                model=self._model_name,
                contents=contents,
                config=config,
            )
        except Exception as e:
            err_str = str(e)
            if any(err in err_str for err in ["RESOURCE_EXHAUSTED", "429", "503", "UNAVAILABLE"]):
                logger.warning("Gemini API error (%s). Falling back to DemoClient.", err_str[:80])
                demo = DemoClient()
                return await demo.chat(messages, tools, system_prompt)
            raise

        if not response.candidates:
            return AIResponse(text="No response generated.", finish_reason="error")

        candidate = response.candidates[0]
        parts = candidate.content.parts if candidate.content else []

        for part in parts:
            if part.function_call:
                fc = part.function_call
                text_parts = [p.text for p in parts if p.text]
                return AIResponse(
                    text="\n".join(text_parts) if text_parts else "",
                    function_call={
                        "name": fc.name,
                        "args": dict(fc.args) if fc.args else {},
                    },
                    finish_reason="function_call",
                )

        text_parts = [p.text for p in parts if p.text]
        return AIResponse(
            text="\n".join(text_parts) if text_parts else "",
            finish_reason="stop",
        )


class DemoClient:
    """
    Intelligent simulated reasoning engine for Demo Mode.
    Accurately classifies requests into:
      1. Conversational questions (capabilities, help, tool info) -> direct text reply.
      2. Specific single-tool tasks (e.g. nmap only, whatweb only, nuclei only) -> targeted plan & execution.
      3. Full assessments -> multi-step adaptive plan and execution.
    """

    def __init__(self) -> None:
        logger.info("DemoClient initialized — running in DEMO MODE")

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        # Extract objective and target
        user_objective = ""
        target = "localhost"
        for m in messages:
            if m.get("role") == "user":
                content = m.get("content", "")
                for line in content.splitlines():
                    if line.startswith("Objective:"):
                        user_objective = line.split(":", 1)[1].strip()
                    elif line.startswith("Authorized target:"):
                        target = line.split(":", 1)[1].strip()
                if not user_objective:
                    user_objective = content

        obj_lower = user_objective.lower()
        func_results = [m for m in messages if m.get("role") == "function_result"]
        has_plan = any(
            m.get("role") == "model" and "Assessment Plan" in m.get("content", "")
            for m in messages
        )

        # ── 1. Conversational / Informational Queries ──
        info_keywords = [
            "capabilities", "capability", "what can you do", "who are you",
            "what are your tools", "list tools", "what tools", "help",
            "how does it work", "how do you work", "commands",
        ]
        is_greeting = obj_lower in ["hi", "hello", "hey", "test"]
        is_info_query = any(k in obj_lower for k in info_keywords) or is_greeting

        # If it's an informational query and not a scan request
        if is_info_query and not any(kw in obj_lower for kw in ["scan", "assess", "check", "audit", "test target"]):
            info_text = (
                "### 🛡️ Kali AI — Autonomous Cybersecurity Operator\n\n"
                "I am an intelligent security operator. I understand user security objectives, "
                "formulate tailored assessment plans, select approved security tools, enforce safety boundaries, "
                "analyze evidence, and generate prioritized risk reports.\n\n"
                "#### 🧰 Registered Security Capabilities:\n"
                "- **Nmap** (`nmap_scan`) — Service discovery, open port mapping, and OS fingerprinting.\n"
                "- **WhatWeb** (`whatweb_scan`) — Web server, CMS (WordPress/Drupal), and tech stack identification.\n"
                "- **Nuclei** (`nuclei_scan`) — Template-driven detection of known CVEs and exposures.\n"
                "- **Nikto** (`nikto_scan`) — Web server configuration auditing and sensitive file detection.\n"
                "- **SSLyze** (`sslyze_scan`) — TLS/SSL cryptographic configuration and certificate analysis.\n"
                "- **OWASP ZAP** (`zap_scan`) — Passive and active web application vulnerability scanning.\n"
                "- **Gobuster** (`gobuster_scan`) — Wordlist-based endpoint and directory discovery.\n\n"
                "#### 💡 Example Commands You Can Try:\n"
                "- `Perform a basic security assessment of my test website` *(multi-step assessment)*\n"
                "- `Local nmap scan` or `Check open ports on localhost` *(Nmap port discovery only)*\n"
                "- `Identify technologies on localhost` *(WhatWeb technology profiling only)*\n"
                "- `Scan for vulnerabilities on localhost` *(Nuclei CVE checks only)*\n"
                "- `Check SSL/TLS configuration on localhost` *(SSLyze cryptographic review)*\n"
                "- `Discover hidden paths on localhost` *(Gobuster directory enumeration)*\n\n"
                "> **Security Restriction:** Scans are only allowed on targets listed in `ALLOWED_TARGETS` (`.env`)."
            )
            return AIResponse(text=info_text, finish_reason="stop", demo=True)

        # ── 2. Tool-Specific Requests ──
        tool_mappings = [
            ("nmap_scan", ["nmap", "port scan", "exposed service", "open port", "services", "open ports"], "Exposed Service & Port Discovery", {"target": target, "profile": "service_detection"}),
            ("whatweb_scan", ["whatweb", "technology", "technologies", "tech stack", "cms", "identify web"], "Web Technology & Stack Profiling", {"target": target}),
            ("nuclei_scan", ["nuclei", "vulnerability", "vulnerabilities", "cve", "misconfiguration"], "Known Vulnerability Detection", {"target": target, "templates": "default"}),
            ("sslyze_scan", ["sslyze", "ssl", "tls", "https", "certificate", "cipher"], "TLS/SSL Cryptographic Configuration Review", {"target": target}),
            ("nikto_scan", ["nikto", "web server security", "server audit"], "Web Server Configuration Audit", {"target": target}),
            ("zap_scan", ["zap", "owasp", "web app security"], "Web Application Security Scanning", {"target": target, "scan_type": "passive"}),
            ("gobuster_scan", ["gobuster", "directory", "directories", "path discovery", "endpoints"], "Web Resource & Path Discovery", {"target": target, "wordlist": "common"}),
        ]

        matched_tool = None
        # Check if user specifically requested a single tool
        is_general_assessment = any(kw in obj_lower for kw in ["basic assessment", "security assessment", "full scan", "audit website", "comprehensive"])
        if not is_general_assessment:
            for tid, keywords, title, args in tool_mappings:
                if any(kw in obj_lower for kw in keywords):
                    matched_tool = (tid, title, args)
                    break

        # Single-tool execution path
        if matched_tool:
            tid, title, args = matched_tool

            if not has_plan and len(func_results) == 0:
                plan_text = (
                    f"### [DEMO MODE] Assessment Plan: {title} for `{target}`\n"
                    f"1. **Execute {tid}**: Run `{tid}` with authorized parameters against `{target}`.\n"
                    "2. **Evidence Analysis**: Normalize findings, assess potential risk, and generate remediation guidance."
                )
                return AIResponse(text=plan_text, finish_reason="stop", demo=True, plan_text=plan_text)

            if len(func_results) == 0:
                return AIResponse(
                    text=f"Selected {tid} to perform the requested {title} against `{target}`.",
                    function_call={"name": tid, "args": args},
                    finish_reason="function_call",
                    demo=True,
                )

            # Once tool result is received -> Complete
            return AIResponse(
                text=(
                    f"## {title} Completed\n\n"
                    f"The `{tid}` assessment against `{target}` has finished. "
                    "All findings have been extracted, normalized, and displayed in the Findings tab."
                ),
                finish_reason="stop",
                demo=True,
            )

        # ── 3. Multi-Step Comprehensive Assessment ──
        if not has_plan and len(func_results) == 0:
            plan_text = (
                f"### [DEMO MODE] AI Assessment Plan for `{target}`\n"
                "1. **Technology Profiling**: Identify web server, CMS, and active tech stack using WhatWeb.\n"
                "2. **Exposed Service Discovery**: Map listening ports and network services using Nmap.\n"
                "3. **Vulnerability & Exposure Scan**: Detect known CVEs, misconfigurations, and sensitive endpoints using Nuclei.\n"
                "4. **Synthesis & Correlation**: Correlate findings, prioritize risks, and produce an executive report."
            )
            return AIResponse(text=plan_text, finish_reason="stop", demo=True, plan_text=plan_text)

        # Step 1: WhatWeb
        if len(func_results) == 0:
            return AIResponse(
                text="Selected WhatWeb to identify the target's web server and CMS technologies before determining further vulnerability checks.",
                function_call={"name": "whatweb_scan", "args": {"target": target}},
                finish_reason="function_call",
                demo=True,
            )

        # Step 2: Nmap
        if len(func_results) == 1:
            return AIResponse(
                text="WhatWeb detected web server components. Now selecting Nmap with service detection profile to verify open ports and network exposure.",
                function_call={"name": "nmap_scan", "args": {"target": target, "profile": "service_detection"}},
                finish_reason="function_call",
                demo=True,
            )

        # Step 3: Nuclei
        if len(func_results) == 2:
            return AIResponse(
                text="Nmap revealed open HTTP/HTTPS services. Selected Nuclei with default templates to check for misconfigurations and known exposures.",
                function_call={"name": "nuclei_scan", "args": {"target": target, "templates": "default"}},
                finish_reason="function_call",
                demo=True,
            )

        # Final Report
        return AIResponse(
            text=(
                "## Security Assessment Final Report\n\n"
                "All planned assessment stages have completed successfully. The findings have been normalized, "
                "correlated across reconnaissance and vulnerability tools, and prioritized in the risk matrix.\n\n"
                "Review the Findings tab for detailed remediation guidance."
            ),
            finish_reason="stop",
            demo=True,
        )


def create_ai_client() -> GeminiClient | DemoClient:
    """Instantiate the AI client according to configuration."""
    settings = get_settings()
    if settings.demo_mode:
        return DemoClient()
    return GeminiClient()
