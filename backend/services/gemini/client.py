"""
Kali AI - Gemini API Client
Integrates with Google's Gemini API using native function/tool calling.
Provides a realistic demo fallback when no API key is configured.
"""

from __future__ import annotations

import json
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

        response = await asyncio.to_thread(
            self._client.models.generate_content,
            model=self._model_name,
            contents=contents,
            config=config,
        )

        if not response.candidates:
            return AIResponse(text="No response generated.", finish_reason="error")

        candidate = response.candidates[0]
        parts = candidate.content.parts if candidate.content else []

        # Check for function call
        for part in parts:
            if part.function_call:
                fc = part.function_call
                # Accompanying thought text if any
                text_parts = [p.text for p in parts if p.text]
                return AIResponse(
                    text="\n".join(text_parts) if text_parts else "",
                    function_call={
                        "name": fc.name,
                        "args": dict(fc.args) if fc.args else {},
                    },
                    finish_reason="function_call",
                )

        # Standard text response
        text_parts = [p.text for p in parts if p.text]
        return AIResponse(
            text="\n".join(text_parts) if text_parts else "",
            finish_reason="stop",
        )


class DemoClient:
    """Simulates realistic Gemini reasoning, planning, tool-calling, and reporting."""

    def __init__(self) -> None:
        logger.info("DemoClient initialized — running in DEMO MODE")

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        # Determine current stage of conversation
        func_results = [m for m in messages if m.get("role") == "function_result"]
        has_plan = any(
            m.get("role") == "model" and "Assessment Plan" in m.get("content", "")
            for m in messages
        )

        # 1. First interaction: Generate Plan
        if not has_plan and len(func_results) == 0:
            target = "localhost"
            for m in messages:
                if m.get("role") == "user" and "Authorized target:" in m.get("content", ""):
                    for line in m["content"].splitlines():
                        if "Authorized target:" in line:
                            target = line.split(":", 1)[1].strip()

            plan_text = (
                f"### [DEMO MODE] AI Assessment Plan for `{target}`\n"
                "1. **Technology Profiling**: Identify web server, CMS, and active tech stack using WhatWeb.\n"
                "2. **Exposed Service Discovery**: Map listening ports and network services using Nmap.\n"
                "3. **Vulnerability & Exposure Scan**: Detect known CVEs, misconfigurations, and sensitive endpoints using Nuclei.\n"
                "4. **Synthesis & Correlation**: Correlate findings, prioritize risks, and produce an executive report."
            )
            return AIResponse(
                text=plan_text,
                finish_reason="stop",
                demo=True,
                plan_text=plan_text,
            )

        # 2. Plan already established: select tools adaptively
        available_ids = [t.id for t in tools]
        target = "localhost"
        for m in messages:
            if m.get("role") == "user" and "Authorized target:" in m.get("content", ""):
                for line in m["content"].splitlines():
                    if "Authorized target:" in line:
                        target = line.split(":", 1)[1].strip()

        # Step 1: WhatWeb
        if len(func_results) == 0:
            return AIResponse(
                text="Selected WhatWeb to identify the target's web server and CMS technologies before determining further vulnerability checks.",
                function_call={"name": "whatweb_scan", "args": {"target": target}},
                finish_reason="function_call",
                demo=True,
            )

        # Step 2: Adaptive - inspect WhatWeb result and run Nmap
        if len(func_results) == 1:
            last_res = func_results[0].get("content", {})
            return AIResponse(
                text="WhatWeb detected web server components. Now selecting Nmap with service detection profile to verify open ports and network exposure.",
                function_call={"name": "nmap_scan", "args": {"target": target, "profile": "service_detection"}},
                finish_reason="function_call",
                demo=True,
            )

        # Step 3: Adaptive - inspect Nmap and run Nuclei
        if len(func_results) == 2:
            return AIResponse(
                text="Nmap revealed open HTTP/HTTPS services. Selected Nuclei with default templates to check for misconfigurations and known exposures.",
                function_call={"name": "nuclei_scan", "args": {"target": target, "templates": "default"}},
                finish_reason="function_call",
                demo=True,
            )

        # Step 4: Finished all assessments -> Generate Final Report
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
