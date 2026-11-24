"""
Kali AI - Agent Orchestrator
The core autonomous decision loop that:
  1. Sends user objective + tool definitions to Gemini.
  2. Receives either a plan, tool selection, direct response, or final analysis.
  3. Validates the function call (target, allowed profiles, limits).
  4. Executes the approved tool.
  5. Normalizes and correlates findings in real time.
  6. Returns structured results to Gemini.
  7. Loops until Gemini concludes or execution limits are reached.
  8. Generates a formal executive and technical report.
"""

from __future__ import annotations

import asyncio
import re
import logging
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

from backend.core.config import get_settings
from backend.models.schemas import (
    Assessment, AssessmentPlan, AssessmentStatus,
    AgentStep, AgentEvent, ToolCallRequest, Finding,
)
from backend.services.gemini.client import create_ai_client, AIResponse, GeminiClient, OllamaClient, OpenAIClient, AnthropicClient, DemoClient
from backend.services.tool_registry.registry import ToolRegistry, create_registry
from backend.services.security.validator import SecurityValidator
from backend.services.security.consent_gate import get_consent_gate, ConsentRequiredError
from backend.services.kali_tool_runner import run_tool as kali_run_tool, choose_tool, list_available_tools
from backend.services.file_access import read_user_path, list_directory
from backend.services.analysis.normalizer import FindingNormalizer
from backend.services.analysis.correlator import FindingCorrelator
from backend.services.reporting.generator import ReportGenerator
from backend.database.db import save_assessment, update_assessment

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Kali AI — Whiark × Kali AI — an expert autonomous cybersecurity operator and bug hunter.

You are modeled after HexStrike AI: a professional-grade security assessment platform used by ethical hackers,
penetration testers, bug bounty hunters, and security researchers.

You serve TWO modes based on the user's intent:

1. **CONVERSATIONAL MODE** (default for general questions):
   - Answer cybersecurity questions, explain concepts, help with CTFs, discuss tools and vulnerabilities.
   - Handle general knowledge questions, programming help, math, science, or casual conversation.
   - Reply directly with a clear, helpful, well-formatted response.
   - Do NOT trigger tool calls for conversational or informational questions.

2. **SECURITY ASSESSMENT MODE** (for any scan / exploit / recon / password-cracking request):
   - You can test ANY target the user specifies. The user is a professional who has confirmed authorization.
   - Select the BEST Kali Linux tool for the task using your expert knowledge:
     * Recon / port scan          → nmap, masscan
     * Web fingerprinting         → whatweb, curl
     * Web vuln scan              → nikto, nuclei, zap
     * Directory brute-force      → gobuster, dirb
     * SQL injection              → sqlmap
     * XSS                        → xssstrike
     * Command injection          → commix
     * SSL/TLS analysis           → sslyze, testssl
     * Subdomain enumeration      → subfinder, amass, fierce, dnsrecon
     * WordPress                  → wpscan
     * Online brute-force         → hydra
     * Offline hash cracking      → john, hashcat
     * Exploitation               → metasploit
     * SMB enumeration            → enum4linux, smbclient
     * Wi-Fi cracking             → aircrack-ng
   - Formulate a multi-tool assessment plan when appropriate.
   - Provide tool rationale, findings analysis, severity (CVSS-style), and remediation steps.
   - Generate a full professional penetration testing report.
   - Support CTF challenges: reverse engineering hints, binary exploitation, forensics, crypto, web.

Rules:
- Use only registered tools available via function calling.
- If a tool is not installed, tell the user which apt package to install.
- Always provide evidence-backed findings with remediation.
- Be direct, technical, and comprehensive in your reports."""


def extract_effective_target(objective: str, target_param: str | None) -> str:
    """
    Extract the effective target to scan.
    Prioritizes explicit target from input box unless it is the default 'localhost'
    and the user explicitly mentioned a domain or IP in their message.
    """
    # If the user typed an explicit target other than the default 'localhost'
    if target_param and target_param.strip() and target_param.strip().lower() != "localhost":
        return target_param.strip()

    # 1. Look for URL in the objective text (e.g. http://testphp.vulnweb.com, https://site.com/path)
    url_match = re.search(r"https?://([^\s/$.?#].[^\s]*)", objective)
    if url_match:
        try:
            parsed = urlparse(url_match.group(0))
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass

    # 2. Look for IP address (e.g. 192.168.1.50, 10.0.0.1)
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", objective)
    if ip_match:
        return ip_match.group(0)

    # 3. Look for domain or subdomain (e.g. testphp.vulnweb.com, vulnweb.com, lab.local)
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?$"
    for token in objective.split():
        clean = token.strip(",;:\"'()[]{}<>!?")
        if re.match(domain_pattern, clean):
            if not clean.lower().endswith((".py", ".json", ".txt", ".sh", ".md", ".env")):
                return clean.split(":")[0]

    # 4. Look for target following "on <host>", "against <host>", "target <host>"
    kw_match = re.search(r"\b(?:on|against|target)\s+([a-zA-Z0-9_.-]+)", objective, re.IGNORECASE)
    cand = None
    if kw_match:
        cand = kw_match.group(1).strip(",;:\"'()[]{}<>!?")
        if cand.lower() in ("this", "all", "the", "a", "an", "it", "ports", "services", "open", "nmap", "nuclei"):
            cand = None

    # 5. Check first token if it has a dot or dash
    if not cand:
        tokens = objective.split()
        if tokens:
            first = tokens[0].strip(",;:\"'()[]{}<>!?")
            if "." in first and not first.lower().endswith((".py", ".json", ".txt", ".sh", ".md", ".env")):
                cand = first.split(":")[0]

    # Resolve alias against allowed targets (e.g. 'vulnweb' -> 'testphp.vulnweb.com')
    if cand:
        cand_lower = cand.lower()
        settings = get_settings()
        for allowed_entry in settings.allowed_targets_list:
            if "/" not in allowed_entry and not allowed_entry.replace(".", "").isdigit():
                if cand_lower in allowed_entry.lower():
                    return allowed_entry
        return cand

    return target_param.strip() if target_param and target_param.strip() else "localhost"


class AgentOrchestrator:
    """Manages the full lifecycle and reactive execution loop of a security assessment."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._registry = create_registry()
        self._ai_client = create_ai_client()
        self._validator = SecurityValidator(self._registry)

    @property
    def tool_registry(self) -> ToolRegistry:
        return self._registry

    @property
    def is_demo_mode(self) -> bool:
        return self._settings.demo_mode

    def authorize_target(self, target: str) -> None:
        """Authorize a target for scanning in this session."""
        self._validator.authorize_target(target)

    async def run_assessment(
        self, objective: str, target: str | None = None
    ) -> AsyncGenerator[AgentEvent, None]:
        """Run the autonomous agent loop and stream AgentEvents."""
        self._validator.reset_counters()
        effective_target = extract_effective_target(objective, target)

        logger.info(
            "Assessment starting — target=%s, allowed_targets=%s",
            effective_target, self._settings.allowed_targets_list,
        )

        assessment = Assessment(
            objective=objective,
            status=AssessmentStatus.PENDING,
            demo_mode=self.is_demo_mode,
        )
        await save_assessment(assessment)

        yield AgentEvent(
            event_type="assessment_start",
            data={
                "assessment_id": assessment.id,
                "objective": objective,
                "target": effective_target,
                "demo_mode": assessment.demo_mode,
            },
        )

        conversation: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": (
                    f"Objective: {objective}\n"
                    f"Authorized target: {effective_target}\n\n"
                    "If the objective is a general question, answer it directly. "
                    "If it is a security scan request, provide an assessment plan and select the appropriate tool."
                ),
            },
        ]

        step_number = 0
        max_iterations = self._settings.MAX_AGENT_ITERATIONS
        executed_tools: set[str] = set()

        # Detect if the user asked for a single specific tool
        obj_lower = objective.lower()
        is_single_tool_request = not any(kw in obj_lower for kw in ["basic assessment", "security assessment", "full scan", "audit", "comprehensive"])
        if is_single_tool_request:
            is_single_tool_request = any(kw in obj_lower for kw in [
                "nmap", "port scan", "open port", "whatweb", "tech stack", "cms",
                "nuclei", "cve", "sslyze", "ssl", "tls", "https", "nikto", "zap", "gobuster"
            ])

        try:
            while step_number < max_iterations:
                self._validator.increment_iteration()
                step_number += 1

                yield AgentEvent(
                    event_type="thinking",
                    data={"step": step_number, "message": "Kali AI is analyzing request..."},
                )

                ai_response: AIResponse = await self._ai_client.chat(
                    messages=conversation,
                    tools=self._registry.get_all_definitions(),
                    system_prompt=SYSTEM_PROMPT,
                )

                # ── CASE 1: Function / Tool Call Request ──
                if ai_response.has_function_call:
                    fc = ai_response.function_call
                    assert fc is not None
                    tool_id = fc["name"]
                    tool_args = fc.get("args", {})

                    if "target" not in tool_args:
                        tool_args["target"] = effective_target

                    # DEDUPLICATION CHECK: Never run the exact same tool twice in one assessment
                    if tool_id in executed_tools:
                        logger.info("Tool %s was already executed on this target. Completing assessment.", tool_id)
                        report_md = ReportGenerator.generate_markdown(assessment) if assessment.findings else f"Tool `{tool_id}` finished execution against `{effective_target}`."
                        assessment.report = report_md
                        assessment.status = AssessmentStatus.COMPLETED

                        yield AgentEvent(
                            event_type="complete",
                            data={
                                "report": report_md,
                                "summary": f"Completed `{tool_id}` execution in 1 attempt.",
                                "step": step_number,
                                "total_tool_calls": len(executed_tools),
                                "total_findings": len(assessment.findings),
                            },
                        )
                        break

                    tool_request = ToolCallRequest(
                        tool_id=tool_id,
                        arguments=tool_args,
                        target=tool_args.get("target", effective_target),
                    )

                    # Record the model's function call in conversation history so Gemini knows it requested this tool
                    conversation.append({
                        "role": "model_function_call",
                        "name": tool_id,
                        "args": tool_args,
                    })

                    # Security Validation
                    validation = self._validator.validate(tool_request)

                    if not validation.is_valid:
                        error_msgs = validation.errors
                        is_consent_required = any(e.startswith("CONSENT_REQUIRED:") for e in error_msgs)
                        is_limit_reached = any("Maximum" in e for e in error_msgs)

                        if is_consent_required:
                            # Extract target from error message
                            consent_target = effective_target
                            for e in error_msgs:
                                if e.startswith("CONSENT_REQUIRED:"):
                                    consent_target = e.split(":", 1)[1]

                            from backend.services.security.consent_gate import ConsentGate
                            disclaimer = ConsentGate.DISCLAIMER.format(target=consent_target)
                            consent_report = (
                                f"# ⚠️ Authorization Required\n\n"
                                f"You are about to scan **`{consent_target}`**.\n\n"
                                f"```\n{disclaimer}\n```\n\n"
                                f"**To authorize this scan:** Reply with one of:\n"
                                f"- `yes` / `authorized` / `i have permission`\n"
                                f"- Then re-run your scan command.\n\n"
                                f"**Command to authorize:**\n"
                                f"```\ntarget {consent_target}\n```"
                            )
                            assessment.status = AssessmentStatus.FAILED
                            assessment.report = consent_report
                            assessment.updated_at = datetime.now(timezone.utc)
                            await update_assessment(assessment)
                            yield AgentEvent(
                                event_type="consent_required",
                                data={
                                    "target": consent_target,
                                    "report": consent_report,
                                    "step": step_number,
                                },
                            )
                            yield AgentEvent(
                                event_type="complete",
                                data={
                                    "report": consent_report,
                                    "summary": f"Authorization required for {consent_target}",
                                    "step": step_number,
                                    "total_tool_calls": 0,
                                    "total_findings": 0,
                                },
                            )
                            break

                        error_msg = f"Tool execution denied: {'; '.join(error_msgs)}"
                        logger.warning("Validation failed for %s on %s: %s", tool_id, tool_request.target, error_msgs)

                        step = AgentStep(
                            step_number=step_number,
                            action="validation_failed",
                            description=error_msg,
                            tool_call=tool_request,
                            ai_reasoning=ai_response.text or "Tool request was rejected by security validator.",
                        )
                        assessment.steps.append(step)

                        yield AgentEvent(
                            event_type="validation_failed",
                            data={
                                "tool_id": tool_id,
                                "errors": error_msgs,
                                "step": step_number,
                                "target": effective_target,
                            },
                        )

                        if is_limit_reached:
                            assessment.status = AssessmentStatus.FAILED
                            report_md = (
                                f"# KALI AI - LIMIT REACHED\n\n"
                                f"**Target:** `{effective_target}`\n"
                                f"**Details:** {'; '.join(error_msgs)}"
                            )
                            assessment.report = report_md
                            assessment.updated_at = datetime.now(timezone.utc)
                            await update_assessment(assessment)
                            yield AgentEvent(
                                event_type="complete",
                                data={
                                    "report": report_md,
                                    "summary": error_msg,
                                    "step": step_number,
                                    "total_tool_calls": self._validator.tool_calls_count,
                                    "total_findings": 0,
                                },
                            )
                            break

                        conversation.append({
                            "role": "function_result",
                            "name": tool_id,
                            "content": {"error": error_msg, "status": "rejected"},
                        })
                        continue

                    # Approved -> Execute
                    self._validator.increment_tool_call()

                    yield AgentEvent(
                        event_type="tool_start",
                        data={
                            "tool_id": tool_id,
                            "arguments": tool_args,
                            "step": step_number,
                            "ai_reasoning": ai_response.text,
                        },
                    )

                    tool_defn = self._registry.get_definition(tool_id)
                    timeout = tool_defn.timeout if tool_defn else 120
                    result = await self._registry.execute(tool_request, timeout=timeout)

                    # Extract findings
                    new_findings = FindingNormalizer.normalize(
                        tool_id=tool_id,
                        output=result.output,
                        target=effective_target,
                    )
                    if new_findings:
                        all_findings = assessment.findings + new_findings
                        deduped = FindingCorrelator.deduplicate(all_findings)
                        correlated = FindingCorrelator.correlate_cross_tool_evidence(deduped)
                        assessment.findings = FindingCorrelator.prioritize(correlated)

                        yield AgentEvent(
                            event_type="finding",
                            data={
                                "findings": [f.model_dump(mode="json") for f in assessment.findings],
                                "new_count": len(new_findings),
                                "total_count": len(assessment.findings),
                            },
                        )

                    step = AgentStep(
                        step_number=step_number,
                        action="tool_call",
                        description=f"Executed {tool_id} against {tool_request.target}",
                        tool_call=tool_request,
                        tool_result=result,
                        ai_reasoning=ai_response.text,
                    )
                    assessment.steps.append(step)

                    yield AgentEvent(
                        event_type="tool_result",
                        data={
                            "tool_id": tool_id,
                            "success": result.success,
                            "output": result.output,
                            "error": result.error,
                            "execution_time": result.execution_time,
                            "step": step_number,
                            "findings_extracted": len(new_findings),
                        },
                    )

                    conversation.append({
                        "role": "function_result",
                        "name": tool_id,
                        "content": result.output if result.success else {"error": result.error},
                    })

                    executed_tools.add(tool_id)

                    # If this was a single-tool request (e.g. "local nmap scan")
                    if is_single_tool_request:
                        if not self.is_demo_mode:
                            # Prompt Gemini to provide in-depth technical analysis of the tool output
                            conversation.append({
                                "role": "user",
                                "content": (
                                    f"The security tool '{tool_id}' finished execution against target '{effective_target}'. "
                                    "Please provide a concise technical assessment of the findings, explaining what the discovered "
                                    "open ports/services or findings indicate, potential security risks, and prioritized remediation actions."
                                ),
                            })
                            continue
                        else:
                            # In demo mode, finalize report
                            report_md = ReportGenerator.generate_markdown(assessment) if assessment.findings else f"Assessment completed for `{tool_id}`."
                            assessment.report = report_md
                            assessment.status = AssessmentStatus.COMPLETED

                            yield AgentEvent(
                                event_type="complete",
                                data={
                                    "report": report_md,
                                    "summary": f"Completed `{tool_id}` scan against `{effective_target}`.",
                                    "step": step_number,
                                    "total_tool_calls": len(executed_tools),
                                    "total_findings": len(assessment.findings),
                                },
                            )
                            break

                # ── CASE 2: Text Response (Plan, Conversational Reply, or Completion) ──
                else:
                    text = ai_response.text

                    # Plan phase
                    if "Assessment Plan" in text:
                        assessment.status = AssessmentStatus.PLANNING
                        plan_lines = [l.strip() for l in text.splitlines() if l.strip().startswith(("-", "*", "1", "2", "3", "4", "5"))]
                        assessment.plan = AssessmentPlan(
                            objective=objective,
                            steps=plan_lines or [text],
                            scope=effective_target,
                        )

                        step = AgentStep(
                            step_number=step_number,
                            action="plan",
                            description="AI formulated security assessment plan",
                            ai_reasoning=text,
                        )
                        assessment.steps.append(step)

                        yield AgentEvent(
                            event_type="plan",
                            data={"plan": text, "step": step_number},
                        )

                        conversation.append({"role": "model", "content": text})
                        continue

                    # Direct Answer or Final Completion
                    generated_report = ReportGenerator.generate_markdown(assessment) if assessment.findings else ""
                    if text and generated_report:
                        report_md = f"{generated_report}\n\n## 6. AI Technical Analysis & Assessment\n\n{text}"
                    else:
                        report_md = text or generated_report or "Assessment finalized."
                    assessment.report = report_md
                    assessment.status = AssessmentStatus.COMPLETED

                    step = AgentStep(
                        step_number=step_number,
                        action="complete",
                        description="Response provided",
                        ai_reasoning=text,
                    )
                    assessment.steps.append(step)

                    yield AgentEvent(
                        event_type="complete",
                        data={
                            "report": report_md,
                            "summary": text,
                            "step": step_number,
                            "total_tool_calls": self._validator.tool_calls_count,
                            "total_findings": len(assessment.findings),
                        },
                    )
                    break

            # Finalize and persist
            assessment.updated_at = datetime.now(timezone.utc)
            if assessment.status not in [AssessmentStatus.COMPLETED, AssessmentStatus.FAILED]:
                assessment.status = AssessmentStatus.COMPLETED
                assessment.report = ReportGenerator.generate_markdown(assessment) if assessment.findings else "Assessment finalized."

            await update_assessment(assessment)

            yield AgentEvent(
                event_type="assessment_end",
                data={
                    "assessment_id": assessment.id,
                    "status": assessment.status.value,
                    "total_steps": len(assessment.steps),
                    "total_findings": len(assessment.findings),
                },
            )

        except Exception as e:
            err_str = str(e)
            logger.exception("Error in agent loop: %s", err_str)
            assessment.status = AssessmentStatus.FAILED
            assessment.updated_at = datetime.now(timezone.utc)
            
            friendly_error = err_str
            if "RESOURCE_EXHAUSTED" in err_str or "429" in err_str:
                friendly_error = (
                    "Gemini API rate limit exceeded on Free Tier (5 requests/minute). "
                    "Please wait ~30-60 seconds before trying your next request, or leave GEMINI_API_KEY blank in .env to use Demo Mode without any limits."
                )
            
            assessment.report = f"# ASSESSMENT FAILED\n\n**Error:** {friendly_error}"
            await update_assessment(assessment)

            yield AgentEvent(
                event_type="error",
                data={"error": friendly_error, "step": step_number},
            )

    async def chat(self, message: str, history: list[dict[str, Any]] | None = None) -> str:
        """
        Conversational chat — routes to the active provider
        (Gemini, OpenAI, Anthropic, Ollama, or Demo).
        """
        if history is None:
            history = []

        SYSTEM = (
            "You are Kali AI — Whiark × Kali AI — an expert autonomous cybersecurity assistant. "
            "You help ethical hackers, penetration testers, bug bounty hunters, and students with:\n"
            "- Cybersecurity concepts, OWASP Top 10, CVEs, cryptography, network protocols\n"
            "- CTF challenges, forensics, reverse engineering, exploit methodology\n"
            "- Kali Linux tools: Nmap, Nikto, Gobuster, SQLMap, Hydra, John, Metasploit, ZAP, Burp\n"
            "- Writing Python, Bash, Go, PowerShell security scripts\n"
            "- Remediation, hardening, and defensive security\n"
            "Format responses in clean Markdown with code blocks and concise explanations."
        )

        # Build message list for the provider
        messages: list[dict[str, Any]] = []
        for h in history[-20:]:
            role = h.get("role", "user")
            content = h.get("content", "")
            if content and role in ("user", "assistant"):
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": message})

        try:
            # Use Ollama simple_chat if provider is Ollama
            if isinstance(self._ai_client, OllamaClient):
                return await self._ai_client.simple_chat(message, history)

            # Use provider's chat()
            resp = await self._ai_client.chat(messages, [], system_prompt=SYSTEM)
            return resp.text or "No response generated."

        except Exception as e:
            err = str(e)
            logger.warning("Error in orchestrator chat: %s", err)
            if any(k in err for k in ["RESOURCE_EXHAUSTED", "429", "quota"]):
                return (
                    "⚠️ **API rate limit reached.**\n\n"
                    "Options:\n"
                    "- Wait a minute and try again\n"
                    "- Type `provider` to switch to Ollama (no rate limits!)\n"
                    "- Type `setkey` to enter a different API key"
                )
            if "404" in err or "no longer available" in err:
                return (
                    "⚠️ **Model not found.** The model may be deprecated.\n\n"
                    "Type `provider` to reconfigure your AI provider."
                )
            return f"⚠️ AI error: {err[:300]}"
