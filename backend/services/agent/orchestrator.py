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
from backend.services.gemini.client import create_ai_client, AIResponse
from backend.services.tool_registry.registry import ToolRegistry, create_default_registry
from backend.services.security.validator import SecurityValidator
from backend.services.analysis.normalizer import FindingNormalizer
from backend.services.analysis.correlator import FindingCorrelator
from backend.services.reporting.generator import ReportGenerator
from backend.database.db import save_assessment, update_assessment

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Kali AI, an autonomous cybersecurity assessment assistant.

Your role:
- Understand security assessment objectives from the user.
- If the user asks a conversational or informational question (e.g. what are your capabilities, list tools), reply directly with clear text. Do not request tools unless a security scan or assessment is specifically requested.
- For assessment requests, formulate a clear, structured assessment plan.
- Select the appropriate security tool for each step via function calling.
- Provide a brief 1-sentence rationale explaining why you selected the tool.
- Analyze tool results and adapt your next action based on actual evidence.
- When sufficient data is collected, complete the assessment with an executive summary.

Rules and Constraints:
- You may ONLY request registered tools available via function calling.
- Never attempt to run arbitrary shell commands.
- Only test targets explicitly authorized in the prompt.
- Do not make assumptions: only report vulnerabilities supported by tool evidence.
- Adapt your plan dynamically if previous tools reveal relevant services or technologies."""


def extract_effective_target(objective: str, target_param: str | None) -> str:
    """
    Extract the effective target to scan.
    Prioritizes explicit target from input box unless it is the default 'localhost'
    and the user explicitly mentioned a domain or IP in their message.
    """
    # If the user typed an explicit target other than the default 'localhost'
    if target_param and target_param.strip() and target_param.strip().lower() != "localhost":
        return target_param.strip()

    # Look for URL in the objective text (e.g. http://mytest.lab, https://annacaterers.in)
    url_match = re.search(r"https?://([^\s/$.?#].[^\s]*)", objective)
    if url_match:
        try:
            parsed = urlparse(url_match.group(0))
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass

    # Look for IP address (e.g. 192.168.1.50, 10.0.0.1)
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", objective)
    if ip_match:
        return ip_match.group(0)

    # Look for domain name in objective (e.g. annacaterers.in, testlab.local)
    for token in objective.split():
        clean = token.strip(",;:\"'()[]{}<>!?")
        if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?::\d+)?$", clean):
            if not clean.lower().endswith((".py", ".json", ".txt", ".sh", ".md", ".env")):
                return clean

    return target_param.strip() if target_param and target_param.strip() else "localhost"


class AgentOrchestrator:
    """Manages the full lifecycle and reactive execution loop of a security assessment."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._registry = create_default_registry()
        self._ai_client = create_ai_client()
        self._validator = SecurityValidator(self._registry)

    @property
    def tool_registry(self) -> ToolRegistry:
        return self._registry

    @property
    def is_demo_mode(self) -> bool:
        return self._settings.demo_mode

    async def run_assessment(
        self, objective: str, target: str | None = None
    ) -> AsyncGenerator[AgentEvent, None]:
        """Run the autonomous agent loop and stream AgentEvents."""
        self._validator.reset_counters()
        effective_target = extract_effective_target(objective, target)

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
                        error_msg = f"Tool execution denied: {'; '.join(validation.errors)}"
                        logger.warning("Validation failed for %s on %s: %s", tool_id, tool_request.target, validation.errors)

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
                                "errors": validation.errors,
                                "step": step_number,
                                "target": effective_target,
                            },
                        )

                        # If target is unauthorized or limits reached, stop assessment immediately
                        is_unauthorized_target = any("not in the allowed targets list" in e for e in validation.errors)
                        is_limit_reached = any("Maximum" in e for e in validation.errors)

                        if is_unauthorized_target or is_limit_reached:
                            assessment.status = AssessmentStatus.FAILED
                            report_md = (
                                f"# KALI AI - SECURITY POLICY BLOCK\n\n"
                                f"**Target:** `{effective_target}`  \n"
                                f"**Status:** Blocked by Security Validator  \n\n"
                                f"**Details:**\n"
                                f"- {'; '.join(validation.errors)}\n\n"
                                f"### How to Authorize This Target:\n"
                                f"Kali AI strictly enforces scope boundaries to prevent unauthorized scanning. "
                                f"If you own or have written authorization to test `{effective_target}`:\n"
                                f"1. Open your `.env` file in the project root.\n"
                                f"2. Add `{effective_target}` to the `ALLOWED_TARGETS` list:\n"
                                f"   ```ini\n"
                                f"   ALLOWED_TARGETS={self._settings.ALLOWED_TARGETS},{effective_target}\n"
                                f"   ```\n"
                                f"3. Re-run your assessment."
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
                    report_md = ReportGenerator.generate_markdown(assessment) if assessment.findings else text
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
