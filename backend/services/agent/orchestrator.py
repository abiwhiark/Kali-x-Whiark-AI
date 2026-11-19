"""
Kali AI - Agent Orchestrator
The core autonomous decision loop that:
  1. Sends user objective + tool definitions to Gemini.
  2. Receives either a plan, tool selection, or final analysis.
  3. Validates the function call (target, allowed profiles, limits).
  4. Executes the approved tool.
  5. Normalizes and correlates findings in real time.
  6. Returns structured results to Gemini.
  7. Loops until Gemini concludes or execution limits are reached.
  8. Generates a formal executive and technical report.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

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
- Formulate a clear, structured assessment plan.
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
        effective_target = target.strip() if target and target.strip() else "localhost"

        # Initialize assessment entity
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
                    "Please create an assessment plan and begin by selecting the first approved tool."
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
                    data={"step": step_number, "message": "Kali AI is reasoning..."},
                )

                # Send context to AI
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

                    # Security Validation
                    validation = self._validator.validate(tool_request)

                    if not validation.is_valid:
                        error_msg = f"Tool execution denied: {'; '.join(validation.errors)}"
                        logger.warning("Validation failed for %s: %s", tool_id, validation.errors)

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
                            },
                        )

                        conversation.append({
                            "role": "function_result",
                            "name": tool_id,
                            "content": {"error": error_msg, "status": "rejected"},
                        })

                        if any("Maximum" in e for e in validation.errors):
                            break
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

                    # Normalize findings from raw output
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

                    # Return result to AI
                    conversation.append({
                        "role": "function_result",
                        "name": tool_id,
                        "content": result.output if result.success else {"error": result.error},
                    })

                # ── CASE 2: Text Response (Plan, Observation, or Completion) ──
                else:
                    text = ai_response.text

                    # Plan phase
                    if "Assessment Plan" in text or step_number == 1:
                        assessment.status = AssessmentStatus.PLANNING
                        plan_lines = [l.strip() for l in text.splitlines() if l.strip().startswith(("-", "*", "1", "2", "3", "4"))]
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

                    # Final completion
                    report_md = ReportGenerator.generate_markdown(assessment)
                    assessment.report = report_md
                    assessment.status = AssessmentStatus.COMPLETED

                    step = AgentStep(
                        step_number=step_number,
                        action="complete",
                        description="Assessment completed and report generated",
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
            if assessment.status != AssessmentStatus.COMPLETED:
                assessment.status = AssessmentStatus.COMPLETED
                assessment.report = ReportGenerator.generate_markdown(assessment)

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
            logger.exception("Error in agent loop: %s", e)
            assessment.status = AssessmentStatus.FAILED
            assessment.updated_at = datetime.now(timezone.utc)
            await update_assessment(assessment)

            yield AgentEvent(
                event_type="error",
                data={"error": str(e), "step": step_number},
            )
