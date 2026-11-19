"""
Kali AI - API Routes
REST and SSE endpoints for the Kali AI application.
"""

from __future__ import annotations

import json
import logging
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse, PlainTextResponse

from backend.core.config import get_settings
from backend.models.schemas import ChatRequest, AgentEvent
from backend.services.agent.orchestrator import AgentOrchestrator
from backend.services.tool_registry.registry import create_default_registry
from backend.database.db import get_assessment, list_assessments

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["api"])

_orchestrator: AgentOrchestrator | None = None


def _get_orchestrator() -> AgentOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator()
    return _orchestrator


@router.get("/health")
async def health():
    """Service health and current runtime mode check."""
    settings = get_settings()
    return {
        "status": "healthy",
        "demo_mode": settings.demo_mode,
        "model": settings.GEMINI_MODEL,
        "allowed_targets": settings.allowed_targets_list,
        "max_iterations": settings.MAX_AGENT_ITERATIONS,
    }


@router.post("/chat")
async def chat(request: ChatRequest):
    """
    Execute an assessment loop and stream progress in real time via Server-Sent Events (SSE).
    """
    orchestrator = _get_orchestrator()

    async def event_stream():
        try:
            async for event in orchestrator.run_assessment(
                objective=request.message,
                target=request.target,
            ):
                payload = event.model_dump(mode="json")
                yield f"data: {json.dumps(payload)}\n\n"
        except Exception as e:
            logger.exception("Error in SSE event stream: %s", e)
            err_evt = AgentEvent(event_type="error", data={"error": str(e)})
            yield f"data: {json.dumps(err_evt.model_dump(mode='json'))}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/tools")
async def get_tools():
    """List all registered security tools and their schemas."""
    registry = create_default_registry()
    definitions = registry.get_all_definitions()
    return {
        "tools": [d.model_dump() for d in definitions],
        "total": len(definitions),
    }


@router.get("/assessments")
async def get_assessments(limit: int = Query(default=50, ge=1, le=200)):
    """List historical security assessments."""
    assessments = await list_assessments(limit=limit)
    return {
        "assessments": [a.model_dump(mode="json") for a in assessments],
        "total": len(assessments),
    }


@router.get("/assessments/{assessment_id}")
async def get_assessment_detail(assessment_id: str):
    """Retrieve full details of a specific assessment."""
    assessment = await get_assessment(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found")
    return assessment.model_dump(mode="json")


@router.get("/assessments/{assessment_id}/report", response_class=PlainTextResponse)
async def get_assessment_report(assessment_id: str):
    """Retrieve the generated markdown security report for an assessment."""
    assessment = await get_assessment(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found")
    if not assessment.report:
        raise HTTPException(status_code=404, detail="Report has not been generated for this assessment")
    return assessment.report


@router.get("/config")
async def get_config():
    """Safe configuration info for the UI."""
    settings = get_settings()
    return {
        "demo_mode": settings.demo_mode,
        "model": settings.GEMINI_MODEL,
        "max_iterations": settings.MAX_AGENT_ITERATIONS,
        "max_tool_calls": settings.MAX_TOOL_CALLS,
        "tool_timeout": settings.TOOL_EXECUTION_TIMEOUT,
        "allowed_targets": settings.allowed_targets_list,
    }
