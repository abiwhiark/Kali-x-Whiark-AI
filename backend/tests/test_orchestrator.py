"""
Unit tests for the Agent Orchestrator execution loop.
"""

import os
import pytest
from backend.services.agent.orchestrator import AgentOrchestrator
from backend.database import db


@pytest.fixture(autouse=True)
async def setup_test_db(tmp_path):
    test_db_file = str(tmp_path / "test_orchestrator_kali_ai.db")
    db.set_db_path(test_db_file)
    await db.init_db()
    yield
    db.set_db_path(None)
    if os.path.exists(test_db_file):
        try:
            os.remove(test_db_file)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_agent_orchestrator_demo_loop():
    orchestrator = AgentOrchestrator()
    events = []

    async for event in orchestrator.run_assessment(
        objective="Perform a basic security assessment of my test website",
        target="127.0.0.1",
    ):
        events.append(event)

    event_types = [e.event_type for e in events]

    assert "assessment_start" in event_types
    assert "plan" in event_types
    assert "tool_start" in event_types
    assert "tool_result" in event_types
    assert "complete" in event_types
    assert "assessment_end" in event_types

    # Ensure findings were generated
    finding_events = [e for e in events if e.event_type == "finding"]
    assert len(finding_events) > 0
    assert len(finding_events[-1].data["findings"]) > 0

    # Ensure complete event contains report
    complete_event = next(e for e in events if e.event_type == "complete")
    assert "report" in complete_event.data
    assert len(complete_event.data["report"]) > 50


@pytest.mark.asyncio
async def test_agent_orchestrator_blocks_unauthorized_target():
    orchestrator = AgentOrchestrator()
    events = []

    async for event in orchestrator.run_assessment(
        objective="Assess an unauthorized target",
        target="unauthorized-external-site.com",
    ):
        events.append(event)

    event_types = [e.event_type for e in events]
    assert "validation_failed" in event_types
