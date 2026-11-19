"""
Unit tests for Pydantic models and schemas.
"""

from datetime import datetime, timezone
from backend.models.schemas import (
    Severity, Confidence, ToolCategory, RiskLevel,
    AssessmentStatus, ToolStatus, ToolDefinition, ToolCallRequest,
    ToolCallResult, Finding, AgentStep, AssessmentPlan, Assessment,
)


def test_finding_creation_and_defaults():
    f = Finding(
        title="Open SSH Port",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.CONFIRMED,
        category="Network",
        affected_asset="127.0.0.1:22",
        description="SSH service is listening on port 22.",
        evidence=["Port 22 open"],
        remediation="Use public key authentication only.",
        source_tool="nmap_scan",
    )
    assert f.id is not None
    assert f.severity == Severity.INFORMATIONAL
    assert f.confidence == Confidence.CONFIRMED
    assert f.verification_status == "unverified"
    assert isinstance(f.timestamp, datetime)

    dumped = f.model_dump(mode="json")
    assert dumped["severity"] == "informational"
    assert dumped["title"] == "Open SSH Port"


def test_tool_definition_schema():
    tool = ToolDefinition(
        id="test_tool",
        name="Test Scanner",
        description="Scans a target for testing",
        category=ToolCategory.RECONNAISSANCE,
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        status=ToolStatus.MOCK,
        risk_level=RiskLevel.LOW,
        timeout=30,
    )
    assert tool.id == "test_tool"
    assert tool.status == ToolStatus.MOCK


def test_assessment_serialization_and_roundtrip():
    assessment = Assessment(
        objective="Scan localhost",
        status=AssessmentStatus.RUNNING,
        plan=AssessmentPlan(
            objective="Scan localhost",
            steps=["Step 1", "Step 2"],
            scope="127.0.0.1",
        ),
        steps=[
            AgentStep(
                step_number=1,
                action="tool_call",
                description="Ran whatweb",
                tool_call=ToolCallRequest(tool_id="whatweb_scan", target="localhost"),
                tool_result=ToolCallResult(tool_id="whatweb_scan", success=True, output={"mock": True}),
            )
        ],
        findings=[
            Finding(
                title="Test Finding",
                severity=Severity.LOW,
                confidence=Confidence.POTENTIAL,
                category="Web",
                affected_asset="localhost",
                description="Test description",
            )
        ],
        demo_mode=True,
    )

    json_str = assessment.model_dump_json()
    reloaded = Assessment.model_validate_json(json_str)

    assert reloaded.id == assessment.id
    assert reloaded.objective == "Scan localhost"
    assert len(reloaded.steps) == 1
    assert len(reloaded.findings) == 1
    assert reloaded.demo_mode is True
