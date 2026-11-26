"""
Kali AI - Data Models (Pydantic Schemas)
All shared data structures for the agent system.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    HYPOTHESIS = "hypothesis"


class ToolCategory(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    WEB_ANALYSIS = "web_analysis"
    SSL_TLS = "ssl_tls"
    DISCOVERY = "discovery"
    EXPLOITATION = "exploitation"
    UTILITY = "utility"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    PLANNING = "planning"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    MOCK = "mock"


# ──────────────────────────────────────────────
# Tool Models
# ──────────────────────────────────────────────

class ToolDefinition(BaseModel):
    """Describes a registered security tool."""
    id: str
    name: str
    description: str
    category: ToolCategory
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    status: ToolStatus = ToolStatus.MOCK
    risk_level: RiskLevel = RiskLevel.LOW
    timeout: int = 120
    permission_requirements: list[str] = Field(default_factory=list)


class ToolCallRequest(BaseModel):
    """A request from the AI to call a specific tool."""
    tool_id: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    target: str = ""


class ToolCallResult(BaseModel):
    """The result of executing a tool."""
    tool_id: str
    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    execution_time: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ──────────────────────────────────────────────
# Finding Model
# ──────────────────────────────────────────────

class Finding(BaseModel):
    """A normalized security finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    affected_asset: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    source_tool: str = ""
    verification_status: str = "unverified"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ──────────────────────────────────────────────
# Agent Step & Assessment
# ──────────────────────────────────────────────

class AgentStep(BaseModel):
    """One step in the agent's decision loop."""
    step_number: int
    action: str  # e.g. "plan", "tool_call", "analyze", "complete"
    description: str
    tool_call: ToolCallRequest | None = None
    tool_result: ToolCallResult | None = None
    ai_reasoning: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssessmentPlan(BaseModel):
    """The AI-generated assessment plan."""
    objective: str
    steps: list[str] = Field(default_factory=list)
    estimated_tools: list[str] = Field(default_factory=list)
    scope: str = ""


class Assessment(BaseModel):
    """A full security assessment — the top-level entity."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    objective: str
    status: AssessmentStatus = AssessmentStatus.PENDING
    plan: AssessmentPlan | None = None
    steps: list[AgentStep] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    report: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    demo_mode: bool = False


# ──────────────────────────────────────────────
# API Request / Response
# ──────────────────────────────────────────────

class ChatRequest(BaseModel):
    """Incoming chat message from the user."""
    message: str
    target: str | None = None


class ChatResponse(BaseModel):
    """Response sent back to the frontend."""
    assessment_id: str
    message: str
    demo_mode: bool = False


class AgentEvent(BaseModel):
    """
    Server-Sent Event pushed to the frontend during the agent loop.
    event_type: plan | step | finding | tool_start | tool_result | thinking | complete | error
    """
    event_type: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
