"""
Kali AI - Database Layer
SQLite storage for assessments, using aiosqlite for async access.
"""

from __future__ import annotations

import json
import aiosqlite
from backend.core.config import get_settings
from backend.models.schemas import Assessment


_DB_PATH: str | None = None


def set_db_path(path: str | None) -> None:
    """Override database file path (e.g. for testing)."""
    global _DB_PATH
    _DB_PATH = path


def _get_db_path() -> str:
    global _DB_PATH
    if _DB_PATH is None:
        _DB_PATH = get_settings().DATABASE_PATH
    return _DB_PATH


async def init_db() -> None:
    """Create the assessments table if it does not exist."""
    path = _get_db_path()
    async with aiosqlite.connect(path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                objective TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                plan_json TEXT,
                steps_json TEXT DEFAULT '[]',
                findings_json TEXT DEFAULT '[]',
                report TEXT,
                demo_mode INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        await db.commit()


async def save_assessment(assessment: Assessment) -> None:
    """Insert a new assessment, ensuring tables exist."""
    await init_db()
    async with aiosqlite.connect(_get_db_path()) as db:
        await db.execute(
            """INSERT INTO assessments
               (id, objective, status, plan_json, steps_json, findings_json, report, demo_mode, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                assessment.id,
                assessment.objective,
                assessment.status.value,
                assessment.plan.model_dump_json() if assessment.plan else None,
                json.dumps([s.model_dump(mode="json") for s in assessment.steps]),
                json.dumps([f.model_dump(mode="json") for f in assessment.findings]),
                assessment.report,
                1 if assessment.demo_mode else 0,
                assessment.created_at.isoformat(),
                assessment.updated_at.isoformat(),
            ),
        )
        await db.commit()


async def update_assessment(assessment: Assessment) -> None:
    """Update an existing assessment."""
    async with aiosqlite.connect(_get_db_path()) as db:
        await db.execute(
            """UPDATE assessments
               SET objective=?, status=?, plan_json=?, steps_json=?, findings_json=?,
                   report=?, demo_mode=?, updated_at=?
               WHERE id=?""",
            (
                assessment.objective,
                assessment.status.value,
                assessment.plan.model_dump_json() if assessment.plan else None,
                json.dumps([s.model_dump(mode="json") for s in assessment.steps]),
                json.dumps([f.model_dump(mode="json") for f in assessment.findings]),
                assessment.report,
                1 if assessment.demo_mode else 0,
                assessment.updated_at.isoformat(),
                assessment.id,
            ),
        )
        await db.commit()


def _row_to_assessment(row: dict) -> Assessment:
    """Convert a sqlite row dict to an Assessment model."""
    from backend.models.schemas import AssessmentPlan, AgentStep, Finding, AssessmentStatus

    plan = None
    if row["plan_json"]:
        plan = AssessmentPlan.model_validate_json(row["plan_json"])

    steps_raw = json.loads(row["steps_json"]) if row["steps_json"] else []
    steps = [AgentStep.model_validate(s) for s in steps_raw]

    findings_raw = json.loads(row["findings_json"]) if row["findings_json"] else []
    findings = [Finding.model_validate(f) for f in findings_raw]

    return Assessment(
        id=row["id"],
        objective=row["objective"],
        status=AssessmentStatus(row["status"]),
        plan=plan,
        steps=steps,
        findings=findings,
        report=row["report"],
        demo_mode=bool(row["demo_mode"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def get_assessment(assessment_id: str) -> Assessment | None:
    """Retrieve a single assessment by ID."""
    await init_db()
    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return _row_to_assessment(dict(row))


async def list_assessments(limit: int = 50) -> list[Assessment]:
    """List recent assessments, newest first."""
    await init_db()
    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM assessments ORDER BY created_at DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_assessment(dict(r)) for r in rows]
