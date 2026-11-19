"""
Unit tests for the SQLite asynchronous database layer.
"""

import os
import pytest
from backend.models.schemas import Assessment, AssessmentStatus, AssessmentPlan
from backend.database import db


@pytest.fixture(autouse=True)
async def setup_test_db(tmp_path):
    test_db_file = str(tmp_path / "test_kali_ai.db")
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
async def test_save_and_get_assessment():
    assessment = Assessment(
        objective="Analyze test environment",
        status=AssessmentStatus.PLANNING,
        plan=AssessmentPlan(
            objective="Analyze test environment",
            steps=["Step 1", "Step 2"],
            scope="localhost",
        ),
        demo_mode=True,
    )

    await db.save_assessment(assessment)
    fetched = await db.get_assessment(assessment.id)

    assert fetched is not None
    assert fetched.id == assessment.id
    assert fetched.objective == "Analyze test environment"
    assert fetched.status == AssessmentStatus.PLANNING
    assert fetched.plan is not None
    assert fetched.plan.scope == "localhost"
    assert fetched.demo_mode is True


@pytest.mark.asyncio
async def test_update_assessment():
    assessment = Assessment(objective="Initial objective")
    await db.save_assessment(assessment)

    assessment.status = AssessmentStatus.COMPLETED
    assessment.report = "## Full Test Report"
    await db.update_assessment(assessment)

    fetched = await db.get_assessment(assessment.id)
    assert fetched is not None
    assert fetched.status == AssessmentStatus.COMPLETED
    assert fetched.report == "## Full Test Report"


@pytest.mark.asyncio
async def test_list_assessments():
    a1 = Assessment(objective="Task 1")
    a2 = Assessment(objective="Task 2")
    await db.save_assessment(a1)
    await db.save_assessment(a2)

    all_items = await db.list_assessments(limit=10)
    assert len(all_items) >= 2
    ids = [a.id for a in all_items]
    assert a1.id in ids
    assert a2.id in ids


@pytest.mark.asyncio
async def test_get_nonexistent_assessment():
    res = await db.get_assessment("nonexistent-uuid")
    assert res is None
