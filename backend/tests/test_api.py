"""
Integration tests for FastAPI endpoints.
"""

import os
import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.database import db


@pytest.fixture(autouse=True)
async def setup_test_db(tmp_path):
    test_db_file = str(tmp_path / "test_api_kali_ai.db")
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
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "demo_mode" in data
        assert "allowed_targets" in data


@pytest.mark.asyncio
async def test_get_tools_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/tools")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 7
        assert len(data["tools"]) == 7
        tool_ids = [t["id"] for t in data["tools"]]
        assert "nmap_scan" in tool_ids
        assert "whatweb_scan" in tool_ids
        assert "nuclei_scan" in tool_ids


@pytest.mark.asyncio
async def test_get_config_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/config")
        assert response.status_code == 200
        data = response.json()
        assert "demo_mode" in data
        assert "model" in data
        assert "max_iterations" in data


@pytest.mark.asyncio
async def test_chat_sse_stream():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/chat",
            json={"message": "Perform quick scan", "target": "127.0.0.1"},
        )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        body = response.text
        assert "assessment_start" in body
        assert "data: " in body
