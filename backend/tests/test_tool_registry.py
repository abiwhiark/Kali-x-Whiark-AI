"""
Unit tests for the Tool Registry and mock tool implementations.
"""

import pytest
import asyncio
from backend.models.schemas import ToolCallRequest
from backend.services.tool_registry.registry import ToolRegistry, create_default_registry


@pytest.fixture
def registry():
    return create_default_registry()


def test_registry_contains_all_seven_tools(registry):
    expected_tools = [
        "nmap_scan",
        "whatweb_scan",
        "nuclei_scan",
        "nikto_scan",
        "sslyze_scan",
        "zap_scan",
        "gobuster_scan",
    ]
    for tid in expected_tools:
        assert registry.tool_exists(tid), f"Expected tool {tid} missing in registry"
        defn = registry.get_definition(tid)
        assert defn is not None
        assert defn.name
        assert "target" in defn.input_schema.get("properties", {})


@pytest.mark.asyncio
async def test_tool_execution_nmap(registry):
    req = ToolCallRequest(tool_id="nmap_scan", arguments={"target": "127.0.0.1", "profile": "quick"}, target="127.0.0.1")
    result = await registry.execute(req)
    assert result.success is True
    assert result.output.get("mock") is True
    assert "ports" in result.output
    assert result.execution_time >= 0.0


@pytest.mark.asyncio
async def test_tool_execution_whatweb(registry):
    req = ToolCallRequest(tool_id="whatweb_scan", arguments={"target": "localhost"}, target="localhost")
    result = await registry.execute(req)
    assert result.success is True
    assert "technologies" in result.output


@pytest.mark.asyncio
async def test_tool_execution_nonexistent(registry):
    req = ToolCallRequest(tool_id="nonexistent_tool_xyz", arguments={"target": "localhost"}, target="localhost")
    result = await registry.execute(req)
    assert result.success is False
    assert "not found" in result.error


@pytest.mark.asyncio
async def test_tool_timeout_handling():
    reg = ToolRegistry()
    from backend.models.schemas import ToolDefinition, ToolCategory, ToolStatus

    async def slow_executor(args):
        await asyncio.sleep(5)
        return {"done": True}

    defn = ToolDefinition(
        id="slow_tool",
        name="Slow Tool",
        description="A tool that takes too long",
        category=ToolCategory.RECONNAISSANCE,
        status=ToolStatus.MOCK,
    )
    reg.register(defn, slow_executor)

    req = ToolCallRequest(tool_id="slow_tool", arguments={}, target="localhost")
    result = await reg.execute(req, timeout=1)

    assert result.success is False
    assert "timed out" in result.error.lower()
