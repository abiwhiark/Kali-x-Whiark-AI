"""
Unit tests for GeminiClient REST fallback when google-genai SDK is unavailable,
plus launcher executor safety.
"""

import builtins
import types as pytypes
import pytest

from backend.models.schemas import ToolDefinition, ToolCategory, ToolStatus
from backend.services.gemini.client import GeminiClient


@pytest.mark.asyncio
async def test_gemini_client_survives_google_genai_importerror(monkeypatch):
    """Simulates `ImportError: cannot import name 'genai' from 'google' (unknown location)`."""
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "google" and fromlist and "genai" in fromlist:
            raise ImportError("cannot import name 'genai' from 'google' (unknown location)")
        if name.startswith("google.genai"):
            raise ImportError("No module named 'google.genai'")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    client = GeminiClient(api_key="AIzaDummyKey", model="gemini-2.5-flash")
    assert client._client is None

    # Mock HTTP transport so no real external request is made
    captured = {}

    def fake_rest(model_name, payload):
        captured["model"] = model_name
        captured["payload"] = payload
        return {
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": {
                            "name": "nmap_scan",
                            "args": {"target": "localhost", "profile": "quick"},
                        }
                    }]
                }
            }]
        }

    monkeypatch.setattr(client, "_generate_via_rest", fake_rest)

    tool = ToolDefinition(
        id="nmap_scan",
        name="Nmap",
        description="Port scanner",
        category=ToolCategory.RECONNAISSANCE,
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
        status=ToolStatus.MOCK,
    )

    resp = await client.chat(
        messages=[
            {"role": "user", "content": "Scan localhost"},
            {"role": "model_function_call", "name": "whatweb_scan", "args": {"target": "localhost"}},
            {"role": "function_result", "name": "whatweb_scan", "content": {"server": "nginx"}},
        ],
        tools=[tool],
        system_prompt="Be concise.",
    )

    assert resp.has_function_call is True
    assert resp.function_call == {"name": "nmap_scan", "args": {"target": "localhost", "profile": "quick"}}
    assert captured["model"] == "gemini-2.5-flash"
    assert "systemInstruction" in captured["payload"]
    assert captured["payload"]["tools"][0]["functionDeclarations"][0]["name"] == "nmap_scan"


def test_parse_rest_response_text():
    resp = GeminiClient._parse_rest_response({
        "candidates": [{"content": {"parts": [{"text": "Hello from Gemini REST"}]}}]
    })
    assert resp.has_function_call is False
    assert resp.text == "Hello from Gemini REST"
    assert resp.provider == "gemini"


def test_cli_imports_safely_under_pytest():
    import cli
    assert hasattr(cli, "_auto_activate_venv")
    assert callable(cli.load_dotenv)
