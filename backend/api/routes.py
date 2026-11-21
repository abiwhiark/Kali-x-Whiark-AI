"""
Kali AI - API Routes
REST and SSE endpoints for the Kali AI application.
"""

from __future__ import annotations

import asyncio
import json
import logging
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse, PlainTextResponse
from pydantic import BaseModel as PydanticBaseModel

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


# ──────────────────────────────────────────────
# General-purpose chatbot endpoint (no tools / SSE)
# ──────────────────────────────────────────────

class SimpleChatRequest(PydanticBaseModel):
    message: str
    history: list[dict] = []   # list of {"role": "user"|"assistant", "content": str}


def _generate_demo_chat_reply(message: str) -> str:
    """Generate helpful educational response when running in demo mode."""
    msg = message.lower().strip()
    if any(g in msg for g in ["hi", "hello", "hey", "who are you", "what can you do"]):
        return (
            "👋 **Hello! I'm Kali AI** — your AI cybersecurity assistant.\n\n"
            "I work just like ChatGPT or Gemini, with special expertise in:\n"
            "- 🛡️ **Penetration Testing & Tools**: Nmap, WhatWeb, Nuclei, Nikto, SSLyze, ZAP, Gobuster\n"
            "- 🧠 **Security Concepts**: OWASP Top 10, CVEs, cryptography, network protocols\n"
            "- 💻 **Coding & Scripting**: Python, Bash, security automation, exploit analysis\n"
            "- 🔍 **Live Target Scanning**: Switch to **Scan Mode** to execute multi-tool security assessments!\n\n"
            "What can I help you explore today?"
        )
    if "sql injection" in msg or "sqli" in msg:
        return (
            "### 💉 SQL Injection (SQLi) Overview\n\n"
            "**SQL Injection** occurs when untrusted user input is directly concatenated into a dynamic SQL query without parameterization.\n\n"
            "#### Example Vulnerable Code (PHP):\n"
            "```php\n"
            "$user = $_GET['user'];\n"
            "$query = \"SELECT * FROM users WHERE username = '$user'\";\n"
            "```\n"
            "#### Attack Payload:\n"
            "`admin' OR '1'='1' -- -`\n\n"
            "#### Prevention:\n"
            "1. **Prepared Statements (Parameterized Queries)**:\n"
            "   ```php\n"
            "   $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :user');\n"
            "   $stmt->execute(['user' => $user]);\n"
            "   ```\n"
            "2. **Input validation & Least Privilege DB user**"
        )
    if "nmap" in msg:
        return (
            "### 📡 Nmap (Network Mapper) Quick Guide\n\n"
            "Nmap is the industry standard for network discovery and vulnerability detection.\n\n"
            "#### Common Scan Profiles:\n"
            "- **Fast Scan (Top 100 ports)**: `nmap -F <target>`\n"
            "- **Service & Version Detection**: `nmap -sV -sC <target>`\n"
            "- **Full Port Range**: `nmap -p- <target>`\n"
            "- **Aggressive Scan**: `nmap -A <target>`\n\n"
            "💡 *Tip:* In **Scan Mode**, you can ask me to run an Nmap scan directly on your target!"
        )
    if "xss" in msg or "cross site scripting" in msg:
        return (
            "### ⚡ Cross-Site Scripting (XSS)\n\n"
            "XSS occurs when malicious scripts are injected into trusted websites and executed in the victim's browser.\n\n"
            "- **Reflected XSS**: Payload is reflected off the server (e.g., in search queries).\n"
            "- **Stored XSS**: Payload is permanently stored in the database (e.g., comments, forum posts).\n"
            "- **DOM-based XSS**: Vulnerability exists purely in client-side JavaScript.\n\n"
            "**Mitigation**: Context-aware output encoding, Content Security Policy (CSP), and HttpOnly cookies."
        )
    return (
        f"**Kali AI (Demo Assistant):**\n\n"
        f"Regarding your question about: *\"{message}\"*\n\n"
        "Kali AI is capable of in-depth conversational answers, explaining security architecture, "
        "remediation steps, code auditing, and performing automated tool assessments. "
        "With `GEMINI_API_KEY` configured in `.env`, you have full multi-turn conversational reasoning powered by Gemini!"
    )


@router.post("/chat_simple")
async def chat_simple(request: SimpleChatRequest):
    """Pure conversational chat endpoint — conversational AI just like ChatGPT/Gemini."""
    settings = get_settings()

    if settings.demo_mode:
        return {"reply": _generate_demo_chat_reply(request.message)}

    from google import genai
    from google.genai import types

    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    CHAT_SYSTEM = (
        "You are Kali AI, an expert, friendly cybersecurity assistant and conversational AI. "
        "You can answer questions about cybersecurity, explain technical concepts, assist with CTF challenges, "
        "write and review code, discuss security tools, networking, and engage in natural conversation on any topic. "
        "Format responses using clear markdown, bolding, lists, and code blocks with syntax highlighting where relevant. "
        "If the user asks to run an active security scan on a target, kindly remind them to use Scan Mode or provide a target."
    )

    contents = []
    for h in request.history[-20:]:
        role = h.get("role", "user")
        content_text = h.get("content", "")
        if not content_text:
            continue
        gemini_role = "user" if role == "user" else "model"
        contents.append(types.Content(role=gemini_role, parts=[types.Part.from_text(text=content_text)]))

    contents.append(types.Content(role="user", parts=[types.Part.from_text(text=request.message)]))

    try:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model=settings.GEMINI_MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=CHAT_SYSTEM,
                temperature=0.7,
            ),
        )
        reply_text = response.text or "No response generated."
    except Exception as e:
        err_str = str(e)
        logger.warning("Error in simple chat: %s", err_str)
        if "RESOURCE_EXHAUSTED" in err_str or "429" in err_str:
            reply_text = (
                "⚠️ **Gemini API rate limit reached (Free tier).**\n\n"
                "Please wait 30 seconds before sending your next message. "
                "Here is an instant demo answer to your question in the meantime:\n\n"
                + _generate_demo_chat_reply(request.message)
            )
        else:
            reply_text = f"I encountered an error communicating with Gemini: {err_str}"

    return {"reply": reply_text}
