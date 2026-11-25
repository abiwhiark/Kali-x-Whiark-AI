"""
Kali AI - Multi-Provider AI Client
====================================
Supports: Google Gemini, OpenAI, Anthropic Claude, Ollama (local/no rate limits)

Provider selection priority:
  1. ACTIVE_PROVIDER env var  (set by setup wizard or mid-session switch)
  2. Auto-detect from which API keys are present in .env
  3. Fallback to Demo Mode (no key needed)
"""

from __future__ import annotations

import logging
import os
from typing import Any

from backend.core.config import get_settings
from backend.models.schemas import ToolDefinition

logger = logging.getLogger(__name__)


def _build_function_declarations(tools: list[ToolDefinition]) -> list[dict[str, Any]]:
    declarations = []
    for tool in tools:
        declarations.append({
            "name": tool.id,
            "description": tool.description,
            "parameters": tool.input_schema,
        })
    return declarations


class AIResponse:
    def __init__(
        self,
        text: str = "",
        function_call: dict[str, Any] | None = None,
        finish_reason: str = "stop",
        demo: bool = False,
        plan_text: str | None = None,
        provider: str = "",
    ):
        self.text = text
        self.function_call = function_call
        self.finish_reason = finish_reason
        self.demo = demo
        self.plan_text = plan_text
        self.provider = provider

    @property
    def has_function_call(self) -> bool:
        return self.function_call is not None

    def __repr__(self) -> str:
        if self.has_function_call:
            return f"AIResponse(fc={self.function_call['name']}, provider={self.provider})"
        return f"AIResponse(text={self.text[:60]}..., provider={self.provider})"


# ── GEMINI CLIENT ─────────────────────────────────────────────────────

# Working Gemini models (in preference order, newest/best first)
GEMINI_MODELS_FALLBACK = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.5-pro",
]


class GeminiClient:
    """Google Gemini API client with automatic model fallback."""

    def __init__(self, api_key: str = "", model: str = "") -> None:
        settings = get_settings()
        self._api_key = api_key or settings.GEMINI_API_KEY
        self._model_name = model or settings.GEMINI_MODEL or "gemini-2.5-flash"

        from google import genai
        # v1beta required for system_instruction support
        self._client = genai.Client(
            api_key=self._api_key,
            http_options={"api_version": "v1beta"},
        )
        self._genai = genai
        logger.info("GeminiClient initialized — model=%s", self._model_name)

    def _next_model(self) -> str | None:
        """Return next model in fallback list, or None if exhausted."""
        try:
            idx = GEMINI_MODELS_FALLBACK.index(self._model_name)
            if idx + 1 < len(GEMINI_MODELS_FALLBACK):
                return GEMINI_MODELS_FALLBACK[idx + 1]
        except ValueError:
            pass
        return None

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        from google.genai import types
        import asyncio

        func_decls = _build_function_declarations(tools)
        gemini_tools = [types.Tool(function_declarations=[
            types.FunctionDeclaration(
                name=fd["name"],
                description=fd["description"],
                parameters=fd["parameters"],
            )
            for fd in func_decls
        ])] if func_decls else []

        contents = []
        for msg in messages:
            role = msg["role"]
            if role == "system":
                continue
            if role == "function_result":
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part.from_function_response(
                        name=msg["name"], response=msg["content"],
                    )],
                ))
            elif role == "model_function_call":
                contents.append(types.Content(
                    role="model",
                    parts=[types.Part.from_function_call(
                        name=msg["name"], args=msg["args"],
                    )],
                ))
            else:
                gemini_role = "user" if role == "user" else "model"
                contents.append(types.Content(
                    role=gemini_role,
                    parts=[types.Part.from_text(text=msg["content"])],
                ))

        config = types.GenerateContentConfig(
            system_instruction=system_prompt if system_prompt else None,
            tools=gemini_tools if gemini_tools else None,
            temperature=0.2,
        )

        # Build candidate models starting with preferred model, then remaining fallbacks
        candidate_models = [self._model_name] + [m for m in GEMINI_MODELS_FALLBACK if m != self._model_name]

        for attempt_model in candidate_models:
            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._client.models.generate_content,
                        model=attempt_model,
                        contents=contents,
                        config=config,
                    ),
                    timeout=30.0,
                )
                # Success — remember working model
                if attempt_model != self._model_name:
                    logger.warning("Switched to working model: %s", attempt_model)
                    self._model_name = attempt_model
                break

            except Exception as e:
                err = str(e)
                if "404" in err or "no longer available" in err or "NOT_FOUND" in err:
                    logger.warning("Model %s not found (404), trying next model...", attempt_model)
                    continue
                elif "RESOURCE_EXHAUSTED" in err or "429" in err:
                    logger.warning("Rate limit on %s (429), trying next fallback model...", attempt_model)
                    continue  # Try next model in chain instead of immediately failing
                elif "INVALID_ARGUMENT" in err and "v1beta" not in err:
                    logger.error("Gemini API error on %s: %s", attempt_model, err)
                    continue
                else:
                    logger.warning("Gemini error on %s: %s, trying next...", attempt_model, err[:150])
                    continue
        else:
            # All models exhausted
            logger.warning("All Gemini models exhausted or rate-limited. Falling back to Demo.")
            return await DemoClient().chat(messages, tools, system_prompt)

        if not response.candidates:
            return AIResponse(text="No response generated.", provider="gemini")

        candidate = response.candidates[0]
        parts = candidate.content.parts if candidate.content else []

        for part in parts:
            if part.function_call:
                fc = part.function_call
                text_parts = [p.text for p in parts if p.text]
                return AIResponse(
                    text="\n".join(text_parts) if text_parts else "",
                    function_call={"name": fc.name, "args": dict(fc.args) if fc.args else {}},
                    finish_reason="function_call",
                    provider="gemini",
                )

        text_parts = [p.text for p in parts if p.text]
        return AIResponse(text="\n".join(text_parts) if text_parts else "", provider="gemini")


# ── OLLAMA CLIENT (local, no rate limits) ────────────────────────────

class OllamaClient:
    """Local Ollama LLM client — supports native tool calling + JSON fallback for cyber models."""

    def __init__(self, model: str = "kali-cyber", host: str = "http://localhost:11434") -> None:
        self._model = model
        self._host = host.rstrip("/")
        self._supports_native_tools: bool | None = None
        logger.info("OllamaClient initialized — model=%s host=%s", model, host)

    @staticmethod
    def _extract_json_tool_call(text: str, valid_names: set[str]) -> dict[str, Any] | None:
        """Extract a JSON tool call emitted in text when model lacks native tool_calls."""
        import json
        import re

        if not text:
            return None

        # Check fenced JSON blocks first, then raw JSON objects containing tool_call/name
        candidates: list[str] = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        candidates.extend(re.findall(r"(\{[^{}]*\"(?:tool_call|name)\"[^{}]*(?:\{[^{}]*\}[^{}]*)?\})", text, re.DOTALL))

        for raw in candidates:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            fc = data.get("tool_call") if isinstance(data.get("tool_call"), dict) else data
            name = fc.get("name") or fc.get("tool") or fc.get("tool_id")
            args = fc.get("args") or fc.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if isinstance(name, str) and name in valid_names and isinstance(args, dict):
                return {"name": name, "args": args}
        return None

    def _build_ollama_messages(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str,
        use_native_tools: bool,
        tools: list[ToolDefinition],
    ) -> list[dict[str, Any]]:
        import json

        ollama_messages: list[dict[str, Any]] = []
        effective_system = system_prompt or ""

        if not use_native_tools and tools:
            tool_specs = "\n".join(
                f"- {t.id}: {t.description} (params: {json.dumps(t.input_schema.get('properties', {}))})"
                for t in tools
            )
            effective_system = (
                f"{effective_system}\n\n"
                "TOOL EXECUTION INSTRUCTIONS:\n"
                "To execute a security tool, reply ONLY with a JSON block in this exact format:\n"
                "```json\n{\"tool_call\": {\"name\": \"<tool_id>\", \"arguments\": {\"target\": \"<target>\"}}}\n```\n"
                f"Available tools:\n{tool_specs}\n"
                "Only after all needed tools have returned results, write your final assessment report."
            ).strip()

        if effective_system:
            ollama_messages.append({"role": "system", "content": effective_system})

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role in ("user", "assistant", "model"):
                ollama_role = "assistant" if role in ("assistant", "model") else "user"
                ollama_messages.append({"role": ollama_role, "content": str(content)})
            elif role == "model_function_call":
                fc_name = msg.get("name", "")
                fc_args = msg.get("args", {})
                if use_native_tools:
                    ollama_messages.append({
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{
                            "type": "function",
                            "function": {"name": fc_name, "arguments": fc_args},
                        }],
                    })
                else:
                    ollama_messages.append({
                        "role": "assistant",
                        "content": json.dumps({"tool_call": {"name": fc_name, "arguments": fc_args}}),
                    })
            elif role == "function_result":
                fc_name = msg.get("name", "tool")
                serialized = json.dumps(content, default=str)[:4000]
                if use_native_tools:
                    ollama_messages.append({
                        "role": "tool",
                        "content": serialized,
                        "tool_name": fc_name,
                    })
                else:
                    ollama_messages.append({
                        "role": "user",
                        "content": f"Tool result for `{fc_name}`:\n```json\n{serialized}\n```",
                    })
        return ollama_messages

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        import asyncio
        import json
        import urllib.error
        import urllib.request

        func_decls = _build_function_declarations(tools)
        ollama_tools = [
            {
                "type": "function",
                "function": {
                    "name": fd["name"],
                    "description": fd["description"],
                    "parameters": fd["parameters"],
                },
            }
            for fd in func_decls
        ]
        valid_names = {t.id for t in tools}

        def _post(payload_dict: dict[str, Any]) -> dict[str, Any]:
            payload = json.dumps(payload_dict).encode("utf-8")
            req = urllib.request.Request(
                f"{self._host}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as he:
                body = he.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"HTTP {he.code}: {body}") from he

        use_native = bool(ollama_tools) and (self._supports_native_tools is not False)
        ollama_messages = self._build_ollama_messages(messages, system_prompt, use_native, tools)

        payload_dict: dict[str, Any] = {
            "model": self._model,
            "messages": ollama_messages,
            "stream": False,
        }
        if use_native and ollama_tools:
            payload_dict["tools"] = ollama_tools

        try:
            try:
                result = await asyncio.wait_for(asyncio.to_thread(_post, payload_dict), timeout=180.0)
                if use_native and ollama_tools:
                    self._supports_native_tools = True
            except RuntimeError as rt_err:
                err_lower = str(rt_err).lower()
                if use_native and ("does not support tools" in err_lower or "tool" in err_lower and "400" in err_lower):
                    logger.info("Model %s lacks native Ollama tool support; using JSON tool fallback.", self._model)
                    self._supports_native_tools = False
                    fallback_msgs = self._build_ollama_messages(messages, system_prompt, False, tools)
                    result = await asyncio.wait_for(
                        asyncio.to_thread(_post, {"model": self._model, "messages": fallback_msgs, "stream": False}),
                        timeout=180.0,
                    )
                else:
                    raise

            msg_obj = result.get("message", {}) or {}
            text = msg_obj.get("content", "") or ""
            raw_tool_calls = msg_obj.get("tool_calls") or []

            # 1. Native Ollama tool_calls
            if raw_tool_calls and isinstance(raw_tool_calls, list):
                first_call = raw_tool_calls[0].get("function", {}) if isinstance(raw_tool_calls[0], dict) else {}
                fc_name = first_call.get("name", "")
                fc_args = first_call.get("arguments", {})
                if isinstance(fc_args, str):
                    try:
                        fc_args = json.loads(fc_args)
                    except json.JSONDecodeError:
                        fc_args = {}
                if fc_name:
                    return AIResponse(
                        text=text,
                        function_call={"name": fc_name, "args": fc_args if isinstance(fc_args, dict) else {}},
                        finish_reason="function_call",
                        provider=f"ollama/{self._model}",
                    )

            # 2. Fallback JSON tool-call extraction (for cyber fine-tuned models without native tools)
            if valid_names:
                parsed_fc = self._extract_json_tool_call(text, valid_names)
                if parsed_fc:
                    return AIResponse(
                        text="",
                        function_call=parsed_fc,
                        finish_reason="function_call",
                        provider=f"ollama/{self._model}",
                    )

            return AIResponse(
                text=text or "No response from Ollama.",
                provider=f"ollama/{self._model}",
            )

        except Exception as e:
            err = str(e)
            if "Connection refused" in err or "connection refused" in err.lower() or "10061" in err:
                return AIResponse(
                    text=(
                        "❌ **Ollama is not running.**\n\n"
                        "Start it on Kali Linux with:\n```bash\nollama serve\n```\n"
                        f"Then make sure your model is pulled:\n```bash\nollama pull {self._model}\n```"
                    ),
                    provider="ollama",
                )
            if "not found" in err.lower() and "404" in err:
                return AIResponse(
                    text=(
                        f"❌ **Ollama model `{self._model}` is not installed yet.**\n\n"
                        f"Pull or create it first:\n```bash\nollama pull {self._model}\n```"
                    ),
                    provider="ollama",
                )
            return AIResponse(text=f"Ollama error: {err[:300]}", provider="ollama")

    async def simple_chat(self, message: str, history: list[dict] | None = None) -> str:
        """Simple conversational chat without tools."""
        messages = []
        for h in (history or [])[-20:]:
            role = h.get("role", "user")
            if role in ("user", "assistant"):
                messages.append({"role": role, "content": h.get("content", "")})
        messages.append({"role": "user", "content": message})
        result = await self.chat(messages, [], system_prompt="You are Kali AI, an expert cybersecurity assistant.")
        return result.text


# ── OPENAI CLIENT ─────────────────────────────────────────────────────

class OpenAIClient:
    """OpenAI GPT client."""

    def __init__(self, api_key: str = "", model: str = "gpt-4o-mini") -> None:
        self._model = model
        self._api_key = api_key
        logger.info("OpenAIClient initialized — model=%s", model)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        import asyncio
        try:
            from openai import AsyncOpenAI
        except ImportError:
            return AIResponse(text="OpenAI package not installed. Run: pip install openai", provider="openai")

        client = AsyncOpenAI(api_key=self._api_key)
        oai_messages = []
        if system_prompt:
            oai_messages.append({"role": "system", "content": system_prompt})
        for msg in messages:
            role = msg["role"]
            content = msg.get("content", "")
            if role == "user":
                oai_messages.append({"role": "user", "content": content})
            elif role in ("model", "assistant"):
                oai_messages.append({"role": "assistant", "content": content})
            elif role == "function_result":
                oai_messages.append({"role": "user", "content": f"Tool result: {content}"})

        try:
            resp = await asyncio.wait_for(
                client.chat.completions.create(model=self._model, messages=oai_messages, temperature=0.2),
                timeout=30.0,
            )
            text = resp.choices[0].message.content or ""
            return AIResponse(text=text, provider=f"openai/{self._model}")
        except Exception as e:
            return AIResponse(text=f"OpenAI error: {str(e)[:200]}", provider="openai")

    async def simple_chat(self, message: str, history: list[dict] | None = None) -> str:
        messages = []
        for h in (history or [])[-20:]:
            role = h.get("role", "user")
            messages.append({"role": role if role != "assistant" else "assistant",
                             "content": h.get("content", "")})
        messages.append({"role": "user", "content": message})
        result = await self.chat(messages, [])
        return result.text


# ── ANTHROPIC CLIENT ──────────────────────────────────────────────────

class AnthropicClient:
    """Anthropic Claude client."""

    def __init__(self, api_key: str = "", model: str = "claude-3-5-haiku-20241022") -> None:
        self._model = model
        self._api_key = api_key
        logger.info("AnthropicClient initialized — model=%s", model)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        import asyncio
        try:
            import anthropic
        except ImportError:
            return AIResponse(text="Anthropic package not installed. Run: pip install anthropic", provider="anthropic")

        client = anthropic.AsyncAnthropic(api_key=self._api_key)
        ant_messages = []
        for msg in messages:
            role = msg["role"]
            content = msg.get("content", "")
            if role == "user":
                ant_messages.append({"role": "user", "content": content})
            elif role in ("model", "assistant"):
                ant_messages.append({"role": "assistant", "content": content})

        try:
            resp = await asyncio.wait_for(
                client.messages.create(
                    model=self._model,
                    max_tokens=4096,
                    system=system_prompt or "You are Kali AI, an expert cybersecurity assistant.",
                    messages=ant_messages,
                ),
                timeout=30.0,
            )
            text = resp.content[0].text if resp.content else ""
            return AIResponse(text=text, provider=f"anthropic/{self._model}")
        except Exception as e:
            return AIResponse(text=f"Anthropic error: {str(e)[:200]}", provider="anthropic")

    async def simple_chat(self, message: str, history: list[dict] | None = None) -> str:
        messages = []
        for h in (history or [])[-20:]:
            role = h.get("role", "user")
            messages.append({"role": role, "content": h.get("content", "")})
        messages.append({"role": "user", "content": message})
        result = await self.chat(messages, [])
        return result.text


# ── DEMO CLIENT ───────────────────────────────────────────────────────

class DemoClient:
    """Offline demo client — no API key needed."""

    def __init__(self) -> None:
        logger.info("DemoClient initialized — DEMO MODE")

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str = "",
    ) -> AIResponse:
        user_objective = ""
        target = "localhost"
        for m in messages:
            if m.get("role") == "user":
                content = m.get("content", "")
                for line in content.splitlines():
                    if line.startswith("Objective:"):
                        user_objective = line.split(":", 1)[1].strip()
                    elif line.startswith("Authorized target:"):
                        target = line.split(":", 1)[1].strip()
                if not user_objective:
                    user_objective = content

        obj_lower = user_objective.lower()
        func_results = [m for m in messages if m.get("role") == "function_result"]
        has_plan = any(
            m.get("role") == "model" and "assessment plan" in m.get("content", "").lower()
            for m in messages
        )

        is_greeting = obj_lower in ["hi", "hello", "hey", "test"]
        info_keywords = ["capabilities", "what can you do", "who are you", "help", "tools"]
        is_info = any(k in obj_lower for k in info_keywords) or is_greeting

        if is_info and not any(kw in obj_lower for kw in ["scan", "assess", "check"]):
            return AIResponse(
                text=(
                    "### 🛡️ Kali AI — DEMO MODE\n\n"
                    "Running without API key. Configure a provider with the `provider` command.\n\n"
                    "**Supported providers:**\n"
                    "- Google Gemini (free tier)\n"
                    "- OpenAI GPT\n"
                    "- Anthropic Claude\n"
                    "- 🟢 Ollama (local — no rate limits!)\n"
                ),
                demo=True, provider="demo",
            )

        tool_mappings = [
            ("nmap_scan", ["nmap", "port", "open port", "service"], "Port Discovery", {"target": target}),
            ("whatweb_scan", ["whatweb", "tech", "cms", "identify"], "Tech Profiling", {"target": target}),
            ("nuclei_scan", ["nuclei", "vuln", "cve"], "Vuln Scan", {"target": target, "templates": "default"}),
            ("gobuster_scan", ["gobuster", "directory", "dir"], "Dir Brute", {"target": target}),
        ]

        for tid, kws, title, args in tool_mappings:
            if any(kw in obj_lower for kw in kws):
                if not func_results:
                    return AIResponse(
                        text=f"[DEMO] Running {tid} against {target}",
                        function_call={"name": tid, "args": args},
                        finish_reason="function_call", demo=True, provider="demo",
                    )
                return AIResponse(
                    text=f"[DEMO] {title} complete on {target}.",
                    finish_reason="stop", demo=True, provider="demo",
                )

        if not has_plan and not func_results:
            return AIResponse(
                text=f"[DEMO] Assessment plan for {target}: WhatWeb → Nmap → Nuclei",
                demo=True, provider="demo",
            )
        if not func_results:
            return AIResponse(
                text="[DEMO] Running WhatWeb...",
                function_call={"name": "whatweb_scan", "args": {"target": target}},
                finish_reason="function_call", demo=True, provider="demo",
            )
        if len(func_results) == 1:
            return AIResponse(
                text="[DEMO] Running Nmap...",
                function_call={"name": "nmap_scan", "args": {"target": target}},
                finish_reason="function_call", demo=True, provider="demo",
            )
        return AIResponse(
            text="[DEMO] Assessment complete. See findings panel.",
            finish_reason="stop", demo=True, provider="demo",
        )

    async def simple_chat(self, message: str, history: list[dict] | None = None) -> str:
        return (
            "⚠️ **Running in Demo Mode** — no AI provider configured.\n\n"
            "Type `provider` to set up Gemini, OpenAI, Anthropic, or Ollama."
        )


# ── FACTORY ───────────────────────────────────────────────────────────

def create_ai_client(
    provider: str = "",
    api_key: str = "",
    model: str = "",
) -> GeminiClient | OllamaClient | OpenAIClient | AnthropicClient | DemoClient:
    """
    Create the right AI client.
    Priority: explicit provider arg → env ACTIVE_PROVIDER → auto-detect from keys → demo
    """
    settings = get_settings()

    # Determine provider
    p = (
        provider
        or os.environ.get("ACTIVE_PROVIDER", "")
        or settings.__dict__.get("ACTIVE_PROVIDER", "")
    ).lower()

    # Auto-detect if not set
    if not p:
        if settings.GEMINI_API_KEY and settings.GEMINI_API_KEY not in ("", "your_key_here"):
            p = "gemini"
        elif os.environ.get("OPENAI_API_KEY", ""):
            p = "openai"
        elif os.environ.get("ANTHROPIC_API_KEY", ""):
            p = "anthropic"
        elif os.environ.get("OLLAMA_HOST", "") or _ollama_running():
            p = "ollama"
        else:
            p = "demo"

    logger.info("AI provider selected: %s", p)

    if p == "gemini":
        key = api_key or settings.GEMINI_API_KEY
        if not key or key in ("", "your_key_here"):
            logger.warning("GEMINI_API_KEY not set — falling back to DemoClient.")
            return DemoClient()
        m = model or settings.GEMINI_MODEL or "gemini-2.5-flash"
        return GeminiClient(api_key=key, model=m)
    elif p == "ollama":
        m = model or settings.OLLAMA_MODEL or os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
        host = settings.OLLAMA_HOST or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        return OllamaClient(model=m, host=host)
    elif p == "openai":
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        m = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        return OpenAIClient(api_key=key, model=m)
    elif p == "anthropic":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        m = model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        return AnthropicClient(api_key=key, model=m)
    else:
        return DemoClient()


def _ollama_running() -> bool:
    """Quick check if Ollama is listening on default port."""
    import socket
    try:
        s = socket.create_connection(("localhost", 11434), timeout=1)
        s.close()
        return True
    except Exception:
        return False
