"""
Kali AI - Setup Wizard
========================
Runs before the first launch (or when user types 'provider' / 'setup').
Asks the user which AI provider to use, collects credentials,
and writes everything cleanly to the .env file.

Supported providers:
  1. Google Gemini  (free tier: 1500 req/day with gemini-3.8-flash)
  2. OpenAI GPT     (paid, very capable)
  3. Anthropic      (paid, great for analysis)
  4. Ollama         (LOCAL — no API key, no rate limits, runs on your machine)
  5. Demo Mode      (no key — simulated responses, good for testing UI)
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ENV_FILE = ROOT / ".env"

# ── Terminal colors (no rich dependency here) ─────────────────────────
C = {
    "RED":    "\033[91m",
    "GREEN":  "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN":   "\033[96m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "RESET":  "\033[0m",
}


def _c(color: str, text: str) -> str:
    return f"{C.get(color, '')}{text}{C['RESET']}"


def _banner():
    print(_c("CYAN", """
╔══════════════════════════════════════════════════════════╗
║        ⚡ WHIARK × KALI AI — PROVIDER SETUP ⚡           ║
╚══════════════════════════════════════════════════════════╝
"""))


def _ollama_running() -> bool:
    try:
        s = socket.create_connection(("localhost", 11434), timeout=1)
        s.close()
        return True
    except Exception:
        return False


def _read_env() -> dict[str, str]:
    """Read existing .env into a dict."""
    env: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def _write_env(env: dict[str, str]) -> None:
    """Write dict back to .env preserving comments from .env.example."""
    example = ROOT / ".env.example"
    if example.exists():
        # Build new .env from example template, substituting values
        lines = []
        written_keys: set[str] = set()
        for line in example.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                if k in env:
                    lines.append(f"{k}={env[k]}")
                    written_keys.add(k)
                else:
                    lines.append(line)
            else:
                lines.append(line)
        # Append any extra keys not in template
        for k, v in env.items():
            if k not in written_keys:
                lines.append(f"{k}={v}")
        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        lines = [f"{k}={v}" for k, v in env.items()]
        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _inp(prompt: str, default: str = "") -> str:
    """Input with default."""
    hint = f" [{_c('DIM', default)}]" if default else ""
    val = input(f"  {prompt}{hint}: ").strip()
    return val if val else default


def run_setup_wizard(force: bool = False) -> dict[str, str]:
    """
    Run the interactive provider setup wizard.
    Returns the chosen config as a dict.
    Only runs if .env has no provider set, or force=True.
    """
    env = _read_env()

    # Skip if already configured and not forced
    if not force:
        has_key = any([
            env.get("GEMINI_API_KEY", "") not in ("", "your_key_here"),
            env.get("OPENAI_API_KEY", ""),
            env.get("ANTHROPIC_API_KEY", ""),
            env.get("ACTIVE_PROVIDER", "").lower() == "ollama",
        ])
        if has_key:
            return env

    _banner()

    ollama_status = (
        _c("GREEN", "✔ Ollama is running on this machine!")
        if _ollama_running()
        else _c("DIM", "(not detected — install with: curl -fsSL https://ollama.com/install.sh | sh)")
    )

    print(_c("BOLD", "  Choose your AI provider:\n"))
    providers = [
        ("1", "gemini",    "Google Gemini",    "Free: 1500 req/day • Needs API key from aistudio.google.com"),
        ("2", "openai",    "OpenAI GPT",        "Paid • Needs API key from platform.openai.com"),
        ("3", "anthropic", "Anthropic Claude",  "Paid • Needs API key from console.anthropic.com"),
        ("4", "ollama",    "Ollama (Local)",    f"FREE • No rate limits • Runs on your machine {ollama_status}"),
        ("5", "demo",      "Demo Mode",         "No key needed • Simulated responses only"),
    ]

    for num, pid, name, desc in providers:
        print(f"  {_c('CYAN', num)}. {_c('BOLD', name)}")
        print(f"     {_c('DIM', desc)}")
        print()

    choice = _inp("Enter choice", "1")
    chosen = next(((pid, name) for num, pid, name, _ in providers if num == choice), ("gemini", "Google Gemini"))
    pid, pname = chosen

    print(f"\n  {_c('GREEN', '✔')} Selected: {_c('BOLD', pname)}\n")
    env["ACTIVE_PROVIDER"] = pid

    if pid == "gemini":
        print(f"  {_c('DIM', 'Get your free API key → https://aistudio.google.com/app/apikey')}")
        key = _inp("Gemini API Key", env.get("GEMINI_API_KEY", ""))
        model = _inp("Model", env.get("GEMINI_MODEL", "gemini-3.8-flash"))
        env["GEMINI_API_KEY"] = key
        env["GEMINI_MODEL"] = model or "gemini-3.8-flash"

    elif pid == "openai":
        print(f"  {_c('DIM', 'Get your API key → https://platform.openai.com/api-keys')}")
        key = _inp("OpenAI API Key", env.get("OPENAI_API_KEY", ""))
        model = _inp("Model", env.get("OPENAI_MODEL", "gpt-4o-mini"))
        env["OPENAI_API_KEY"] = key
        env["OPENAI_MODEL"] = model or "gpt-4o-mini"

    elif pid == "anthropic":
        print(f"  {_c('DIM', 'Get your API key → https://console.anthropic.com')}")
        key = _inp("Anthropic API Key", env.get("ANTHROPIC_API_KEY", ""))
        model = _inp("Model", env.get("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022"))
        env["ANTHROPIC_API_KEY"] = key
        env["ANTHROPIC_MODEL"] = model or "claude-3-5-haiku-20241022"

    elif pid == "ollama":
        host = _inp("Ollama host", env.get("OLLAMA_HOST", "http://localhost:11434"))
        env["OLLAMA_HOST"] = host or "http://localhost:11434"

        # List available models
        try:
            import urllib.request, json
            with urllib.request.urlopen(f"{host}/api/tags", timeout=3) as r:
                data = json.loads(r.read())
                models = [m["name"] for m in data.get("models", [])]
            if models:
                print(f"\n  {_c('GREEN', 'Available Ollama models:')}")
                for i, m in enumerate(models[:10], 1):
                    print(f"    {_c('CYAN', str(i))}. {m}")
                print()
        except Exception:
            models = []

        default_model = models[0] if models else "llama3"
        model = _inp("Ollama model", env.get("OLLAMA_MODEL", default_model))
        env["OLLAMA_MODEL"] = model or default_model

        if not _ollama_running():
            print(f"\n  {_c('YELLOW', '⚠  Ollama not detected. Start it with:')}")
            print(f"     {_c('CYAN', 'ollama serve')}")
            print(f"     {_c('CYAN', f'ollama pull {env[\"OLLAMA_MODEL\"]}')}\n")

    elif pid == "demo":
        print(f"  {_c('YELLOW', '  Running in Demo Mode — no AI calls, simulated responses.')}")

    # Write .env
    if "ALLOWED_TARGETS" not in env:
        env["ALLOWED_TARGETS"] = "*"
    if "MAX_AGENT_ITERATIONS" not in env:
        env["MAX_AGENT_ITERATIONS"] = "10"
    if "MAX_TOOL_CALLS" not in env:
        env["MAX_TOOL_CALLS"] = "15"
    if "TOOL_EXECUTION_TIMEOUT" not in env:
        env["TOOL_EXECUTION_TIMEOUT"] = "120"

    _write_env(env)

    # Reload settings
    from backend.core.config import reload_settings
    reload_settings()

    # Also set env vars for current process
    for k, v in env.items():
        os.environ[k] = v

    print(f"\n  {_c('GREEN', '✔  Configuration saved to .env')}")
    print(f"  {_c('DIM', str(ENV_FILE))}\n")
    return env


def change_api_key(provider: str = "") -> None:
    """Mid-session: change API key or switch provider."""
    env = _read_env()

    if not provider:
        print(f"\n  {_c('CYAN', 'Current provider:')} {env.get('ACTIVE_PROVIDER', 'not set')}")
        print(f"  {_c('BOLD', 'Enter new provider')} (gemini/openai/anthropic/ollama/demo) or press Enter to keep:")
        provider = input("  > ").strip().lower() or env.get("ACTIVE_PROVIDER", "gemini")

    env["ACTIVE_PROVIDER"] = provider

    if provider == "gemini":
        print(f"  {_c('DIM', 'Get key → https://aistudio.google.com/app/apikey')}")
        key = _inp("New Gemini API Key", env.get("GEMINI_API_KEY", ""))
        model = _inp("Model", env.get("GEMINI_MODEL", "gemini-3.8-flash"))
        env["GEMINI_API_KEY"] = key
        env["GEMINI_MODEL"] = model or "gemini-3.8-flash"
        os.environ["GEMINI_API_KEY"] = key
        os.environ["GEMINI_MODEL"] = env["GEMINI_MODEL"]

    elif provider == "openai":
        key = _inp("New OpenAI API Key", env.get("OPENAI_API_KEY", ""))
        env["OPENAI_API_KEY"] = key
        os.environ["OPENAI_API_KEY"] = key

    elif provider == "anthropic":
        key = _inp("New Anthropic API Key", env.get("ANTHROPIC_API_KEY", ""))
        env["ANTHROPIC_API_KEY"] = key
        os.environ["ANTHROPIC_API_KEY"] = key

    elif provider == "ollama":
        model = _inp("Ollama model", env.get("OLLAMA_MODEL", "llama3"))
        env["OLLAMA_MODEL"] = model or "llama3"
        os.environ["OLLAMA_MODEL"] = env["OLLAMA_MODEL"]

    _write_env(env)
    os.environ["ACTIVE_PROVIDER"] = provider

    from backend.core.config import reload_settings
    reload_settings()

    print(f"  {_c('GREEN', '✔')} Switched to {_c('BOLD', provider)}. Changes saved to .env.\n")


def reset_config() -> None:
    """Wipe the .env and re-run wizard."""
    if ENV_FILE.exists():
        ENV_FILE.unlink()
    example = ROOT / ".env.example"
    if example.exists():
        import shutil
        shutil.copy(example, ENV_FILE)
    print("  Config reset. Re-running setup wizard...\n")
    run_setup_wizard(force=True)
