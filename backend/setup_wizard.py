"""
Kali AI - Setup Wizard
========================
Step 1: Asks what model to pick by selecting a number in order.
Step 2: Asks for the API key with masked/encrypted input (hidden on terminal).
Step 3: Automatically updates the .env file.
"""

from __future__ import annotations

import getpass
import os
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

# Terminal colors
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
╔════════════════════════════════════════════════════════════════════════╗
║             ⚡ WHIARK × KALI AI — MODEL SELECTION WIZARD ⚡            ║
╚════════════════════════════════════════════════════════════════════════╝"""))


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
        for k, v in env.items():
            if k not in written_keys:
                lines.append(f"{k}={v}")
        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        lines = [f"{k}={v}" for k, v in env.items()]
        ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── ORDERED MODEL DEFINITIONS (by number) ──────────────────────────
# (number, provider_id, provider_display, model_id, model_display, needs_key, description)
MODELS_CATALOG = [
    (
        "1", "gemini", "Google Gemini", "gemini-1.5-flash",
        "Google Gemini — gemini-1.5-flash", True,
        "RECOMMENDED FREE • Fast • 1500 req/day • Very generous limits"
    ),
    (
        "2", "gemini", "Google Gemini", "gemini-1.5-pro",
        "Google Gemini — gemini-1.5-pro", True,
        "Deep Reasoning • Large context window • Free tier"
    ),
    (
        "3", "gemini", "Google Gemini", "gemini-3.8-flash",
        "Google Gemini — gemini-3.8-flash", True,
        "Latest Google model • Cutting-edge speed & tool calls"
    ),
    (
        "4", "ollama", "Ollama (Local)", "llama3",
        "Ollama Local — llama3", False,
        "100% FREE • Offline • NO rate limits • Runs on your machine"
    ),
    (
        "5", "openai", "OpenAI", "gpt-4o-mini",
        "OpenAI — gpt-4o-mini", True,
        "Fast & smart • Cost-efficient • High rate limits"
    ),
    (
        "6", "openai", "OpenAI", "gpt-4o",
        "OpenAI — gpt-4o", True,
        "Full GPT-4o power • Complex multi-step cyber assessments"
    ),
    (
        "7", "anthropic", "Anthropic", "claude-3-5-haiku-20241022",
        "Anthropic — claude-3-5-haiku", True,
        "Fast • Excellent code & scripting analysis"
    ),
    (
        "8", "anthropic", "Anthropic", "claude-3-5-sonnet-20241022",
        "Anthropic — claude-3-5-sonnet", True,
        "Top-tier reasoning • Industry standard for security tasks"
    ),
    (
        "9", "demo", "Demo Mode", "demo",
        "Demo Mode (Offline Simulation)", False,
        "No API key needed • Offline mock testing"
    ),
]


def _get_encrypted_key(provider_name: str, existing_key: str = "") -> str:
    """Prompt for API key with hidden/encrypted terminal input."""
    print(f"\n  {_c('BOLD', 'Step 2: Enter API Key for')} {_c('CYAN', provider_name)}")
    print(f"  {_c('DIM', '🔐 Keystrokes are hidden/encrypted on screen for security.')}")

    if existing_key and existing_key not in ("your_key_here", ""):
        masked = existing_key[:6] + "••••••••" + existing_key[-4:] if len(existing_key) > 10 else "••••••••"
        print(f"  {_c('YELLOW', 'Current key:')} {masked} {_c('DIM', '(Press Enter to keep, or paste new key)')}")

    key = ""
    try:
        key = getpass.getpass("  API Key: ").strip()
    except Exception:
        # Fallback if getpass is unsupported in certain virtual terminals
        key = input("  API Key: ").strip()

    if not key and existing_key and existing_key != "your_key_here":
        key = existing_key
        print(f"  {_c('GREEN', '✔ Kept existing API key.')}")
    elif key:
        print(f"  {_c('GREEN', '✔ API key received & encrypted.')}")

    return key


def run_setup_wizard(choice: str | None = None, force: bool = False) -> dict[str, str]:
    """
    Run the ordered model & API key setup wizard.
    Step 1: Pick a model by number [1-9]
    Step 2: Enter encrypted API key
    Step 3: Automatically update .env
    """
    env = _read_env()

    # Skip if already configured and not forced
    if not force and not choice:
        has_key = any([
            env.get("GEMINI_API_KEY", "") not in ("", "your_key_here"),
            env.get("OPENAI_API_KEY", ""),
            env.get("ANTHROPIC_API_KEY", ""),
            env.get("ACTIVE_PROVIDER", "").lower() == "ollama",
        ])
        if has_key and env.get("ACTIVE_PROVIDER"):
            return env

    _banner()

    # Step 1: Model Selection by Number
    if not choice:
        print(_c("BOLD", "  Step 1: Pick what model to use by selecting a number:\n"))
        for num, pid, _, _, model_disp, _, desc in MODELS_CATALOG:
            extra = ""
            if pid == "ollama" and _ollama_running():
                extra = _c("GREEN", " [Ollama detected running!]")
            print(f"  {_c('CYAN', f'[{num}]')} {_c('BOLD', model_disp)}{extra}")
            print(f"      {_c('DIM', desc)}")
            print()

        choice = input(f"  Enter number {_c('BOLD', '[1-9]')}: ").strip()

    # Find chosen item
    selected = None
    for item in MODELS_CATALOG:
        if item[0] == choice:
            selected = item
            break

    # Also handle word inputs like 'gemini', 'ollama', etc.
    if not selected:
        choice_lower = (choice or "1").lower().strip()
        for item in MODELS_CATALOG:
            if item[1] in choice_lower or choice_lower in item[3].lower():
                selected = item
                break

    if not selected:
        selected = MODELS_CATALOG[0]  # Default: Gemini 1.5 Flash

    num, pid, provider_disp, model_id, model_disp, needs_key, _ = selected

    print(f"\n  {_c('GREEN', '✔')} Selected: {_c('BOLD', model_disp)}")

    # Update active provider and model in env dict
    env["ACTIVE_PROVIDER"] = pid

    if pid == "gemini":
        env["GEMINI_MODEL"] = model_id
        if needs_key:
            print(f"  {_c('DIM', 'Get your free Gemini key at: https://aistudio.google.com/app/apikey')}")
            key = _get_encrypted_key("Google Gemini", env.get("GEMINI_API_KEY", ""))
            if key:
                env["GEMINI_API_KEY"] = key

    elif pid == "openai":
        env["OPENAI_MODEL"] = model_id
        if needs_key:
            print(f"  {_c('DIM', 'Get your OpenAI key at: https://platform.openai.com/api-keys')}")
            key = _get_encrypted_key("OpenAI", env.get("OPENAI_API_KEY", ""))
            if key:
                env["OPENAI_API_KEY"] = key

    elif pid == "anthropic":
        env["ANTHROPIC_MODEL"] = model_id
        if needs_key:
            print(f"  {_c('DIM', 'Get your Anthropic key at: https://console.anthropic.com')}")
            key = _get_encrypted_key("Anthropic", env.get("ANTHROPIC_API_KEY", ""))
            if key:
                env["ANTHROPIC_API_KEY"] = key

    elif pid == "ollama":
        env["OLLAMA_MODEL"] = model_id
        env["OLLAMA_HOST"] = env.get("OLLAMA_HOST", "http://localhost:11434")
        if not _ollama_running():
            print(f"\n  {_c('YELLOW', '⚠  Note: Ollama is not currently running.')}")
            print(f"     Start it in a terminal: {_c('CYAN', 'ollama serve')}")
            print(f"     Pull the model:         {_c('CYAN', f'ollama pull {model_id}')}")

    elif pid == "demo":
        print(f"  {_c('YELLOW', 'Running in Demo Mode — no API calls, offline simulated responses.')}")

    # Set common settings if missing
    if "ALLOWED_TARGETS" not in env:
        env["ALLOWED_TARGETS"] = "*"
    if "MAX_AGENT_ITERATIONS" not in env:
        env["MAX_AGENT_ITERATIONS"] = "10"
    if "MAX_TOOL_CALLS" not in env:
        env["MAX_TOOL_CALLS"] = "15"
    if "TOOL_EXECUTION_TIMEOUT" not in env:
        env["TOOL_EXECUTION_TIMEOUT"] = "120"

    # Step 3: Automatically update .env file
    _write_env(env)

    # Sync to current runtime process env vars
    for k, v in env.items():
        os.environ[k] = v

    # Reload cached settings
    try:
        from backend.core.config import reload_settings
        reload_settings()
    except Exception:
        pass

    print(f"\n  {_c('GREEN', '✔  Step 3 Complete: .env file automatically updated!')}")
    print(f"  {_c('DIM', f'Config saved to: {ENV_FILE}')}")
    print(f"  {_c('BOLD', f'Active: {provider_disp} ({model_id})')}\n")

    return env


def change_api_key(provider: str = "") -> None:
    """Mid-session key change / model switch with masked input."""
    env = _read_env()
    current_p = provider or env.get("ACTIVE_PROVIDER", "gemini")
    run_setup_wizard(force=True)


def reset_config() -> None:
    """Wipe .env and re-run setup wizard."""
    if ENV_FILE.exists():
        ENV_FILE.unlink()
    example = ROOT / ".env.example"
    if example.exists():
        import shutil
        shutil.copy(example, ENV_FILE)
    print("  Configuration reset. Launching model selection wizard...\n")
    run_setup_wizard(force=True)
