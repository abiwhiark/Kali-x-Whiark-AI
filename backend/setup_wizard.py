"""
Kali AI - Streamlined Setup Wizard
====================================
Simple, zero-friction setup:
Prompts for Google Gemini API key (hidden/encrypted),
automatically writes to .env, and launches!
"""

from __future__ import annotations

import getpass
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

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
╔══════════════════════════════════════════════════════════════╗
║              ⚡ WHIARK × KALI AI — SETUP ⚡                  ║
╚══════════════════════════════════════════════════════════════╝"""))


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


def run_setup_wizard(force: bool = False, **kwargs) -> dict[str, str]:
    """
    Streamlined setup wizard:
    Supports Google Gemini (cloud) or Local Ollama (offline cybersecurity model).
    Saves configuration to .env and reloads settings live.
    """
    env = _read_env()

    # Skip if already configured and not forced
    existing_active = env.get("ACTIVE_PROVIDER", "")
    existing_key = env.get("GEMINI_API_KEY", "")
    if not force:
        if existing_active == "ollama":
            return env
        if existing_key and existing_key != "your_key_here":
            return env

    _banner()
    print(f"\n  {_c('BOLD', 'Choose AI Provider:')}")
    print(f"    {_c('CYAN', '1')}. Google Gemini        {_c('DIM', '(Cloud — requires free API key)')}")
    print(f"    {_c('CYAN', '2')}. Local Ollama         {_c('DIM', '(Offline on Kali — no rate limits)')}")
    print(f"    {_c('DIM', '(Press Enter for Gemini)')}\n")

    choice = input("  Provider [1]: ").strip().lower() or "1"

    if choice in ("2", "ollama", "local"):
        default_ollama = env.get("OLLAMA_MODEL", "kali-cyber")
        print(f"\n  {_c('DIM', 'Recommended models: kali-cyber, qwen2.5:7b, kali-cyber-pro, deephat')}")
        ollama_model = input(f"  Ollama Model [{default_ollama}]: ").strip() or default_ollama
        ollama_host = env.get("OLLAMA_HOST", "http://localhost:11434")

        env["ACTIVE_PROVIDER"] = "ollama"
        env["OLLAMA_MODEL"] = ollama_model
        env["OLLAMA_HOST"] = ollama_host
        print(f"\n  {_c('GREEN', f'✔ Configured Local Ollama ({ollama_model} @ {ollama_host})!')}")
        print(f"  {_c('DIM', 'Make sure Ollama is running: ollama serve')}")
    else:
        print(f"\n  {_c('BOLD', 'Enter your Google Gemini API Key:')}")
        print(f"  {_c('DIM', 'Get your free key at: https://aistudio.google.com/app/apikey')}")
        print(f"  {_c('DIM', '🔐 Keystrokes are hidden/encrypted for security.')}")
        print(f"  {_c('DIM', '(Or press Enter to start in offline Demo Mode)')}\n")

        if existing_key and existing_key != "your_key_here":
            masked = existing_key[:6] + "••••••••" + existing_key[-4:] if len(existing_key) > 10 else "••••••••"
            print(f"  {_c('YELLOW', 'Current key:')} {masked} {_c('DIM', '(Press Enter to keep, or paste new key)')}")

        key = ""
        try:
            key = getpass.getpass("  Gemini API Key: ").strip()
        except Exception:
            key = input("  Gemini API Key: ").strip()

        if not key and existing_key and existing_key != "your_key_here":
            key = existing_key

        if key:
            env["ACTIVE_PROVIDER"] = "gemini"
            env["GEMINI_API_KEY"] = key
            env["GEMINI_MODEL"] = "gemini-2.5-flash"
            print(f"\n  {_c('GREEN', '✔ API key saved & encrypted!')}")
            print(f"  {_c('GREEN', '✔ Configured Google Gemini (gemini-2.5-flash)')}")
        else:
            env["ACTIVE_PROVIDER"] = "demo"
            env["GEMINI_API_KEY"] = ""
            env["GEMINI_MODEL"] = "gemini-2.5-flash"
            print(f"\n  {_c('YELLOW', '⚠ No key entered — running in Demo Mode (simulated responses).')}")
            print(f"  {_c('DIM', 'You can configure Gemini or Ollama anytime by typing: provider')}")

    # Set common pentest limits
    if "ALLOWED_TARGETS" not in env:
        env["ALLOWED_TARGETS"] = "*"
    if "MAX_AGENT_ITERATIONS" not in env:
        env["MAX_AGENT_ITERATIONS"] = "10"
    if "MAX_TOOL_CALLS" not in env:
        env["MAX_TOOL_CALLS"] = "15"
    if "TOOL_EXECUTION_TIMEOUT" not in env:
        env["TOOL_EXECUTION_TIMEOUT"] = "120"

    # Automatically save to .env
    _write_env(env)

    # Sync to current runtime process
    for k, v in env.items():
        os.environ[k] = v

    # Live reload settings
    try:
        from backend.core.config import reload_settings
        reload_settings()
    except Exception:
        pass

    print(f"  {_c('GREEN', '✔ Updated .env file automatically!')}\n")
    return env


def change_api_key(provider: str = "") -> None:
    """Mid-session key update."""
    run_setup_wizard(force=True)


def reset_config() -> None:
    """Reset config and re-run setup."""
    if ENV_FILE.exists():
        ENV_FILE.unlink()
    example = ROOT / ".env.example"
    if example.exists():
        import shutil
        shutil.copy(example, ENV_FILE)
    print("  Configuration reset. Re-entering setup...\n")
    run_setup_wizard(force=True)
