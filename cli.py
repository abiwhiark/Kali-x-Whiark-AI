#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          KALI x WHIARK AI — Terminal CLI Interface           ║
║          Autonomous Cybersecurity Operator & Terminal Agent  ║
║          HexStrike AI & ChainRaptor Hybrid Architecture      ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python cli.py                              # Interactive REPL
    python cli.py -o "nmap scan" -t localhost  # One-shot scan
    python cli.py --no-color                   # Disable colors
"""

from __future__ import annotations

import sys
import os
import json
import asyncio
import argparse
import textwrap
from pathlib import Path

# ─── Add project root to path ────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# Load .env from project root
from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

# ─── Rich Terminal UI ────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


# ─── Config Storage (like ChainRaptor's data/config.json) ────────
CONFIG_DIR  = ROOT / "data"
CONFIG_FILE = CONFIG_DIR / "config.json"

def load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


# ─── ASCII Banner ────────────────────────────────────────────────
BANNER = """\
  ██╗  ██╗ █████╗ ██╗     ██╗    ██╗  ██╗    ██╗    ██╗██╗  ██╗██╗ █████╗ ██████╗ ██╗  ██╗
  ██║ ██╔╝██╔══██╗██║     ██║    ╚██╗██╔╝    ██║    ██║██║  ██║██║██╔══██╗██╔══██╗██║ ██╔╝
  █████╔╝ ███████║██║     ██║     ╚███╔╝     ██║ █╗ ██║███████║██║███████║██████╔╝█████╔╝ 
  ██╔═██╗ ██╔══██║██║     ██║     ██╔██╗     ██║███╗██║██╔══██║██║██╔══██║██╔══██╗██╔═██╗ 
  ██║  ██╗██║  ██║███████╗██║    ██╔╝ ██╗    ╚███╔███╔╝██║  ██║██║██║  ██║██║  ██║██║  ██╗
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚═╝  ╚═╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"""


def print_banner(demo_mode: bool, provider: str = "gemini") -> None:
    if HAS_RICH:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        console.print("[bold red]  ⚡ KALI x WHIARK AI ⚡[/bold red]  [bold white]— Autonomous Cybersecurity Operator[/bold white]")
        console.print("[dim]  Chatbot Engine: [bold cyan]Kali AI[/bold cyan] | HexStrike AI Architecture[/dim]")
        mode_badge = (
            "[bold yellow]  ⚠  DEMO MODE — simulated reasoning and mock security tools[/bold yellow]"
            if demo_mode else
            f"[bold green]  ✓  LIVE — AI Active ({provider.upper()})[/bold green]"
        )
        console.print(mode_badge)
        console.print("[dim]  Chat naturally like ChatGPT/Gemini, or give scan instructions directly.[/dim]")
        console.print("[dim]  Type [bold]help[/bold] for commands, [bold]tools[/bold] to view tool registry, [bold]quit[/bold] to exit.[/dim]")
        console.rule(style="dim")
    else:
        print(BANNER)
        print("  ⚡ KALI x WHIARK AI ⚡ — Autonomous Cybersecurity Operator")
        print("  Chatbot Engine: Kali AI")
        mode = "DEMO MODE" if demo_mode else f"LIVE ({provider.upper()})"
        print(f"  Mode: [{mode}] — HexStrike AI Model")
        print("  Chat naturally or give scan commands directly.")
        print("  Type 'help' for commands, 'quit' to exit.")
        print("─" * 75)
    print()


def rprint(msg: str) -> None:
    """Print with rich markup if available, plain text otherwise."""
    if HAS_RICH:
        console.print(msg)
    else:
        # Strip rich markup tags
        import re
        clean = re.sub(r'\[/?[^\]]*\]', '', msg)
        print(clean)


# ─── Provider Setup (like ChainRaptor) ───────────────────────────
PROVIDERS = {
    "1": ("gemini",    "Google Gemini",   "GEMINI_API_KEY",  "gemini-2.0-flash"),
    "2": ("anthropic", "Anthropic Claude","ANTHROPIC_API_KEY","claude-3-5-sonnet-20241022"),
    "3": ("openai",    "OpenAI GPT",      "OPENAI_API_KEY",  "gpt-4o-mini"),
    "4": ("ollama",    "Local Ollama",    None,              "llama3"),
}

def setup_provider(cfg: dict) -> dict:
    """Interactive provider setup — mirrors ChainRaptor's setup_ai()."""
    rprint("\n[bold red]╔══════════════════════════════════════════════╗[/bold red]")
    rprint("[bold red]║    KALI x WHIARK AI — PROVIDER SETUP         ║[/bold red]")
    rprint("[bold red]╚══════════════════════════════════════════════╝[/bold red]\n")

    rprint("[bold white]Select AI Provider:[/bold white]")
    for key, (pid, name, _, default_model) in PROVIDERS.items():
        rprint(f"  [cyan]{key}[/cyan]. {name}  [dim](default: {default_model})[/dim]")

    choice = input("\nChoice [1]: ").strip() or "1"
    if choice not in PROVIDERS:
        choice = "1"

    pid, name, env_key, default_model = PROVIDERS[choice]

    if pid == "ollama":
        api_key = "ollama"
        rprint("[dim]  Make sure Ollama is running: ollama run llama3[/dim]")
    else:
        # Check env first
        env_val = os.environ.get(env_key, "")
        if env_val and env_val not in ("your_key_here", ""):
            rprint(f"[dim]  Found {env_key} in environment.[/dim]")
            api_key = env_val
        else:
            api_key = input(f"Enter {name} API Key: ").strip()

    model = input(f"Model [{default_model}]: ").strip() or default_model

    cfg["active"]   = pid
    cfg[pid]        = api_key
    cfg[f"{pid}_model"] = model
    save_config(cfg)

    rprint(f"\n[bold green]✓  Configured {name} with model {model}[/bold green]\n")
    return cfg


def get_active_provider(cfg: dict) -> str:
    return cfg.get("active", "gemini")

def get_model_name(cfg: dict) -> str:
    p = get_active_provider(cfg)
    return cfg.get(f"{p}_model", "gemini-2.0-flash")

def initialize_from_env() -> dict:
    """Build config from .env if no saved config exists."""
    cfg = load_config()
    if not cfg:
        # Auto-configure from .env Gemini key
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if gemini_key and gemini_key not in ("", "your_key_here"):
            cfg = {
                "active": "gemini",
                "gemini": gemini_key,
                "gemini_model": os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
            }
    return cfg


# ─── Severity & Event Styling ─────────────────────────────────────
SEV_STYLES = {
    "CRITICAL":      "bold white on red",
    "HIGH":          "bold red",
    "MEDIUM":        "bold yellow",
    "LOW":           "bold cyan",
    "INFORMATIONAL": "dim",
}

EVENT_ICONS = {
    "assessment_start":  "🚀",
    "thinking":          "🤔",
    "plan":              "📋",
    "tool_start":        "🔧",
    "tool_result":       "✅",
    "finding":           "🔍",
    "validation_failed": "🚫",
    "complete":          "🏁",
    "assessment_end":    "📊",
    "error":             "❌",
}


def render_event(event_type: str, data: dict) -> None:
    """Render an agent event using Rich panels and styled output."""
    icon = EVENT_ICONS.get(event_type, "•")

    if event_type == "assessment_start":
        rprint("")
        if HAS_RICH:
            console.rule("[bold cyan]ASSESSMENT STARTED[/bold cyan]", style="cyan")
        rprint(f"  {icon}  [bold]Target:[/bold] [cyan]{data.get('target','?')}[/cyan]")
        rprint(f"      [dim]Objective:[/dim] {data.get('objective','?')}")
        rprint("")

    elif event_type == "thinking":
        step = data.get("step", "?")
        msg  = data.get("message", "Analyzing...")
        if HAS_RICH:
            console.print(f"  {icon}  [dim][Step {step}] {msg}[/dim]", end="\r")
        else:
            print(f"  {icon}  [Step {step}] {msg}", end="\r")

    elif event_type == "plan":
        rprint("")
        if HAS_RICH:
            console.rule("[bold magenta]AI ASSESSMENT PLAN[/bold magenta]", style="magenta")
            plan_text = data.get("plan", "")
            console.print(Markdown(plan_text))
        else:
            print("─── AI ASSESSMENT PLAN ───")
            for line in data.get("plan","").splitlines():
                print(f"  {line.strip()}")
        rprint("")

    elif event_type == "tool_start":
        tool_id = data.get("tool_id", "?")
        step    = data.get("step", "?")
        reason  = (data.get("ai_reasoning") or "").strip()
        rprint("")
        rprint(f"  {icon}  [dim][Step {step}] Running:[/dim] [bold yellow]{tool_id}[/bold yellow]")
        if reason:
            wrapped = textwrap.fill(reason, width=62, initial_indent="      ", subsequent_indent="      ")
            rprint(f"[dim]{wrapped}[/dim]")

    elif event_type == "tool_result":
        tool_id  = data.get("tool_id", "?")
        success  = data.get("success", False)
        ex_time  = data.get("execution_time", 0)
        findings = data.get("findings_extracted", 0)
        status   = "[bold green]SUCCESS[/bold green]" if success else "[bold red]FAILED[/bold red]"
        rprint(f"  ✅  [cyan]{tool_id}[/cyan] → {status} [dim]({ex_time}s)[/dim] | [yellow]{findings}[/yellow] findings")

    elif event_type == "finding":
        new_count   = data.get("new_count", 0)
        total_count = data.get("total_count", 0)
        findings    = data.get("findings", [])
        rprint("")
        if HAS_RICH:
            console.rule(f"[bold yellow]FINDINGS (+{new_count} new, {total_count} total)[/bold yellow]", style="yellow")
        else:
            print(f"─── FINDINGS (+{new_count} new, {total_count} total) ───")

        new_findings = findings[-new_count:] if new_count > 0 else findings
        for f in new_findings:
            sev   = f.get("severity", "informational").upper()
            title = f.get("title", "Unknown")
            asset = f.get("affected_asset", "")
            style = SEV_STYLES.get(sev, "white")
            if HAS_RICH:
                sev_text = Text(f" {sev:>13} ", style=style)
                line     = Text("  ")
                line.append_text(sev_text)
                line.append(f"  {title}")
                console.print(line)
                if asset:
                    console.print(f"[dim]              Asset: {asset}[/dim]")
            else:
                print(f"  [{sev:>13}]  {title}")
                if asset:
                    print(f"               Asset: {asset}")
        rprint("")

    elif event_type == "validation_failed":
        tool_id = data.get("tool_id","?")
        errors  = data.get("errors",[])
        target  = data.get("target","?")
        rprint("")
        rprint(f"  {icon}  [bold red]BLOCKED:[/bold red] [yellow]{tool_id}[/yellow] on [cyan]{target}[/cyan]")
        for err in errors:
            rprint(f"      [red]↳ {err}[/red]")
        rprint("")

    elif event_type == "complete":
        report         = data.get("report","")
        total_tools    = data.get("total_tool_calls",0)
        total_findings = data.get("total_findings",0)
        steps          = data.get("step",0)
        rprint("")
        if HAS_RICH:
            console.rule("[bold green]ASSESSMENT COMPLETE[/bold green]", style="green")
        else:
            print("─── ASSESSMENT COMPLETE ───")
        rprint(f"  {icon}  Steps: [cyan]{steps}[/cyan]  |  Tools: [cyan]{total_tools}[/cyan]  |  Findings: [bold yellow]{total_findings}[/bold yellow]")
        rprint("")
        if report:
            _render_report(report)

    elif event_type == "assessment_end":
        status = data.get("status","")
        style  = "green" if "complete" in status.lower() else "red"
        if HAS_RICH:
            console.rule(style=style)
        rprint(f"  📊  Assessment ended — Status: [{style}]{status.upper()}[/{style}]")
        rprint("")

    elif event_type == "error":
        err = data.get("error","Unknown error")
        rprint("")
        if HAS_RICH:
            console.rule(style="red")
            console.print(Panel(f"[bold white]{err}[/bold white]", title="[bold red]❌ ERROR[/bold red]", border_style="red"))
        else:
            print(f"  ❌  ERROR: {err}")
        rprint("")


def _render_report(report: str) -> None:
    """Render markdown report with Rich or plain fallback."""
    if HAS_RICH:
        console.print(Markdown(report))
    else:
        for line in report.splitlines():
            stripped = line.strip()
            if stripped.startswith("# "):
                print(stripped)
            elif stripped.startswith("## "):
                print(f"\n{stripped}")
            elif stripped.startswith("### "):
                print(stripped)
            elif stripped:
                wrapped = textwrap.fill(stripped, width=70, initial_indent="  ", subsequent_indent="  ")
                print(wrapped)
            else:
                print()


# ─── Tool Table ───────────────────────────────────────────────────
def print_tools(registry) -> None:
    if HAS_RICH:
        console.rule("[bold cyan]REGISTERED SECURITY TOOLS[/bold cyan]", style="cyan")
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
                      border_style="dim")
        table.add_column("Tool ID",     style="cyan bold", no_wrap=True)
        table.add_column("Name",        style="white")
        table.add_column("Category",    style="dim")
        table.add_column("Status",      justify="center")
        table.add_column("Risk",        justify="center")
        for d in registry.get_all_definitions():
            risk_map = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}
            risk_style = risk_map.get(d.risk_level.value, "white")
            stat_style = "green" if "active" in d.status.value else "yellow"
            table.add_row(
                d.id,
                d.name,
                d.category.value if hasattr(d.category, "value") else str(d.category),
                f"[{stat_style}]{d.status.value.upper()}[/{stat_style}]",
                f"[{risk_style}]{d.risk_level.value.upper()}[/{risk_style}]",
            )
        console.print(table)
    else:
        print("─── TOOLS ───")
        for d in registry.get_all_definitions():
            print(f"  {d.id:<30} [{d.status.value.upper()}]  Risk: {d.risk_level.value.upper()}")
            print(f"      {d.description[:70]}")
    rprint("")


# ─── Help ────────────────────────────────────────────────────────
def print_help() -> None:
    if HAS_RICH:
        console.rule("[bold cyan]KALI AI TERMINAL — HEXSTRIKE MODEL[/bold cyan]", style="cyan")
        table = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        table.add_column("cmd",  style="cyan bold", no_wrap=True)
        table.add_column("desc", style="white")
        cmds = [
            ("help / ?",         "Show this help manual"),
            ("tools",            "List registered security tools and their execution status"),
            ("target <host>",    "Set a persistent scan target (e.g. target 127.0.0.1)"),
            ("target",           "View current active target"),
            ("clear / cls",      "Clear terminal screen and conversation history"),
            ("reset",            "Clear configuration and re-run setup"),
            ("quit / exit",      "Exit Kali AI"),
            ("",                 ""),
            ("— Conversational Chat (Like ChatGPT / Gemini) —", ""),
            ("what is sql injection?", "Ask any cybersecurity question or concept"),
            ("how do I exploit CVE-2021-41773?", "Technical vulnerability & exploitation guidance"),
            ("write a python script to scan ports", "Code generation & scripting"),
            ("explain why port 80 was open", "Follow-up questions remembering previous context"),
            ("",                 ""),
            ("— Autonomous Security Scans (HexStrike AI Execution) —", ""),
            ("scan localhost",   "Autonomous security assessment"),
            ("nmap scan",        "Direct Nmap port & service discovery"),
            ("identify tech stack on localhost", "WhatWeb technology profiling"),
            ("scan for vulnerabilities on localhost", "Nuclei template-driven CVE scanner"),
            ("check ssl on mysite.com", "SSLyze TLS/SSL cryptographic audit"),
            ("find hidden directories", "Gobuster wordlist directory enumeration"),
            ("/scan <target>",   "Force scan mode explicitly"),
            ("/chat <message>",  "Force conversational chat mode explicitly"),
        ]
        for cmd, desc in cmds:
            if cmd == "":
                continue
            elif cmd.startswith("—"):
                table.add_row(f"[bold magenta]{cmd}[/bold magenta]", f"[dim]{desc}[/dim]")
            else:
                table.add_row(cmd, desc)
        console.print(table)
    else:
        print("─── KALI AI TERMINAL (HEXSTRIKE MODEL) ───")
        print("  help              Show this help")
        print("  tools             List registered tools")
        print("  target <host>     Set target host")
        print("  clear             Clear screen and memory")
        print("  quit / exit       Quit")
        print()
        print("  Conversational Chat:")
        print("    what is sql injection?")
        print("    write a python port scanner")
        print("  Security Scans:")
        print("    scan localhost")
        print("    nmap scan")
        print("    check ssl on mysite.com")
    rprint("")


def is_scan_request(text: str, has_target: bool = False) -> bool:
    """
    Determine whether the user intent is an active security scan or a conversational chat.
    HexStrike AI model: conversational questions go to AI chat, scan requests trigger tool pipelines.
    """
    t = text.strip().lower()

    if t.startswith(("/scan", "scan ", "scan:")):
        return True
    if t.startswith(("/chat", "chat ", "ask ")):
        return False

    # Conversational question starters
    question_starters = (
        "what is", "what are", "what does", "how does", "how to", "how do", "how can",
        "why does", "why is", "why do", "explain", "describe", "tell me about",
        "can you", "could you", "help me", "write a", "create a", "generate a",
        "who are you", "what can you do", "difference between", "compare",
        "hi", "hello", "hey",
    )
    if any(t.startswith(q) for q in question_starters) or t == "test" or t.startswith("test "):
        return False

    scan_verbs = [
        "scan", "nmap", "whatweb", "nuclei", "nikto", "sslyze", "zap", "gobuster",
        "port scan", "vulnerability scan", "security assessment", "audit", "recon",
        "enumerate", "penetration test", "pentest"
    ]
    has_scan_kw = any(kw in t for kw in scan_verbs)

    # Check for target indicators (subdomains, IPs, URLs, or 'on <target>')
    import re
    has_target_in_text = bool(
        re.search(r"https?://", t) or
        re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t) or
        re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", t) or
        "localhost" in t or "127.0.0.1" in t or
        re.search(r"\b(?:on|against|target)\s+[a-zA-Z0-9_.-]+", t)
    )

    if has_scan_kw and (has_target_in_text or has_target or t.startswith(("nmap", "scan", "whatweb", "nuclei", "port scan"))):
        return True

    return False


async def run_chat(orchestrator, message: str, history: list[dict[str, str]]) -> None:
    """Run conversational chat turn with Markdown rendering and memory."""
    clean_msg = message
    if clean_msg.lower().startswith("/chat "):
        clean_msg = clean_msg[6:].strip()

    rprint("")
    if HAS_RICH:
        with console.status("[bold cyan]Kali AI is thinking...[/bold cyan]", spinner="dots"):
            reply = await orchestrator.chat(clean_msg, history=history)
        console.rule("[bold cyan]KALI AI[/bold cyan]", style="cyan")
        console.print(Markdown(reply))
        console.rule(style="dim")
    else:
        print("\nKali AI:")
        reply = await orchestrator.chat(clean_msg, history=history)
        print(reply)
        print("─" * 60)

    history.append({"role": "user", "content": clean_msg})
    history.append({"role": "assistant", "content": reply})


# ─── Core Runner ─────────────────────────────────────────────────
async def run_assessment(orchestrator, objective: str, target: str | None, history: list[dict[str, str]] | None = None) -> None:
    """Stream agent events and display them."""
    clean_obj = objective
    if clean_obj.lower().startswith("/scan "):
        clean_obj = clean_obj[6:].strip()

    try:
        last_report = ""
        async for event in orchestrator.run_assessment(objective=clean_obj, target=target):
            render_event(event.event_type, event.data)
            if event.event_type == "complete" and event.data.get("report"):
                last_report = event.data.get("report")

        if history is not None and last_report:
            history.append({"role": "user", "content": f"Security scan objective: {clean_obj} against {target or 'target'}"})
            history.append({"role": "assistant", "content": f"Scan completed. Key summary:\n{last_report[:600]}..."})

    except KeyboardInterrupt:
        rprint("")
        rprint("[bold yellow]  ⚠  Assessment interrupted by user.[/bold yellow]")
        rprint("")


# ─── Interactive REPL ────────────────────────────────────────────
async def interactive_loop(orchestrator, cfg: dict) -> None:
    """Main interactive REPL — HexStrike AI model (conversational chat + automated tool execution)."""
    persistent_target: str | None = None
    provider = get_active_provider(cfg)
    model    = get_model_name(cfg)
    chat_history: list[dict[str, str]] = []

    print_banner(orchestrator.is_demo_mode, provider)

    while True:
        target_hint = f" ({persistent_target})" if persistent_target else ""
        try:
            if HAS_RICH:
                prompt_str = f"\n[bold red]KaliAI{target_hint}[/bold red][bold white] ❯ [/bold white]"
                console.print(prompt_str, end="")
                user_input = input().strip()
            else:
                user_input = input(f"\nKaliAI{target_hint} ❯ ").strip()
        except (KeyboardInterrupt, EOFError):
            rprint("\n[cyan]  Goodbye! Stay ethical. 👋[/cyan]\n")
            break

        if not user_input:
            continue

        lower = user_input.lower()

        # ── Built-in Commands ────────────────────────────────
        if lower in ("quit", "exit", "q"):
            rprint("[cyan]\n  Goodbye! Stay ethical. 👋\n[/cyan]")
            break

        elif lower in ("help", "h", "?"):
            print_help()

        elif lower in ("tools", "list tools", "capabilities"):
            print_tools(orchestrator.tool_registry)

        elif lower in ("clear", "cls"):
            os.system("cls" if sys.platform == "win32" else "clear")
            chat_history.clear()
            print_banner(orchestrator.is_demo_mode, get_active_provider(cfg))

        elif lower.startswith("target "):
            new_target = user_input[7:].strip()
            if new_target:
                persistent_target = new_target
                orchestrator.authorize_target(persistent_target)
                if persistent_target in ("*", "all", "any"):
                    rprint(f"  [green]✔[/green]  [bold yellow]HexStrike Mode Enabled:[/bold yellow] Any target is now authorized for scanning!")
                else:
                    rprint(f"  [green]✔[/green]  Target set to: [cyan bold]{persistent_target}[/cyan bold] (Authorized for scanning)")
            else:
                rprint("[red]  Usage: target <hostname, IP, URL, or * for all>[/red]")

        elif lower == "target":
            if persistent_target:
                rprint(f"  Current target: [cyan bold]{persistent_target}[/cyan bold]")
            else:
                rprint("[dim]  No target set. Use: target <hostname or IP>[/dim]")

        elif lower == "provider":
            cfg = setup_provider(cfg)
            rprint(f"[green]  ✔  Switched to {get_active_provider(cfg)} / {get_model_name(cfg)}[/green]")
            rprint("[dim]  Restart cli.py for the new provider to take full effect.[/dim]")

        elif lower.startswith("/model "):
            new_model = user_input[7:].strip()
            p = get_active_provider(cfg)
            cfg[f"{p}_model"] = new_model
            save_config(cfg)
            rprint(f"[green]  ✔  Model changed to: {new_model}[/green]")
            rprint("[dim]  Restart cli.py for the model change to take effect.[/dim]")

        elif lower == "/models":
            rprint(f"[bold cyan]  Current provider:[/bold cyan] {get_active_provider(cfg)}")
            rprint(f"[bold cyan]  Current model:[/bold cyan] {get_model_name(cfg)}")
            rprint("[dim]  Use [bold]/model <name>[/bold] to switch.[/dim]")

        elif lower == "reset":
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
            cfg = {}
            chat_history.clear()
            rprint("[bold red]  Config and session history cleared. Reconfiguring...[/bold red]")
            cfg = setup_provider(cfg)

        # ── Autonomous Scan Mode vs Conversational Chat Mode ──
        elif is_scan_request(user_input, has_target=bool(persistent_target)):
            if HAS_RICH:
                with console.status("[bold cyan]  Engaging security tool pipeline...[/bold cyan]", spinner="dots"):
                    await asyncio.sleep(0.3)
            await run_assessment(orchestrator, objective=user_input, target=persistent_target, history=chat_history)

        else:
            # Conversational Chat like ChatGPT / Gemini / HexStrike AI
            await run_chat(orchestrator, message=user_input, history=chat_history)


# ─── Entry Point ─────────────────────────────────────────────────
async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kali x Whiark AI — Autonomous Cybersecurity Terminal Operator (Chatbot: Kali AI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python cli.py                                    # Interactive REPL
              python cli.py -o "nmap scan" -t localhost        # One-shot scan
              python cli.py -o "what is sql injection"         # One-shot chat
              python cli.py -o "full assessment" -t 192.168.1.1
              python cli.py --no-color
        """)
    )
    parser.add_argument("-o", "--objective", type=str, help="One-shot objective")
    parser.add_argument("-t", "--target",    type=str, help="Scan target (IP, hostname, URL)")
    parser.add_argument("--no-color",        action="store_true", help="Disable Rich styling")
    parser.add_argument("--setup",           action="store_true", help="Force provider setup")
    args = parser.parse_args()

    global HAS_RICH
    if args.no_color:
        HAS_RICH = False

    # Load / initialize config
    cfg = initialize_from_env()

    # Force setup if requested or no config
    if args.setup or not cfg:
        cfg = setup_provider(cfg)

    # Import backend
    try:
        from backend.services.agent.orchestrator import AgentOrchestrator
    except ImportError as e:
        rprint(f"[bold red][ERROR] Failed to import backend: {e}[/bold red]")
        rprint("[dim]Make sure you're running from the project root directory.[/dim]")
        sys.exit(1)

    orchestrator = AgentOrchestrator()
    provider = get_active_provider(cfg)

    # One-shot mode
    if args.objective:
        print_banner(orchestrator.is_demo_mode, provider)
        if is_scan_request(args.objective, has_target=bool(args.target)):
            await run_assessment(orchestrator, objective=args.objective, target=args.target)
        else:
            await run_chat(orchestrator, message=args.objective, history=[])
    else:
        await interactive_loop(orchestrator, cfg)


if __name__ == "__main__":
    asyncio.run(main())
