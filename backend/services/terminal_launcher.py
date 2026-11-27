"""
Kali AI - Terminal Launcher
============================
Opens REAL visible terminal windows on behalf of Kali AI.
Supports: xterm, gnome-terminal, xfce4-terminal, konsole, tmux

The AI can:
  - Open a new terminal window running any Kali tool
  - Keep the window open so the user can watch/interact
  - Optionally capture output to a log file for the report
  - Open multiple terminals simultaneously
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Log directory for terminal output captures
LOG_DIR = Path(tempfile.gettempdir()) / "kali_ai_terminals"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ── Terminal emulator preference order ──────────────────────────────
TERMINAL_EMULATORS = [
    "xterm",
    "gnome-terminal",
    "xfce4-terminal",
    "konsole",
    "tilix",
    "mate-terminal",
    "lxterminal",
]


def _find_terminal() -> str | None:
    """Return the first available terminal emulator on this system."""
    for t in TERMINAL_EMULATORS:
        if shutil.which(t):
            return t
    return None


def _build_terminal_command(
    terminal: str,
    title: str,
    command: str,
    log_file: str,
) -> list[str]:
    """
    Build the shell command to open a terminal emulator running `command`.
    The command is wrapped with `script` or `tee` to capture output.
    """
    # Wrap command to tee output to log file and keep window open after finish
    wrapped = (
        f"bash -c '{command} 2>&1 | tee {log_file}; "
        f"echo; echo \"--- Kali AI: Command finished. Press Enter to close ---\"; "
        f"read'"
    )

    if terminal == "xterm":
        return ["xterm", "-title", title, "-fa", "Monospace", "-fs", "11",
                "-bg", "black", "-fg", "lime", "-e", wrapped]

    elif terminal == "gnome-terminal":
        return ["gnome-terminal", f"--title={title}", "--", "bash", "-c",
                f"{command} 2>&1 | tee {log_file}; echo; "
                f"echo '--- Finished. Close window to continue ---'; read"]

    elif terminal == "xfce4-terminal":
        return ["xfce4-terminal", f"--title={title}", "--command", wrapped]

    elif terminal == "konsole":
        return ["konsole", "--title", title, "-e", wrapped]

    elif terminal in ("tilix", "mate-terminal", "lxterminal"):
        return [terminal, "--title", title, "-e", wrapped]

    else:
        return [terminal, "-e", wrapped]


@dataclass
class TerminalSession:
    """Represents an opened terminal window."""
    session_id: str
    title: str
    command: str
    terminal: str
    log_file: str
    pid: int = -1
    opened_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    output: str = ""

    def read_output(self) -> str:
        """Read captured output from the log file."""
        try:
            return Path(self.log_file).read_text(errors="replace")
        except Exception:
            return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "title": self.title,
            "command": self.command,
            "terminal": self.terminal,
            "log_file": self.log_file,
            "pid": self.pid,
            "opened_at": self.opened_at,
        }


# Active terminal sessions registry
_sessions: dict[str, TerminalSession] = {}


def open_terminal(
    command: str,
    title: str = "Kali AI — Tool",
    wait_for_output: bool = False,
    wait_seconds: float = 5.0,
) -> TerminalSession | str:
    """
    Open a new terminal window running `command`.

    Parameters
    ----------
    command       : shell command to run (e.g. "nmap -sV example.com")
    title         : window title
    wait_for_output : if True, wait `wait_seconds` then read the log
    wait_seconds  : seconds to wait before reading output

    Returns a TerminalSession or an error string.
    """
    terminal = _find_terminal()
    if terminal is None:
        return (
            "No terminal emulator found. Install one with:\n"
            "  sudo apt install xterm\n"
            "  or: sudo apt install gnome-terminal"
        )

    # Create a unique log file for this session
    session_id = f"term_{int(time.time() * 1000)}"
    log_file = str(LOG_DIR / f"{session_id}.log")
    Path(log_file).touch()

    cmd = _build_terminal_command(terminal, title, command, log_file)

    logger.info("[TerminalLauncher] Opening %s: %s", terminal, " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,     # detach from parent process
        )
        session = TerminalSession(
            session_id=session_id,
            title=title,
            command=command,
            terminal=terminal,
            log_file=log_file,
            pid=proc.pid,
        )
        _sessions[session_id] = session

        if wait_for_output:
            time.sleep(wait_seconds)
            session.output = session.read_output()

        logger.info("[TerminalLauncher] Opened session %s (pid=%d)", session_id, proc.pid)
        return session

    except Exception as exc:
        logger.error("[TerminalLauncher] Failed to open terminal: %s", exc)
        return f"Failed to open terminal: {exc}"


def open_tool_terminal(tool: str, args: str = "", target: str = "") -> TerminalSession | str:
    """
    Convenience wrapper — opens a terminal for a specific Kali tool.
    Builds the command automatically.
    """
    tool_commands = {
        "nmap":       f"nmap -sV -sC --open {target}",
        "nikto":      f"nikto -h {target}",
        "gobuster":   f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
        "sqlmap":     f"sqlmap -u '{target}' --batch --level=2",
        "hydra":      f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4",
        "msfconsole": "msfconsole",
        "john":       f"john {args or target}",
        "hashcat":    f"hashcat -m 0 {args or target} /usr/share/wordlists/rockyou.txt --force",
        "aircrack-ng":f"aircrack-ng {args or target}",
        "wpscan":     f"wpscan --url {target} --enumerate p,u",
        "enum4linux": f"enum4linux -a {target}",
        "masscan":    f"masscan {target} -p1-65535 --rate=1000",
        "subfinder":  f"subfinder -d {target}",
        "amass":      f"amass enum -d {target}",
        "whatweb":    f"whatweb -a 3 {target}",
        "dirb":       f"dirb {target} /usr/share/wordlists/dirb/common.txt",
        "nuclei":     f"nuclei -u {target} -t cves/",
        "sslyze":     f"sslyze --regular {target}",
    }

    if tool in tool_commands:
        command = tool_commands[tool]
        if args and args not in command:
            command += f" {args}"
    else:
        command = f"{tool} {args} {target}".strip()

    title = f"Kali AI — {tool.upper()} → {target or args}"
    return open_terminal(command, title=title)


def open_metasploit_terminal() -> TerminalSession | str:
    """Open an interactive Metasploit console in a new terminal."""
    return open_terminal(
        command="msfconsole -q",
        title="Kali AI — Metasploit Framework",
    )


def get_session_output(session_id: str) -> str:
    """Read output from a previously opened terminal session."""
    session = _sessions.get(session_id)
    if not session:
        return f"Session '{session_id}' not found."
    return session.read_output()


def list_sessions() -> list[dict[str, Any]]:
    """List all opened terminal sessions this run."""
    return [s.to_dict() for s in _sessions.values()]
