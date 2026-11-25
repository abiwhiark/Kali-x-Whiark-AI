"""
Kali AI - System Command Executor
===================================
Runs real OS commands (ip a, ipconfig, whoami, ps, netstat, etc.) via
subprocess — just like HexStrike's /api/command endpoint.
No AI hallucination: real output from the real system.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

IS_WINDOWS = platform.system() == "Windows"


@dataclass
class SysCommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    success: bool
    runtime: float
    error: str = ""

    def to_output(self) -> str:
        """Return clean output for the AI to read."""
        out = self.stdout.strip()
        err = self.stderr.strip()
        if out and err:
            return f"{out}\n\n[stderr]\n{err}"
        return out or err or f"(no output, exit code {self.exit_code})"


# ─── Safe allowlist of OS commands that are always permitted ──────────────────
# These reveal system info without touching any external target
SAFE_SYSTEM_COMMANDS: set[str] = {
    "ip", "ipconfig", "ifconfig", "ip addr", "ip a", "ip link",
    "whoami", "id", "hostname", "uname", "uname -a",
    "ps", "ps aux", "top", "htop",
    "netstat", "netstat -an", "netstat -tulpn", "ss", "ss -tulpn",
    "cat /etc/os-release", "lsb_release", "cat /etc/hostname",
    "df", "df -h", "free", "free -h",
    "env", "printenv", "echo",
    "which", "type", "find", "ls", "dir",
    "ping", "traceroute", "tracert", "nslookup", "dig",
    "arp", "arp -a", "route", "route -n", "ip route",
    "systeminfo",   # Windows
    "ipconfig /all",  # Windows
    "getmac",       # Windows
    "net user", "net localgroup",  # Windows
    "cat /etc/passwd", "cat /etc/shadow",
    "kubectl", "docker", "docker ps",
}


def _is_safe_command(cmd: str) -> bool:
    """Check if command starts with an allowed safe binary."""
    first_token = cmd.strip().split()[0].lower() if cmd.strip() else ""
    safe_binaries = {
        "ip", "ipconfig", "ifconfig", "whoami", "id", "hostname",
        "uname", "ps", "netstat", "ss", "cat", "echo", "which",
        "ping", "traceroute", "tracert", "nslookup", "dig", "arp",
        "route", "df", "free", "env", "printenv", "ls", "dir",
        "find", "getmac", "net", "systeminfo", "kubectl", "docker",
        "lsb_release", "head", "tail", "grep", "wc", "top",
    }
    return first_token in safe_binaries


async def run_system_command(
    command: str,
    timeout: int = 30,
) -> SysCommandResult:
    """
    Execute a real OS command and return its output.
    Used for 'what is my ip', 'show system info', etc.
    """
    start = time.monotonic()
    try:
        # Use shell=True for natural command strings (ip a, ipconfig /all, etc.)
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            stdout = stdout_b.decode("utf-8", errors="replace").strip()
            stderr = stderr_b.decode("utf-8", errors="replace").strip()
            code = proc.returncode or 0
            return SysCommandResult(
                command=command, stdout=stdout, stderr=stderr,
                exit_code=code, success=(code == 0),
                runtime=round(time.monotonic() - start, 2),
            )
        except asyncio.TimeoutError:
            proc.kill()
            return SysCommandResult(
                command=command, stdout="", stderr="",
                exit_code=-1, success=False,
                runtime=round(time.monotonic() - start, 2),
                error=f"Command timed out after {timeout}s",
            )
    except Exception as e:
        return SysCommandResult(
            command=command, stdout="", stderr="",
            exit_code=-1, success=False,
            runtime=round(time.monotonic() - start, 2),
            error=str(e),
        )


# ─── Smart OS Query Router ────────────────────────────────────────────────────

def get_ip_command() -> str:
    """Return the right 'get IP' command for this OS."""
    if IS_WINDOWS:
        return "ipconfig"
    if shutil.which("ip"):
        return "ip a"
    return "ifconfig"


def get_whoami_command() -> str:
    if IS_WINDOWS:
        return "whoami /all"
    return "id && whoami"


def get_netstat_command() -> str:
    if IS_WINDOWS:
        return "netstat -an"
    if shutil.which("ss"):
        return "ss -tulpn"
    return "netstat -tulpn"


def get_process_list_command() -> str:
    if IS_WINDOWS:
        return "tasklist"
    return "ps aux"


def get_sysinfo_command() -> str:
    if IS_WINDOWS:
        return "systeminfo"
    return "uname -a && cat /etc/os-release 2>/dev/null || lsb_release -a 2>/dev/null"


# ─── Keyword → Command mapper (for the orchestrator to use) ──────────────────

SYSTEM_QUERY_PATTERNS: list[tuple[list[str], str]] = [
    # IP address queries
    (
        ["what is my ip", "my ip address", "show ip", "ip address", "ipconfig",
         "ip a", "ifconfig", "my local ip", "network ip", "what's my ip",
         "find my ip", "get my ip", "ip addr", "ip info", "network info",
         "show me my ip", "tell me my ip", "give me my ip", "check my ip",
         "current ip", "display ip", "my network ip", "show my ip"],
        get_ip_command(),
    ),
    # Who am I
    (
        ["whoami", "who am i", "current user", "my username", "logged in user",
         "what user", "my user", "who is logged", "current username",
         "what is my username", "my account"],
        get_whoami_command(),
    ),
    # Hostname
    (
        ["hostname", "computer name", "machine name", "system name", "host name"],
        "hostname",
    ),
    # OS info
    (
        ["what os", "operating system", "os version", "system info", "system version",
         "uname", "linux version", "windows version", "kali version", "distro"],
        get_sysinfo_command(),
    ),
    # Open ports / network connections
    (
        ["open ports", "listening ports", "netstat", "network connections",
         "what ports", "active connections", "ss -tulpn", "port list"],
        get_netstat_command(),
    ),
    # Processes
    (
        ["running processes", "process list", "what processes", "ps aux",
         "tasklist", "active processes"],
        get_process_list_command(),
    ),
    # Disk
    (
        ["disk space", "storage", "df -h", "free disk", "hard disk", "drive space"],
        "df -h" if not IS_WINDOWS else "wmic logicaldisk get size,freespace,caption",
    ),
    # Memory
    (
        ["memory", "ram", "free -h", "free memory", "how much ram", "memory usage"],
        "free -h" if not IS_WINDOWS else "wmic os get FreePhysicalMemory,TotalVisibleMemorySize",
    ),
    # ARP / local network
    (
        ["arp table", "arp -a", "local hosts", "network hosts", "mac address"],
        "arp -a",
    ),
    # Route / gateway
    (
        ["route", "default gateway", "routing table", "gateway", "ip route"],
        "ip route" if shutil.which("ip") and not IS_WINDOWS else ("route print" if IS_WINDOWS else "route -n"),
    ),
    # DNS
    (
        ["dns", "nslookup", "resolve", "dig", "dns lookup", "name server"],
        "cat /etc/resolv.conf" if not IS_WINDOWS else "ipconfig /all",
    ),
    # Docker
    (
        ["docker ps", "docker containers", "running containers", "docker info"],
        "docker ps" if shutil.which("docker") else "docker not installed",
    ),
]


def detect_system_query(user_input: str) -> str | None:
    """
    If the user is asking about THEIR system (not a target),
    return the OS command to run. Otherwise return None.
    """
    lower = user_input.lower().strip()
    for keywords, command in SYSTEM_QUERY_PATTERNS:
        if any(kw in lower for kw in keywords):
            return command
    return None
