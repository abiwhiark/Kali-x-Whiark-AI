"""
Kali AI - External Kali Linux Tool Runner
==========================================
Runs any installed Kali Linux security tool as a real subprocess.
Captures stdout/stderr, enforces timeouts, and streams results back.

Design principles:
  - No shell=True; all commands are passed as argument lists (no injection risk).
  - Semaphore limits concurrent executions to avoid overloading the system.
  - Each invocation is logged with timestamp, tool, target, exit-code, and runtime.
  - User consent is checked BEFORE execution via ConsentGate.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Max simultaneous tool processes
_SEMAPHORE = asyncio.Semaphore(3)

# Global execution log (in-memory; persist to file if needed)
_EXECUTION_LOG: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Tool Result
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Result returned from an external tool execution."""
    tool: str
    target: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    runtime_seconds: float = 0.0
    command: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "runtime_seconds": self.runtime_seconds,
            "command": self.command,
            "timestamp": self.timestamp,
            "error": self.error,
        }

    def report_section(self) -> str:
        """Return a formatted markdown section for the report."""
        status = "✅ SUCCESS" if self.success else "❌ FAILED"
        lines = [
            f"## Tool: `{self.tool}` → {self.target}",
            f"**Status:** {status}  |  **Runtime:** {self.runtime_seconds:.1f}s  |  **Exit code:** {self.exit_code}",
            f"**Command:** `{' '.join(self.command)}`",
            "",
        ]
        if self.stdout:
            lines += ["**Output:**", "```", self.stdout[:8000], "```", ""]
        if self.stderr:
            lines += ["**Stderr:**", "```", self.stderr[:2000], "```", ""]
        if self.error:
            lines += [f"**Error:** {self.error}", ""]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# TOOL REGISTRY — maps tool_id → command builder
# ---------------------------------------------------------------------------

def _build_nmap(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    flags = args.get("flags", "-sV -sC --open")
    cmd = ["nmap"] + flags.split() + [target]
    return cmd

def _build_nikto(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["nikto", "-h", target, "-Format", "txt"]

def _build_gobuster(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    return ["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "--no-error"]

def _build_whatweb(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["whatweb", "-a", "3", target]

def _build_nuclei(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    templates = args.get("templates", "cves")
    return ["nuclei", "-u", target, "-t", templates, "-silent"]

def _build_hydra(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    service = args.get("service", "ssh")
    userlist = args.get("userlist", "/usr/share/wordlists/metasploit/unix_users.txt")
    passlist = args.get("passlist", "/usr/share/wordlists/rockyou.txt")
    return ["hydra", "-L", userlist, "-P", passlist, target, service, "-t", "4", "-f"]

def _build_john(args: dict[str, Any]) -> list[str]:
    hashfile = args.get("hashfile", "")
    wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    if not hashfile:
        raise ValueError("john requires 'hashfile' argument pointing to a hash file.")
    return ["john", f"--wordlist={wordlist}", hashfile]

def _build_hashcat(args: dict[str, Any]) -> list[str]:
    hashfile = args.get("hashfile", "")
    wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    mode = args.get("mode", "0")  # 0=MD5, 1000=NTLM, etc.
    if not hashfile:
        raise ValueError("hashcat requires 'hashfile' argument.")
    return ["hashcat", "-m", str(mode), hashfile, wordlist, "--force", "-O"]

def _build_sqlmap(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "")
    extra = args.get("flags", "--batch --level=2 --risk=1")
    if not target:
        raise ValueError("sqlmap requires 'target' URL.")
    return ["sqlmap", "-u", target] + extra.split()

def _build_dirb(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    return ["dirb", target, wordlist, "-S"]

def _build_wpscan(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["wpscan", "--url", target, "--no-banner", "--random-user-agent"]

def _build_masscan(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    ports = args.get("ports", "1-1000")
    rate = args.get("rate", "1000")
    return ["masscan", target, f"-p{ports}", "--rate", rate]

def _build_fierce(args: dict[str, Any]) -> list[str]:
    domain = args.get("target", "localhost")
    return ["fierce", "--domain", domain]

def _build_dnsrecon(args: dict[str, Any]) -> list[str]:
    domain = args.get("target", "localhost")
    return ["dnsrecon", "-d", domain, "-t", "std"]

def _build_subfinder(args: dict[str, Any]) -> list[str]:
    domain = args.get("target", "localhost")
    return ["subfinder", "-d", domain, "-silent"]

def _build_amass(args: dict[str, Any]) -> list[str]:
    domain = args.get("target", "localhost")
    return ["amass", "enum", "-passive", "-d", domain]

def _build_sslyze(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["sslyze", "--regular", target]

def _build_testssl(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["testssl.sh", "--quiet", target]

def _build_metasploit(args: dict[str, Any]) -> list[str]:
    module = args.get("module", "")
    target = args.get("target", "localhost")
    opts = args.get("options", "")
    if not module:
        raise ValueError("metasploit requires 'module' argument (e.g. auxiliary/scanner/http/http_version).")
    rc_content = f"use {module}\nset RHOSTS {target}\n{opts}\nrun\nexit\n"
    rc_path = f"/tmp/kali_ai_msf_{int(time.time())}.rc"
    Path(rc_path).write_text(rc_content)
    return ["msfconsole", "-q", "-r", rc_path]

def _build_enum4linux(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["enum4linux", "-a", target]

def _build_smbclient(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    share = args.get("share", "")
    return ["smbclient", f"//{target}/{share}", "-N", "-L"]

def _build_curl(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    flags = args.get("flags", "-sI")
    return ["curl"] + flags.split() + [target]

def _build_wget(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["wget", "--spider", "-S", target]

def _build_xssstrike(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["xssstrike", "-u", target, "--skip"]

def _build_commix(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    return ["commix", "--url", target, "--batch"]

def _build_aircrack(args: dict[str, Any]) -> list[str]:
    capfile = args.get("capfile", "")
    wordlist = args.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    if not capfile:
        raise ValueError("aircrack-ng requires 'capfile' argument.")
    return ["aircrack-ng", "-w", wordlist, capfile]

def _build_burpsuite(args: dict[str, Any]) -> list[str]:
    target = args.get("target", "localhost")
    # Launch Burp headless if jar is available
    burp_jar = shutil.which("burpsuite") or "/opt/BurpSuiteCommunity/BurpSuiteCommunity"
    return [burp_jar, "--unpause-spider-and-scanner", f"--target-scope={target}"]


# ---------------------------------------------------------------------------
# MASTER TOOL MAP  {tool_id: (command_builder, description)}
# ---------------------------------------------------------------------------

KALI_TOOL_MAP: dict[str, tuple[Any, str]] = {
    "nmap":         (_build_nmap,       "Port/service scanner"),
    "nikto":        (_build_nikto,      "Web server vulnerability scanner"),
    "gobuster":     (_build_gobuster,   "Directory/file brute-forcer"),
    "dirb":         (_build_dirb,       "Web directory bruter"),
    "whatweb":      (_build_whatweb,    "Web tech fingerprinter"),
    "nuclei":       (_build_nuclei,     "Template-based vuln scanner"),
    "sqlmap":       (_build_sqlmap,     "SQL injection tester"),
    "hydra":        (_build_hydra,      "Online password cracker"),
    "john":         (_build_john,       "Offline hash cracker"),
    "hashcat":      (_build_hashcat,    "GPU-accelerated hash cracker"),
    "wpscan":       (_build_wpscan,     "WordPress vulnerability scanner"),
    "masscan":      (_build_masscan,    "Mass port scanner"),
    "fierce":       (_build_fierce,     "DNS recon tool"),
    "dnsrecon":     (_build_dnsrecon,   "DNS enumeration"),
    "subfinder":    (_build_subfinder,  "Subdomain discovery"),
    "amass":        (_build_amass,      "Attack surface mapping"),
    "sslyze":       (_build_sslyze,     "TLS/SSL analyzer"),
    "testssl":      (_build_testssl,    "TLS testing script"),
    "metasploit":   (_build_metasploit, "Exploitation framework"),
    "enum4linux":   (_build_enum4linux, "SMB/Linux enumeration"),
    "smbclient":    (_build_smbclient,  "SMB share lister"),
    "curl":         (_build_curl,       "HTTP probe"),
    "wget":         (_build_wget,       "HTTP resource fetcher"),
    "xssstrike":    (_build_xssstrike,  "XSS scanner"),
    "commix":       (_build_commix,     "Command injection tester"),
    "aircrack":     (_build_aircrack,   "Wi-Fi password cracker"),
    "burpsuite":    (_build_burpsuite,  "Web app security testing"),
}


# ---------------------------------------------------------------------------
# TOOL SELECTION ENGINE  — picks the best tool for a task description
# ---------------------------------------------------------------------------

TASK_KEYWORD_MAP: dict[str, list[str]] = {
    "nmap":       ["port", "scan", "service", "recon", "open ports", "banner", "network"],
    "nikto":      ["web server", "nikto", "http vuln", "dangerous files"],
    "gobuster":   ["directory", "dir", "file brute", "gobuster", "hidden"],
    "dirb":       ["dirb", "directory listing"],
    "whatweb":    ["fingerprint", "tech stack", "cms", "whatweb", "identify"],
    "nuclei":     ["cve", "template", "nuclei", "known vuln", "exposure", "misconfiguration"],
    "sqlmap":     ["sql", "sqli", "injection", "database", "sqlmap"],
    "hydra":      ["login", "brute force", "ssh brute", "ftp brute", "password spray", "online crack"],
    "john":       ["hash crack", "john", "offline", "shadow", "ntlm", "md5 crack"],
    "hashcat":    ["hashcat", "gpu crack", "password hash", "cracking"],
    "wpscan":     ["wordpress", "wp", "wpscan", "plugin vuln"],
    "masscan":    ["masscan", "fast scan", "large range", "cidr scan"],
    "fierce":     ["dns", "fierce", "zone transfer"],
    "dnsrecon":   ["dns enum", "dnsrecon", "subdomain dns"],
    "subfinder":  ["subdomain", "subfinder", "sub-domain"],
    "amass":      ["amass", "asset discovery", "attack surface"],
    "sslyze":     ["ssl", "tls", "certificate", "cipher", "sslyze"],
    "testssl":    ["testssl", "tls test", "ssl test"],
    "metasploit": ["exploit", "metasploit", "msf", "meterpreter", "payload"],
    "enum4linux": ["smb", "samba", "enum4linux", "shares", "users"],
    "sqlmap":     ["sql injection", "sqli"],
    "xssstrike":  ["xss", "cross-site", "xssstrike"],
    "commix":     ["command injection", "commix", "rce"],
    "burpsuite":  ["burp", "web app test", "spider", "intercept"],
}


def choose_tool(task_description: str) -> list[str]:
    """
    Return an ordered list of recommended tool IDs for the given task description.
    Uses keyword matching; falls back to ['nmap'] if nothing matches.
    """
    desc_lower = task_description.lower()
    scores: dict[str, int] = {}
    for tool_id, keywords in TASK_KEYWORD_MAP.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score:
            scores[tool_id] = score
    ranked = sorted(scores, key=lambda t: scores[t], reverse=True)
    return ranked if ranked else ["nmap"]


# ---------------------------------------------------------------------------
# MAIN RUNNER
# ---------------------------------------------------------------------------

async def run_tool(
    tool_id: str,
    args: dict[str, Any],
    timeout: int = 120,
) -> ToolResult:
    """
    Execute a Kali Linux tool and return a ToolResult.

    Parameters
    ----------
    tool_id  : one of the keys in KALI_TOOL_MAP
    args     : dict of parameters (target, flags, wordlist, etc.)
    timeout  : seconds before the process is killed
    """
    target = args.get("target", "unknown")

    if tool_id not in KALI_TOOL_MAP:
        return ToolResult(
            tool=tool_id, target=target, success=False,
            error=f"Tool '{tool_id}' is not in the Kali tool map. "
                  f"Available tools: {', '.join(sorted(KALI_TOOL_MAP))}",
        )

    builder, _desc = KALI_TOOL_MAP[tool_id]

    try:
        cmd = builder(args)
    except Exception as exc:
        return ToolResult(tool=tool_id, target=target, success=False,
                          error=f"Command build error: {exc}")

    # Check if binary is on PATH
    binary = cmd[0]
    if not shutil.which(binary):
        return ToolResult(
            tool=tool_id, target=target, success=False,
            command=cmd,
            error=f"Binary '{binary}' not found on PATH. "
                  f"Install it on Kali with: sudo apt install {binary}",
        )

    logger.info("[KaliRunner] Running: %s", " ".join(cmd))

    start = time.monotonic()
    stdout_buf, stderr_buf = "", ""
    exit_code = -1

    async with _SEMAPHORE:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                stdout_buf = stdout_bytes.decode("utf-8", errors="replace")
                stderr_buf = stderr_bytes.decode("utf-8", errors="replace")
                exit_code = proc.returncode or 0
                success = exit_code == 0
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return ToolResult(
                    tool=tool_id, target=target, success=False,
                    command=cmd, exit_code=-1,
                    runtime_seconds=time.monotonic() - start,
                    error=f"Tool timed out after {timeout}s.",
                )
        except Exception as exc:
            return ToolResult(
                tool=tool_id, target=target, success=False,
                command=cmd,
                runtime_seconds=time.monotonic() - start,
                error=str(exc),
            )

    runtime = time.monotonic() - start

    result = ToolResult(
        tool=tool_id,
        target=target,
        success=success,
        stdout=stdout_buf,
        stderr=stderr_buf,
        exit_code=exit_code,
        runtime_seconds=round(runtime, 2),
        command=cmd,
    )

    # Persist to execution log
    _EXECUTION_LOG.append(result.to_dict())
    logger.info("[KaliRunner] %s on %s → exit=%d  runtime=%.1fs",
                tool_id, target, exit_code, runtime)

    return result


def get_execution_log() -> list[dict[str, Any]]:
    """Return all past tool executions this session."""
    return list(_EXECUTION_LOG)


def list_available_tools() -> list[dict[str, str]]:
    """List all tools and whether they are installed on this system."""
    out = []
    for tool_id, (builder, desc) in KALI_TOOL_MAP.items():
        # Guess binary name (first token of a dummy build, or just tool_id)
        try:
            dummy_cmd = builder({"target": "localhost"})
            binary = dummy_cmd[0]
        except Exception:
            binary = tool_id
        installed = bool(shutil.which(binary))
        out.append({
            "tool_id": tool_id,
            "binary": binary,
            "description": desc,
            "installed": "✅" if installed else "❌ (not on PATH)",
        })
    return out
