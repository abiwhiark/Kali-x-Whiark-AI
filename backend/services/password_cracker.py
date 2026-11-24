"""
Kali AI - Password Cracking Module
====================================
Wraps Kali's cracking tools (Hydra, John, Hashcat, Aircrack-ng).

Gate:
  - Requires explicit user consent via ConsentGate before ANY cracking.
  - Target must be an authorized host (or user has acknowledged they own it).
  - All crack attempts are logged.

Purpose: assess PASSWORD STRENGTH of authorized targets
         so the owner can fix security gaps.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.services.kali_tool_runner import run_tool, ToolResult
from backend.services.security.consent_gate import get_consent_gate, ConsentRequiredError

logger = logging.getLogger(__name__)

_CRACK_LOG: list[dict[str, Any]] = []


@dataclass
class CrackResult:
    tool: str
    target: str
    success: bool
    cracked_credentials: list[str] = field(default_factory=list)
    strength_assessment: str = ""
    raw_output: str = ""
    error: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def report_section(self) -> str:
        lines = [
            f"## Password Strength Assessment — {self.target}",
            f"**Tool used:** `{self.tool}`",
            f"**Status:** {'✅ Cracked' if self.cracked_credentials else '🔒 Not cracked / Strong'}",
            "",
        ]
        if self.cracked_credentials:
            lines += [
                "### ⚠️ Cracked Credentials Found",
                "```",
                *self.cracked_credentials[:20],
                "```",
                "",
                "### Remediation",
                "- Immediately change the exposed credentials.",
                "- Enforce strong password policy (min 12 chars, mixed case, symbols).",
                "- Enable MFA on all services.",
                "- Consider account lockout after 5 failed attempts.",
                "",
            ]
        else:
            lines += [
                "### 🔒 No weak credentials found.",
                "The target service appears to have adequate password strength.",
                "",
            ]
        if self.strength_assessment:
            lines += [f"**Assessment:** {self.strength_assessment}", ""]
        if self.raw_output:
            lines += ["**Raw tool output:**", "```", self.raw_output[:3000], "```"]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Online Brute-force (Hydra)
# ---------------------------------------------------------------------------

async def crack_online(
    target: str,
    service: str,
    userlist: str = "",
    passlist: str = "/usr/share/wordlists/rockyou.txt",
) -> CrackResult:
    """
    Run Hydra against an online service (SSH, FTP, HTTP-form, etc.)
    Requires prior consent in ConsentGate.
    """
    gate = get_consent_gate()
    try:
        gate.require_consent(target)
    except ConsentRequiredError as exc:
        return CrackResult(tool="hydra", target=target, success=False,
                           error=f"Consent required:\n{exc.prompt}")

    if not userlist:
        userlist = "/usr/share/wordlists/metasploit/unix_users.txt"

    result = await run_tool("hydra", {
        "target": target,
        "service": service,
        "userlist": userlist,
        "passlist": passlist,
    }, timeout=300)

    cracked = _parse_hydra_output(result.stdout)
    strength = _assess_strength(cracked, result)

    record = CrackResult(
        tool="hydra", target=target, success=result.success,
        cracked_credentials=cracked,
        strength_assessment=strength,
        raw_output=result.stdout,
        error=result.error,
    )
    _CRACK_LOG.append({
        "tool": "hydra", "target": target,
        "cracked_count": len(cracked),
        "timestamp": record.timestamp,
    })
    return record


# ---------------------------------------------------------------------------
# Offline Hash Cracking (John / Hashcat)
# ---------------------------------------------------------------------------

async def crack_hashes(
    hashfile: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    mode: str = "john",
    hash_type: str = "0",
) -> CrackResult:
    """
    Crack hashes from a file using John the Ripper or Hashcat.
    No ConsentGate needed for offline cracking (target is a file, not a live host).
    """
    if not Path(hashfile).exists():
        return CrackResult(tool=mode, target=hashfile, success=False,
                           error=f"Hash file not found: {hashfile}")

    if mode == "hashcat":
        result = await run_tool("hashcat", {
            "hashfile": hashfile,
            "wordlist": wordlist,
            "mode": hash_type,
        }, timeout=600)
        cracked = _parse_hashcat_output(result.stdout)
    else:
        result = await run_tool("john", {
            "hashfile": hashfile,
            "wordlist": wordlist,
        }, timeout=600)
        cracked = _parse_john_output(result.stdout)

    strength = _assess_strength(cracked, result)
    record = CrackResult(
        tool=mode, target=hashfile, success=result.success,
        cracked_credentials=cracked,
        strength_assessment=strength,
        raw_output=result.stdout,
        error=result.error,
    )
    _CRACK_LOG.append({
        "tool": mode, "target": hashfile,
        "cracked_count": len(cracked),
        "timestamp": record.timestamp,
    })
    return record


# ---------------------------------------------------------------------------
# Output Parsers
# ---------------------------------------------------------------------------

def _parse_hydra_output(output: str) -> list[str]:
    """Extract 'login: X password: Y' lines from Hydra output."""
    lines = output.splitlines()
    return [l.strip() for l in lines if "login:" in l.lower() and "password:" in l.lower()]


def _parse_john_output(output: str) -> list[str]:
    """Extract cracked passwords from John output."""
    lines = output.splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("Using") and "password" not in l.lower()[:20]]


def _parse_hashcat_output(output: str) -> list[str]:
    """Extract hash:plain pairs from Hashcat output."""
    lines = output.splitlines()
    return [l.strip() for l in lines if ":" in l and not l.startswith("Session") and not l.startswith("Status")]


# ---------------------------------------------------------------------------
# Strength Assessment
# ---------------------------------------------------------------------------

def _assess_strength(cracked: list[str], result: ToolResult) -> str:
    if not cracked:
        return "Password strength appears STRONG. No credentials were cracked."
    count = len(cracked)
    if count >= 5:
        return f"Password strength is CRITICALLY WEAK — {count} credentials cracked. Immediate remediation required."
    elif count >= 2:
        return f"Password strength is WEAK — {count} credentials cracked. Enforce stronger password policy."
    else:
        return f"Password strength is LOW — {count} credential cracked. Review and update."


def get_crack_log() -> list[dict[str, Any]]:
    return list(_CRACK_LOG)
