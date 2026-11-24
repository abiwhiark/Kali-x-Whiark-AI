"""
Kali AI - Consent Gate
======================
Replaces the hard ALLOWED_TARGETS allowlist with a professional
"user-confirms-authorization" model — exactly how Metasploit,
Burp Suite, and Nessus handle authorization.

Flow:
  1. User requests a scan on any target.
  2. ConsentGate checks if the target was already consented to this session.
  3. If not, it raises ConsentRequiredError with a prompt for the CLI/API layer.
  4. The CLI/API layer shows the prompt, user types "yes" / "i have permission".
  5. ConsentGate records the consent and the scan proceeds.
  6. All consents are logged with timestamp and target.

This satisfies legal requirements (user acknowledges they have permission)
while allowing unlimited targets — the same approach used by all professional
security tools.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConsentRequiredError(Exception):
    """Raised when a target has not been consented to yet."""
    def __init__(self, target: str, prompt: str) -> None:
        self.target = target
        self.prompt = prompt
        super().__init__(prompt)


# ---------------------------------------------------------------------------
# Consent Record
# ---------------------------------------------------------------------------

@dataclass
class ConsentRecord:
    target: str
    consented_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    user_acknowledgement: str = ""
    scope: str = "vulnerability assessment"


# ---------------------------------------------------------------------------
# ConsentGate
# ---------------------------------------------------------------------------

class ConsentGate:
    """
    Session-scoped consent store.
    One instance lives per assessment session.
    """

    # Legal disclaimer shown to the user before they scan any new target
    DISCLAIMER = (
        "\n╔══════════════════════════════════════════════════════════════╗\n"
        "║           ⚠️  WHIARK × KALI AI — LEGAL NOTICE ⚠️              ║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        "║  You are about to perform a security assessment on:          ║\n"
        "║  TARGET: {target:<52} ║\n"
        "║                                                              ║\n"
        "║  By proceeding you confirm that you:                         ║\n"
        "║  1. OWN this system, OR                                      ║\n"
        "║  2. Have WRITTEN authorization from the owner, OR            ║\n"
        "║  3. Are testing within an official Bug Bounty program scope. ║\n"
        "║                                                              ║\n"
        "║  Unauthorized scanning is ILLEGAL under cybercrime laws.     ║\n"
        "║  Whiark × Kali AI logs this consent. You are responsible.   ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n"
        "\n  Type  YES / I HAVE PERMISSION / AUTHORIZED  to proceed.\n"
        "  Type  NO  to cancel.\n"
    )

    def __init__(self) -> None:
        self._consents: dict[str, ConsentRecord] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_consented(self, target: str) -> bool:
        """Return True if the target has already been consented to."""
        key = self._normalize(target)
        return key in self._consents

    def require_consent(self, target: str) -> None:
        """
        Raise ConsentRequiredError if target is not yet consented.
        Call this BEFORE invoking any tool against the target.
        """
        key = self._normalize(target)
        if key not in self._consents:
            prompt = self.DISCLAIMER.format(target=target)
            raise ConsentRequiredError(target=target, prompt=prompt)

    def grant_consent(self, target: str, acknowledgement: str = "yes") -> ConsentRecord:
        """
        Record user consent for a target.
        Call this after the user types 'yes' / 'authorized' / 'i have permission'.
        """
        key = self._normalize(target)
        record = ConsentRecord(
            target=target,
            user_acknowledgement=acknowledgement,
        )
        self._consents[key] = record
        logger.warning(
            "[ConsentGate] CONSENT GRANTED: target=%s  ack='%s'  at=%s",
            target, acknowledgement, record.consented_at,
        )
        return record

    def revoke_consent(self, target: str) -> None:
        """Remove consent for a target (e.g. user typed 'stop')."""
        key = self._normalize(target)
        self._consents.pop(key, None)

    def all_consented_targets(self) -> list[str]:
        return [r.target for r in self._consents.values()]

    def consent_log(self) -> list[dict[str, Any]]:
        return [
            {
                "target": r.target,
                "consented_at": r.consented_at,
                "acknowledgement": r.user_acknowledgement,
            }
            for r in self._consents.values()
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(target: str) -> str:
        """Normalize target to a consistent key."""
        from urllib.parse import urlparse
        t = target.strip().lower()
        try:
            parsed = urlparse(t)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass
        return t

    @staticmethod
    def parse_user_answer(answer: str) -> bool:
        """Return True if the user's answer means 'yes, I have permission'."""
        normalized = answer.strip().lower()
        affirmative = {
            "yes", "y", "yeah", "yep", "yup", "ok", "okay",
            "authorized", "authorised", "i have permission", "i have authorization",
            "i have authorisation", "confirmed", "confirm", "proceed",
            "i own it", "i own this", "agreed", "agree",
        }
        return any(aff in normalized for aff in affirmative)


# ---------------------------------------------------------------------------
# Module-level singleton (used by orchestrator and CLI)
# ---------------------------------------------------------------------------

_global_gate = ConsentGate()


def get_consent_gate() -> ConsentGate:
    """Return the module-level ConsentGate singleton."""
    return _global_gate


def reset_consent_gate() -> None:
    """Create a fresh gate (call between sessions if needed)."""
    global _global_gate
    _global_gate = ConsentGate()
