"""
Kali AI - Security Validator
Validates every tool call before execution:
  - Is the tool registered?
  - Is the target authorized?
  - Are the arguments valid?
  - Are execution limits respected?
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

from backend.core.config import get_settings
from backend.models.schemas import ToolCallRequest
from backend.services.tool_registry.registry import ToolRegistry

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of a security validation check."""
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class SecurityValidator:
    """
    Enforces all security policies before a tool is allowed to execute.
    The AI cannot bypass this layer.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry
        self._settings = get_settings()
        self._tool_calls_count: int = 0
        self._iteration_count: int = 0
        self._session_allowed_targets: set[str] = set()

    def authorize_target(self, target: str) -> None:
        """Dynamically authorize a target for the current session or assessment."""
        if not target:
            return
        cleaned = target.strip().lower()
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                cleaned = parsed.hostname.lower()
        except Exception:
            pass
        self._session_allowed_targets.add(cleaned)

    def reset_counters(self) -> None:
        """Reset per-assessment counters."""
        self._tool_calls_count = 0
        self._iteration_count = 0

    def increment_iteration(self) -> None:
        self._iteration_count += 1

    def increment_tool_call(self) -> None:
        self._tool_calls_count += 1

    @property
    def tool_calls_count(self) -> int:
        return self._tool_calls_count

    @property
    def iteration_count(self) -> int:
        return self._iteration_count

    def validate(self, request: ToolCallRequest) -> ValidationResult:
        """Run all validation checks on a tool call request."""
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Tool exists in registry
        defn = self._registry.get_definition(request.tool_id)
        if defn is None:
            errors.append(f"Tool '{request.tool_id}' is not registered in the tool registry.")
            return ValidationResult(is_valid=False, errors=errors)

        # 2. Iteration limit
        if self._iteration_count >= self._settings.MAX_AGENT_ITERATIONS:
            errors.append(
                f"Maximum agent iterations reached ({self._settings.MAX_AGENT_ITERATIONS}). "
                "Cannot execute more tools in this assessment."
            )

        # 3. Tool call limit
        if self._tool_calls_count >= self._settings.MAX_TOOL_CALLS:
            errors.append(
                f"Maximum tool calls reached ({self._settings.MAX_TOOL_CALLS}). "
                "Cannot execute more tools in this assessment."
            )

        # 4. Target validation
        target = request.target or request.arguments.get("target", "")
        if target:
            target_valid, target_msg = self._validate_target(target)
            if not target_valid:
                errors.append(target_msg)
        else:
            errors.append("No target specified in the tool call request.")

        # 5. Required arguments
        required_fields = defn.input_schema.get("required", [])
        for req_field in required_fields:
            if req_field not in request.arguments or not request.arguments[req_field]:
                errors.append(f"Missing required argument: '{req_field}'")

        # 6. Argument validation — enum constraints
        props = defn.input_schema.get("properties", {})
        for arg_name, arg_value in request.arguments.items():
            if arg_name in props:
                allowed = props[arg_name].get("enum")
                if allowed and arg_value not in allowed:
                    errors.append(
                        f"Invalid value '{arg_value}' for argument '{arg_name}'. "
                        f"Allowed values: {allowed}"
                    )

        # 7. Permission warnings
        if defn.permission_requirements:
            warnings.append(
                f"Tool '{defn.name}' has permission requirements: {defn.permission_requirements}"
            )

        is_valid = len(errors) == 0
        if not is_valid:
            logger.warning("Validation FAILED for %s: %s", request.tool_id, errors)
        else:
            logger.info("Validation PASSED for %s targeting %s", request.tool_id, target)

        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    def _validate_target(self, target: str) -> tuple[bool, str]:
        """
        Validate the target.

        New model (professional consent gate):
          - ANY target is allowed once the user has acknowledged authorization
            via ConsentGate (same model as Metasploit / Burp Suite / Nessus).
          - If the target has NOT been consented to yet in the session, the
            orchestrator will show the ConsentGate disclaimer to the user.
          - The old ALLOWED_TARGETS hard-list is still checked as a fast-path
            to skip the consent prompt for pre-approved hosts.
        """
        from backend.services.security.consent_gate import get_consent_gate

        allowed = self._settings.allowed_targets_list

        # Extract hostname from URL if needed
        hostname = target
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                hostname = parsed.hostname
        except Exception:
            pass

        hostname_lower = hostname.strip().lower()

        logger.debug(
            "Validating target '%s' (hostname='%s')",
            target, hostname_lower,
        )

        # 1. Wildcard mode in ALLOWED_TARGETS → always allow
        if "*" in allowed or "all" in allowed or "any" in allowed:
            logger.info("Target '%s' allowed via wildcard mode.", hostname_lower)
            return True, ""

        # 2. Pre-approved via ALLOWED_TARGETS (fast path — no consent needed)
        allowed_lower = [a.strip().lower() for a in allowed]
        if hostname_lower in allowed_lower:
            logger.info("Target '%s' allowed via ALLOWED_TARGETS exact match.", hostname_lower)
            return True, ""

        for entry in allowed_lower:
            if "/" in entry or entry.replace(".", "").isdigit():
                continue
            if (
                hostname_lower.endswith("." + entry)
                or entry.endswith("." + hostname_lower)
                or (len(hostname_lower) >= 4 and hostname_lower in entry)
            ):
                logger.info("Target '%s' allowed via ALLOWED_TARGETS domain match '%s'.", hostname_lower, entry)
                return True, ""

        # 3. Check CIDR ranges in ALLOWED_TARGETS
        try:
            import ipaddress, socket
            ip = ipaddress.ip_address(hostname)
            for allowed_entry in allowed:
                try:
                    network = ipaddress.ip_network(allowed_entry, strict=False)
                    if ip in network:
                        return True, ""
                except ValueError:
                    continue
        except ValueError:
            pass

        # 4. ConsentGate — user confirmed authorization for this target this session
        gate = get_consent_gate()
        if gate.is_consented(hostname_lower):
            logger.info("Target '%s' allowed via ConsentGate session consent.", hostname_lower)
            return True, ""

        # 5. Session-authorized targets (legacy path from authorize_target())
        if hasattr(self, "_session_allowed_targets"):
            if "*" in self._session_allowed_targets or hostname_lower in self._session_allowed_targets:
                logger.info("Target '%s' allowed via session authorization.", hostname_lower)
                return True, ""

        # 6. Not yet consented — return a consent-required message (not a hard block)
        return False, (
            f"CONSENT_REQUIRED:{hostname}"
        )
