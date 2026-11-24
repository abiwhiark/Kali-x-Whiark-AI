"""
Unit tests for the Security Validator.
Verifies target allowlists, argument validation, iteration limits, and tool-call limits.
"""

import pytest
from backend.models.schemas import ToolCallRequest
from backend.services.tool_registry.registry import create_default_registry
from backend.services.security.validator import SecurityValidator


@pytest.fixture(autouse=True)
def isolate_validator_test(monkeypatch):
    monkeypatch.setenv("ALLOWED_TARGETS", "127.0.0.1,localhost,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
    from backend.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def validator():
    registry = create_default_registry()
    return SecurityValidator(registry)


def test_valid_localhost_target_accepted(validator):
    req = ToolCallRequest(
        tool_id="whatweb_scan",
        arguments={"target": "localhost"},
        target="localhost",
    )
    result = validator.validate(req)
    assert result.is_valid is True
    assert len(result.errors) == 0


def test_valid_private_ip_target_accepted(validator):
    req = ToolCallRequest(
        tool_id="nmap_scan",
        arguments={"target": "192.168.1.50", "profile": "quick"},
        target="192.168.1.50",
    )
    result = validator.validate(req)
    assert result.is_valid is True


def test_unauthorized_external_target_blocked(validator):
    req = ToolCallRequest(
        tool_id="nmap_scan",
        arguments={"target": "example.com", "profile": "quick"},
        target="example.com",
    )
    result = validator.validate(req)
    assert result.is_valid is False
    assert any("not in the allowed targets list" in err for err in result.errors)


def test_dynamically_authorized_target_accepted(validator):
    validator.authorize_target("targetwebsite.com")
    req = ToolCallRequest(
        tool_id="whatweb_scan",
        arguments={"target": "targetwebsite.com"},
        target="targetwebsite.com",
    )
    result = validator.validate(req)
    assert result.is_valid is True


def test_wildcard_target_accepted(validator):
    validator.authorize_target("*")
    req = ToolCallRequest(
        tool_id="nmap_scan",
        arguments={"target": "random-target-site.com", "profile": "quick"},
        target="random-target-site.com",
    )
    result = validator.validate(req)
    assert result.is_valid is True


def test_unregistered_tool_blocked(validator):
    req = ToolCallRequest(
        tool_id="unauthorized_exploit_tool",
        arguments={"target": "localhost"},
        target="localhost",
    )
    result = validator.validate(req)
    assert result.is_valid is False
    assert any("not registered" in err for err in result.errors)


def test_invalid_enum_argument_blocked(validator):
    req = ToolCallRequest(
        tool_id="nmap_scan",
        arguments={"target": "localhost", "profile": "dangerous_aggressive_syn_flood"},
        target="localhost",
    )
    result = validator.validate(req)
    assert result.is_valid is False
    assert any("Invalid value" in err for err in result.errors)


def test_missing_required_target_argument(validator):
    req = ToolCallRequest(
        tool_id="whatweb_scan",
        arguments={},
        target="",
    )
    result = validator.validate(req)
    assert result.is_valid is False
    assert any("No target specified" in err or "Missing required argument" in err for err in result.errors)


def test_max_tool_calls_limit(validator):
    req = ToolCallRequest(
        tool_id="whatweb_scan",
        arguments={"target": "localhost"},
        target="localhost",
    )

    # Exceed limit
    for _ in range(15):
        validator.increment_tool_call()

    result = validator.validate(req)
    assert result.is_valid is False
    assert any("Maximum tool calls reached" in err for err in result.errors)


def test_max_iterations_limit(validator):
    req = ToolCallRequest(
        tool_id="whatweb_scan",
        arguments={"target": "localhost"},
        target="localhost",
    )

    for _ in range(10):
        validator.increment_iteration()

    result = validator.validate(req)
    assert result.is_valid is False
    assert any("Maximum agent iterations reached" in err for err in result.errors)
