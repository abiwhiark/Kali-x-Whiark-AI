"""
Unit tests for configuration loading and validation.
"""

from backend.core.config import Settings, get_settings


def test_settings_defaults():
    settings = Settings()
    assert settings.GEMINI_MODEL in ("gemini-2.0-flash", "gemini-2.5-flash")
    assert settings.MAX_AGENT_ITERATIONS == 10
    assert settings.MAX_TOOL_CALLS == 15
    assert settings.TOOL_EXECUTION_TIMEOUT == 120
    assert settings.DATABASE_PATH == "kali_ai.db"


def test_settings_demo_mode_when_no_key():
    settings = Settings(GEMINI_API_KEY="")
    assert settings.demo_mode is True

    settings_placeholder = Settings(GEMINI_API_KEY="your_key_here")
    assert settings_placeholder.demo_mode is True


def test_settings_active_mode_when_key_provided():
    settings = Settings(GEMINI_API_KEY="AIzaSyDummyKeyForTesting")
    assert settings.demo_mode is False


def test_allowed_targets_list_parsing():
    settings = Settings(ALLOWED_TARGETS="127.0.0.1, localhost, 192.168.1.0/24")
    targets = settings.allowed_targets_list
    assert "127.0.0.1" in targets
    assert "localhost" in targets
    assert "192.168.1.0/24" in targets


def test_get_settings_cached_singleton():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
