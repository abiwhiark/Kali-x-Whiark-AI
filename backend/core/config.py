"""
Kali AI - Configuration
Loads settings from .env file using pydantic-settings.
Supports Gemini, OpenAI, Anthropic, and Ollama providers.
"""

from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field, computed_field

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Active Provider ──────────────────────────────────────────────
    ACTIVE_PROVIDER: str = Field(default="", description="Active AI provider: gemini | openai | anthropic | ollama")

    # ── Gemini ───────────────────────────────────────────────────────
    GEMINI_API_KEY: str = Field(default="", description="Gemini API key.")
    GEMINI_MODEL: str = Field(default="gemini-2.5-flash", description="Gemini model.")

    # ── OpenAI ───────────────────────────────────────────────────────
    OPENAI_API_KEY: str = Field(default="", description="OpenAI API key.")
    OPENAI_MODEL: str = Field(default="gpt-4o-mini", description="OpenAI model.")

    # ── Anthropic ────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = Field(default="", description="Anthropic API key.")
    ANTHROPIC_MODEL: str = Field(default="claude-3-5-haiku-20241022", description="Anthropic model.")

    # ── Ollama (local, no key needed) ────────────────────────────────
    OLLAMA_HOST: str = Field(default="http://localhost:11434", description="Ollama server URL.")
    OLLAMA_MODEL: str = Field(default="kali-cyber", description="Ollama model name.")

    # ── Database ─────────────────────────────────────────────────────
    DATABASE_PATH: str = Field(default="kali_ai.db", description="SQLite database file path.")

    # ── Agent Limits ─────────────────────────────────────────────────
    MAX_AGENT_ITERATIONS: int = Field(default=10)
    MAX_TOOL_CALLS: int = Field(default=15)
    TOOL_EXECUTION_TIMEOUT: int = Field(default=120)

    # ── Security ─────────────────────────────────────────────────────
    ALLOWED_TARGETS: str = Field(
        default="*",
        description="Comma-separated allowed targets. Use * for all (HexStrike mode).",
    )

    @computed_field
    @property
    def demo_mode(self) -> bool:
        """True when no usable provider is configured."""
        has_gemini = bool(self.GEMINI_API_KEY and self.GEMINI_API_KEY not in ("", "your_key_here"))
        has_openai = bool(self.OPENAI_API_KEY)
        has_anthropic = bool(self.ANTHROPIC_API_KEY)
        has_ollama = self.ACTIVE_PROVIDER == "ollama"
        return not (has_gemini or has_openai or has_anthropic or has_ollama)

    @property
    def allowed_targets_list(self) -> list[str]:
        return [t.strip() for t in self.ALLOWED_TARGETS.split(",") if t.strip()]

    model_config = {
        "env_file": str(_ENV_FILE),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    """Force reload settings (used after .env is updated mid-session)."""
    get_settings.cache_clear()
    return get_settings()
