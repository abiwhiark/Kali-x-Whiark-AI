"""
Kali AI - Configuration
Loads settings from .env file using pydantic-settings.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field, computed_field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Gemini API ---
    GEMINI_API_KEY: str = Field(default="", description="Gemini API key. Leave empty for demo mode.")
    GEMINI_MODEL: str = Field(default="gemini-2.5-flash", description="Gemini model to use.")

    # --- Database ---
    DATABASE_PATH: str = Field(default="kali_ai.db", description="SQLite database file path.")

    # --- Agent Limits ---
    MAX_AGENT_ITERATIONS: int = Field(default=10, description="Maximum agent loop iterations per assessment.")
    MAX_TOOL_CALLS: int = Field(default=15, description="Maximum tool calls per assessment.")
    TOOL_EXECUTION_TIMEOUT: int = Field(default=120, description="Tool execution timeout in seconds.")

    # --- Security ---
    ALLOWED_TARGETS: str = Field(
        default="127.0.0.1,localhost,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
        description="Comma-separated list of allowed target hosts/CIDRs.",
    )

    @computed_field
    @property
    def demo_mode(self) -> bool:
        """True when no API key is configured — the agent runs in demo mode."""
        return not self.GEMINI_API_KEY or self.GEMINI_API_KEY == "your_key_here"

    @property
    def allowed_targets_list(self) -> list[str]:
        """Parse the comma-separated ALLOWED_TARGETS into a list."""
        return [t.strip() for t in self.ALLOWED_TARGETS.split(",") if t.strip()]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()
