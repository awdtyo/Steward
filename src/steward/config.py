"""Config: load and validate steward settings from environment variables.

Rules (see AGENTS.md):
- LLM base_url, model names, and all secrets come from env vars. Never hardcode.
- Keep .env.example in sync with the variables read here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _require(name: str, env: dict[str, str], *, dry_run: bool) -> str:
    value = env.get(name, "").strip()
    if value:
        return value
    if dry_run:
        # Dry-run uses mock events/logs and touches nothing real,
        # so allow missing secrets to ease local testing.
        return f"dry-run-{name.lower().replace('_', '-')}"
    raise ConfigError(f"Missing required env var: {name}")


@dataclass(frozen=True)
class Settings:
    """Validated steward configuration. See .env.example for all fields."""

    llm_base_url: str
    llm_api_key: str
    model_nano: str  # triage
    model_super: str  # planning
    model_ultra: str  # hard or ambiguous cases
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    alert_to: str = ""
    healthcheck_url: str = ""
    dry_run: bool = False

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ) if env is None else dict(env)
        dry_run = _parse_bool(env.get("DRY_RUN", "false"))

        llm_base_url = _require("LLM_BASE_URL", env, dry_run=dry_run)
        if not (
            llm_base_url.startswith("http://")
            or llm_base_url.startswith("https://")
            or (dry_run and llm_base_url.startswith("dry-run-"))
        ):
            raise ConfigError("LLM_BASE_URL must start with http:// or https://")

        smtp_port_raw = env.get("SMTP_PORT", "587").strip() or "587"
        try:
            smtp_port = int(smtp_port_raw)
        except ValueError:
            raise ConfigError("SMTP_PORT must be an integer") from None
        if not 1 <= smtp_port <= 65535:
            raise ConfigError("SMTP_PORT must be between 1 and 65535")

        return cls(
            llm_base_url=llm_base_url,
            llm_api_key=_require("LLM_API_KEY", env, dry_run=dry_run),
            model_nano=_require("MODEL_NANO", env, dry_run=dry_run),
            model_super=_require("MODEL_SUPER", env, dry_run=dry_run),
            model_ultra=_require("MODEL_ULTRA", env, dry_run=dry_run),
            smtp_host=env.get("SMTP_HOST", "").strip(),
            smtp_port=smtp_port,
            smtp_user=env.get("SMTP_USER", "").strip(),
            smtp_password=env.get("SMTP_PASSWORD", "").strip(),
            smtp_from=env.get("SMTP_FROM", "").strip(),
            alert_to=env.get("ALERT_TO", "").strip(),
            healthcheck_url=env.get("HEALTHCHECK_URL", "").strip(),
            dry_run=dry_run,
        )


def load_config(env: dict[str, str] | None = None) -> Settings:
    """Load and validate settings from the environment."""
    return Settings.from_env(env)


__all__ = ["ConfigError", "Settings", "load_config"]
