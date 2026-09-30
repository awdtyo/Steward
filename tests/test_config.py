"""Tests for steward.config (env loading and validation)."""

import pytest

from steward.config import ConfigError, load_config

BASE_ENV = {
    "LLM_BASE_URL": "https://api.example.com/v1",
    "LLM_API_KEY": "test-key",
    "MODEL_NANO": "nano",
    "MODEL_SUPER": "super",
    "MODEL_ULTRA": "ultra",
}


def test_load_config_valid_minimal():
    settings = load_config(dict(BASE_ENV))
    assert settings.llm_base_url == "https://api.example.com/v1"
    assert settings.model_nano == "nano"
    assert settings.model_super == "super"
    assert settings.model_ultra == "ultra"
    assert settings.smtp_port == 587
    assert settings.dry_run is False


def test_load_config_full_env():
    env = dict(
        BASE_ENV,
        SMTP_HOST="mail.example.com",
        SMTP_PORT="465",
        SMTP_USER="user",
        SMTP_PASSWORD="pass",
        SMTP_FROM="steward@example.com",
        ALERT_TO="admin@example.com",
        HEALTHCHECK_URL="https://hc.example.com/ping/abc",
        DRY_RUN="true",
    )
    settings = load_config(env)
    assert settings.smtp_host == "mail.example.com"
    assert settings.smtp_port == 465
    assert settings.alert_to == "admin@example.com"
    assert settings.healthcheck_url == "https://hc.example.com/ping/abc"
    assert settings.dry_run is True


@pytest.mark.parametrize("name", list(BASE_ENV))
def test_missing_required_raises(name):
    env = dict(BASE_ENV)
    del env[name]
    with pytest.raises(ConfigError, match=name):
        load_config(env)


def test_dry_run_allows_missing_secrets():
    settings = load_config({"DRY_RUN": "1"})
    assert settings.dry_run is True
    assert settings.llm_api_key.startswith("dry-run-")


def test_invalid_base_url_scheme():
    with pytest.raises(ConfigError, match="LLM_BASE_URL"):
        load_config(dict(BASE_ENV, LLM_BASE_URL="api.example.com/v1"))


@pytest.mark.parametrize("port", ["abc", "0", "70000"])
def test_invalid_smtp_port(port):
    with pytest.raises(ConfigError, match="SMTP_PORT"):
        load_config(dict(BASE_ENV, SMTP_PORT=port))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1", True), ("true", True), ("YES", True), ("on", True),
     ("0", False), ("false", False), ("no", False), ("", False)],
)
def test_dry_run_parsing(raw, expected):
    settings = load_config(dict(BASE_ENV, DRY_RUN=raw))
    assert settings.dry_run is expected
