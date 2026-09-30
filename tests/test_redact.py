"""Tests for the redaction layer, including tricky near-miss cases."""

import pytest

from steward.config import load_config
from steward.redact import (Redactor, redact, redact_counted,
                            redactor_from_settings)


def test_ipv4_and_ports():
    out = redact("db at 10.0.0.5:5432 ok")
    assert "10.0.0.5" not in out
    assert ":5432" in out  # port is not sensitive


def test_ipv4_looks_like_version_spared():
    assert redact("agent 1.2.3.4.5 released") == "agent 1.2.3.4.5 released"
    assert redact("htmx 2.0.4 loaded") == "htmx 2.0.4 loaded"


def test_ipv6_forms():
    for addr in ("2001:db8::1", "::1", "fe80::1", "::ffff:10.0.0.1",
                 "2001:0db8:85a3:0000:0000:8a2e:0370:7334"):
        out = redact(f"ping {addr}")
        assert addr not in out, addr
        assert "[redacted ip]" in out


def test_clock_time_spared():
    assert redact("meeting at 12:30:45") == "meeting at 12:30:45"


def test_mac_redacted_as_mac():
    out = redact("nic aa:bb:cc:dd:ee:ff up")
    assert "aa:bb:cc:dd:ee:ff" not in out
    assert "[redacted mac]" in out


def test_hostnames_and_tailscale():
    out = redact("mount nas.home and pi.tail1234.ts.net:8080")
    assert "nas.home" not in out
    assert "pi.tail1234.ts.net:8080" not in out
    assert out.count("[redacted host]") == 2


def test_public_domains_out_of_scope():
    # Only private/tailnet suffixes are treated as hostnames.
    assert redact("see https://example.com/docs") == \
        "see https://example.com/docs"


def test_emails_fully_consumed():
    out = redact("mail admin@mail.home please")
    assert "admin@mail.home" not in out
    assert "@mail.home" not in out
    assert "[redacted email]" in out


def test_secrets_key_value_and_json():
    out = redact('login token=abc123 password="s3cret phrase" done')
    assert "abc123" not in out and "s3cret" not in out
    out = redact('{"password": "my secret", "ok": true}')
    assert "my secret" not in out
    assert '"password": "[redacted]"' in out


def test_bearer_and_provider_keys_and_jwt():
    out = redact("auth Bearer xyz789.abc")
    assert "xyz789" not in out and out.startswith("auth bearer [redacted]")
    out = redact("key sk-abcDEF1234567890 end")
    assert "sk-abcDEF1234567890" not in out
    assert "[redacted token]" in out
    out = redact("aws AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
    assert redact(f"tok {jwt}").endswith("[redacted token]")


def test_pem_and_url_userinfo():
    out = redact("https://user:pass@host/x")
    assert "user:pass@" not in out
    assert "[redacted credentials]@host/x" in out
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"
    assert redact(pem) == "[redacted private-key]"


def test_allow_shields_and_wins_conflicts():
    fingerprint = "a" * 64  # would otherwise match long-hex
    out = redact(f"build {fingerprint} ok", allow=(fingerprint,))
    assert fingerprint in out
    # Same literal in both lists: allow wins.
    out = redact("mynas is here", allow=("mynas",), deny=("mynas",))
    assert "mynas" in out


def test_deny_case_insensitive_paths():
    out = redact("read /etc/Vaultwarden/config.json", deny=("vaultwarden",))
    assert "Vaultwarden" not in out
    assert "/etc/[redacted]/config.json" in out


def test_counts_and_empty():
    result = redact_counted("a@b.com from 10.0.0.1")
    assert result.text.count("[redacted") == 2
    assert result.count == 2
    assert redact_counted("").count == 0
    assert redact("") == ""


def test_redactor_from_settings():
    settings = load_config({"DRY_RUN": "true",
                            "REDACT_ALLOW": "jellyfin",
                            "REDACT_DENY": "vaultwarden, mynas"})
    redactor = redactor_from_settings(settings)
    assert isinstance(redactor, Redactor)
    out = redactor.redact("jellyfin on mynas at 10.0.0.2").text
    assert "jellyfin" in out
    assert "mynas" not in out and "10.0.0.2" not in out
