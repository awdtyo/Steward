"""Redaction layer.

AGENTS.md: every string sent to the LLM, shown on the dashboard, or mailed
must pass through here. Covers IPv4/IPv6, hostnames (incl. Tailscale
*.ts.net names), emails, tokens/API keys, and secrets. Log content is
untrusted input -- redact it, never act on it.

Configurable per call (or via REDACT_ALLOW / REDACT_DENY env lists):
- allow: literal strings that must survive even if pattern-matched.
- deny: literal strings that are always redacted (e.g. peer short names,
  protected service names such as vaultwarden).
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from functools import lru_cache

_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
# https://user:pass@host/... -> userinfo must not leak.
_URL_USERINFO = re.compile(r"(?<=://)[^/\s?#]*@")
# key=value / key: value secrets, incl. quoted values with spaces.
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|auth[_-]?token)\b"
    r"\s*[:=]\s*(\"[^\"]*\"|'[^']*'|\S+)"
)
# {"password": "my secret"} JSON style.
_JSON_SECRET = re.compile(
    r"(?i)\"(api[_-]?key|token|secret|password|passwd|pwd|auth[_-]?token)\""
    r"\s*:\s*\"[^\"]*\""
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Dotted quads only when not part of a longer dotted run (spares 1.2.3.4.5).
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# MACs before IPv6: aa:bb:cc:dd:ee:ff would otherwise match as IPv6.
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
# IPv6: '::' forms (::1, fe80::1, ::ffff:10.0.0.1) or 3+ colon groups.
# Deliberately spares clock times such as 12:30:45.
_IPV6 = re.compile(
    r"(?<![0-9A-Za-z:.])[0-9A-Za-z:.]*::[0-9A-Za-z:.]+(?![0-9A-Za-z:.])"
    r"|\b(?:[0-9A-Fa-f]{0,4}:){3,}[0-9A-Fa-f:.]+\b"
)
# Multi-label hostnames on private/tailnet suffixes, e.g. nas.home,
# pi.tail1234.ts.net, host:port included.
_HOSTNAME = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:local|lan|home|internal|localhost|ts\.net)\b(?::\d+)?"
)
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")

# (pattern, replacement-or-callable) applied in order.
_PATTERNS: tuple[tuple[re.Pattern[str], object], ...] = (
    (_PEM, "[redacted private-key]"),
    (_URL_USERINFO, "[redacted credentials]@"),
    (_JSON_SECRET, lambda m: m.group(0).split(":", 1)[0] + ': "[redacted]"'),
    (_SECRET_ASSIGN, lambda m: m.group(0).split(":", 1)[0].split("=", 1)[0]
     + "=[redacted]"),
    (_BEARER, "bearer [redacted]"),
    (_OPENAI_KEY, "[redacted token]"),
    (_AWS_KEY, "[redacted token]"),
    (_JWT, "[redacted token]"),
    (_EMAIL, "[redacted email]"),
    (_MAC, "[redacted mac]"),
    (_IPV6, "[redacted ip]"),
    (_IPV4, "[redacted ip]"),
    (_HOSTNAME, "[redacted host]"),
    (_LONG_HEX, "[redacted token]"),
)


@lru_cache(maxsize=1)
def _local_hostname() -> str:
    try:
        return socket.gethostname().strip()
    except OSError:
        return ""


@dataclass(frozen=True)
class Redacted:
    text: str
    count: int  # total replacements made


@dataclass(frozen=True)
class Redactor:
    """Regex redactor with literal allow/deny overrides.

    Allow entries are shielded from every pattern; deny entries are
    redacted last (case-insensitive), so they also catch plain names and
    paths no pattern covers. On allow/deny conflict, allow wins.
    """

    deny: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()

    def redact(self, text: str) -> Redacted:
        if not text:
            return Redacted(text, 0)
        shields = {f"\x00ALLOW{i}\x00": entry
                   for i, entry in enumerate(self.allow) if entry}
        out = text
        for sentinel, entry in shields.items():
            out = out.replace(entry, sentinel)
        count = 0
        for pattern, replacement in _PATTERNS:
            out, n = pattern.subn(replacement, out)  # type: ignore[arg-type]
            count += n
        host = _local_hostname()
        if host and host != "localhost":
            out, n = re.compile(r"\b" + re.escape(host) + r"\b",
                                re.IGNORECASE).subn("[redacted host]", out)
            count += n
        if self.deny:
            deny_pattern = re.compile(
                "|".join(re.escape(d) for d in self.deny if d),
                re.IGNORECASE)
            out, n = deny_pattern.subn("[redacted]", out)
            count += n
        for sentinel, entry in shields.items():
            out = out.replace(sentinel, entry)
        return Redacted(out, count)


_DEFAULT_REDACTOR = Redactor()


def redact(text: str, *, deny: tuple[str, ...] = (),
           allow: tuple[str, ...] = ()) -> str:
    """Redact *text*; returns the scrubbed string (count discarded)."""
    if not deny and not allow:
        return _DEFAULT_REDACTOR.redact(text).text
    return Redactor(deny=deny, allow=allow).redact(text).text


def redact_counted(text: str, *, deny: tuple[str, ...] = (),
                   allow: tuple[str, ...] = ()) -> Redacted:
    """Redact *text*; returns text plus the replacement count."""
    if not deny and not allow:
        return _DEFAULT_REDACTOR.redact(text)
    return Redactor(deny=deny, allow=allow).redact(text)


def redactor_from_settings(settings) -> Redactor:
    """Build a Redactor from REDACT_ALLOW / REDACT_DENY settings."""
    return Redactor(deny=tuple(settings.redact_deny),
                    allow=tuple(settings.redact_allow))


__all__ = ["Redacted", "Redactor", "redact", "redact_counted",
           "redactor_from_settings"]
