"""OpenAI-compatible LLM client (chat completions) over LLM_BASE_URL.

Stdlib urllib only -- no new dependencies. Every prompt is redacted before
sending (count recorded); Vaultwarden content is refused outright (AGENTS.md:
never send its logs, env, or paths to the LLM). Retries use exponential
backoff, honor Retry-After on 429, and never retry auth/client errors.
Dry-run returns a canned response without touching the network.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .config import Settings
from .redact import redactor_from_settings

# transport(url, headers, payload, timeout) -> (status, headers, body)
Transport = Callable[[str, dict[str, str], dict, float],
                     tuple[int, dict[str, str], bytes]]
Sleeper = Callable[[float], None]


class LLMError(Exception):
    """Base class for all LLM client failures."""


class VaultwardenRefusal(LLMError):
    """Refused: prompt mentions the protected Vaultwarden service."""


class AuthError(LLMError):
    """401/403: bad key or forbidden. Never retried."""


class BadRequestError(LLMError):
    """4xx (other than 429): malformed request or unknown model. No retry."""


class RateLimitError(LLMError):
    """429s persisted through all retries."""


class ServerError(LLMError):
    """5xx / network / malformed responses persisted through all retries."""


@dataclass(frozen=True)
class LLMResponse:
    model: str
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_s: float = 0.0
    redaction_count: int = 0
    attempts: int = 1


def _urllib_transport(url: str, headers: dict[str, str], payload: dict,
                      timeout: float) -> tuple[int, dict[str, str], bytes]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, dict(exc.headers or {}), body
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise ServerError(f"LLM transport failed: {exc}") from exc


def _retry_after(headers: dict[str, str]) -> float | None:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                return max(0.0, float(str(value).strip()))
            except ValueError:
                return None
    return None


def _validate_messages(messages: Sequence[dict]) -> None:
    if not messages:
        raise BadRequestError("No messages provided")
    for message in messages:
        if not isinstance(message, dict) or not isinstance(
                message.get("content"), str):
            raise BadRequestError("Each message needs a string 'content'")


def chat(settings: Settings, messages: Sequence[dict], *,
         model: str | None = None, purpose: str = "",
         timeout: float = 60.0, max_retries: int = 3,
         backoff_base: float = 1.0, backoff_cap: float = 30.0,
         transport: Transport | None = None,
         sleep: Sleeper | None = None) -> LLMResponse:
    """POST one chat completion; retry rate limits and server faults.

    Returns token usage, USD cost (from configured per-1K prices),
    wall latency, redaction count, and attempt count for SQLite logging.
    """
    _validate_messages(messages)
    chosen = model or settings.model_nano
    for message in messages:
        if "vaultwarden" in message["content"].lower():
            raise VaultwardenRefusal(
                "Refusing: prompt references protected service Vaultwarden")

    redactor = redactor_from_settings(settings)
    redacted_messages: list[dict] = []
    redaction_count = 0
    for message in messages:
        result = redactor.redact(message["content"])
        redaction_count += result.count
        redacted_messages.append({**message, "content": result.text})

    started = time.monotonic()
    if settings.dry_run:
        return LLMResponse(
            model=chosen, content="[dry-run] no LLM call made",
            latency_s=time.monotonic() - started,
            redaction_count=redaction_count, attempts=1)

    transport = transport or _urllib_transport
    sleep = sleep or time.sleep
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"}
    payload = {"model": chosen, "messages": redacted_messages}
    if purpose:
        payload["metadata"] = {"purpose": purpose}

    last_error: LLMError = ServerError("LLM call failed")
    attempts = 1 + max(0, max_retries)
    for attempt in range(1, attempts + 1):
        try:
            status, resp_headers, body = transport(url, headers, payload,
                                                   timeout)
        except LLMError as exc:  # network-level failure: back off, retry
            last_error = exc
        else:
            if status == 200:
                try:
                    return _parse_success(
                        body, chosen, settings, redaction_count, attempt,
                        started)
                except LLMError as exc:
                    last_error = exc
            elif status == 429:
                wait = _retry_after(resp_headers)
                last_error = RateLimitError(
                    f"Rate limited (HTTP 429) on attempt {attempt}")
                if attempt < attempts:
                    sleep(_backoff(wait, attempt, backoff_base, backoff_cap))
                    continue
            elif status in (401, 403):
                raise AuthError(f"LLM auth failed (HTTP {status})")
            elif 400 <= status < 500:
                raise BadRequestError(f"LLM rejected request (HTTP {status})")
            else:
                last_error = ServerError(
                    f"LLM server error (HTTP {status}) on attempt {attempt}")
        if attempt < attempts:
            sleep(_backoff(None, attempt, backoff_base, backoff_cap))
    raise last_error


def _backoff(hint: float | None, attempt: int, base: float,
             cap: float) -> float:
    delay = base * (2 ** (attempt - 1))
    if hint is not None:
        delay = max(delay, hint)
    return min(delay, cap)


def _parse_success(body: bytes, model: str, settings: Settings,
                   redaction_count: int, attempt: int,
                   started: float) -> LLMResponse:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise ServerError(f"LLM returned invalid JSON: {exc}") from exc
    try:
        choices = payload["choices"]
        content = choices[0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ServerError(f"LLM response had no content: {exc}") from exc
    if not isinstance(content, str):
        raise ServerError("LLM response content was not a string")
    usage = payload.get("usage") or {}
    prompt = int(usage.get("prompt_tokens", 0) or 0)
    completion = int(usage.get("completion_tokens", 0) or 0)
    total = int(usage.get("total_tokens", 0) or (prompt + completion))
    cost = (prompt / 1000.0 * settings.llm_price_input_per_1k
            + completion / 1000.0 * settings.llm_price_output_per_1k)
    return LLMResponse(
        model=model, content=content, prompt_tokens=prompt,
        completion_tokens=completion, total_tokens=total, cost_usd=cost,
        latency_s=time.monotonic() - started,
        redaction_count=redaction_count, attempts=attempt)


__all__ = [
    "AuthError",
    "BadRequestError",
    "LLMError",
    "LLMResponse",
    "RateLimitError",
    "ServerError",
    "VaultwardenRefusal",
    "chat",
]
