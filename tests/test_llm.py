"""Tests for the OpenAI-compatible LLM client and call logging."""

import json

import pytest

from steward import store
from steward.config import load_config
from steward.llm import (AuthError, BadRequestError, LLMResponse,
                         RateLimitError, ServerError, VaultwardenRefusal,
                         chat)


def make_settings(**over):
    env = {"DRY_RUN": "false",
           "LLM_BASE_URL": "https://llm.example.com/v1",
           "LLM_API_KEY": "test-key",
           "MODEL_NANO": "nano",
           "MODEL_SUPER": "super",
           "MODEL_ULTRA": "ultra",
           "LLM_PRICE_INPUT_PER_1K": "0.01",
           "LLM_PRICE_OUTPUT_PER_1K": "0.03"}
    env.update(over)
    return load_config(env)


def ok_body(content="hello", prompt=1000, completion=500):
    return json.dumps({
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion,
                  "total_tokens": prompt + completion},
    }).encode()


class FakeTransport:
    """Queued (status, headers, body) replies; records calls and payloads."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.payloads = []

    def __call__(self, url, headers, payload, timeout):
        self.calls.append((url, dict(headers), timeout))
        self.payloads.append(payload)
        status, resp_headers, body = self.replies[min(
            len(self.calls) - 1, len(self.replies) - 1)]
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        return status, resp_headers, body


@pytest.fixture
def sleeper():
    sleeps = []
    return sleeps, sleeps.append


def test_success_usage_cost_and_redaction(sleeper):
    sleeps, sleep = sleeper
    transport = FakeTransport([(200, {}, ok_body())])
    resp = chat(make_settings(),
                [{"role": "user", "content": "disk at 10.0.0.9 full"}],
                sleep=sleep, transport=transport)
    assert isinstance(resp, LLMResponse)
    assert resp.content == "hello"
    assert (resp.prompt_tokens, resp.completion_tokens,
            resp.total_tokens) == (1000, 500, 1500)
    assert resp.cost_usd == pytest.approx(0.01 + 0.015)
    assert resp.attempts == 1 and sleeps == []
    assert resp.redaction_count == 1
    assert resp.latency_s >= 0
    # The wire payload carries the redacted prompt, never the raw IP.
    sent = transport.payloads[0]["messages"][0]["content"]
    assert "10.0.0.9" not in sent
    assert transport.calls[0][0] == \
        "https://llm.example.com/v1/chat/completions"


def test_retry_then_success_backoff(sleeper):
    sleeps, sleep = sleeper
    transport = FakeTransport([(500, {}, b"boom"), (200, {}, ok_body())])
    resp = chat(make_settings(), [{"role": "user", "content": "hi"}],
                sleep=sleep, transport=transport)
    assert resp.attempts == 2
    assert sleeps == [1.0]


def test_backoff_grows_exponentially(sleeper):
    sleeps, sleep = sleeper
    transport = FakeTransport([(500, {}, b"x"), (502, {}, b"y"),
                               (200, {}, ok_body())])
    chat(make_settings(), [{"role": "user", "content": "hi"}],
         sleep=sleep, transport=transport)
    assert sleeps == [1.0, 2.0]


def test_rate_limit_honors_retry_after(sleeper):
    sleeps, sleep = sleeper
    transport = FakeTransport([(429, {"Retry-After": "5"}, b"slow"),
                               (200, {}, ok_body())])
    resp = chat(make_settings(), [{"role": "user", "content": "hi"}],
                sleep=sleep, transport=transport)
    assert resp.attempts == 2
    assert sleeps == [5.0]


def test_rate_limit_exhausted(sleeper):
    sleeps, sleep = sleeper
    transport = FakeTransport([(429, {}, b"slow")] * 5)
    with pytest.raises(RateLimitError):
        chat(make_settings(), [{"role": "user", "content": "hi"}],
             max_retries=2, sleep=sleep, transport=transport)
    assert len(transport.calls) == 3
    assert sleeps == [1.0, 2.0]


def test_auth_and_bad_request_do_not_retry(sleeper):
    sleeps, sleep = sleeper
    for status, exc in ((401, AuthError), (403, AuthError), (400,
                                                             BadRequestError)):
        transport = FakeTransport([(status, {}, b"no")])
        with pytest.raises(exc):
            chat(make_settings(), [{"role": "user", "content": "hi"}],
                 sleep=sleep, transport=transport)
        assert len(transport.calls) == 1
    assert sleeps == []


def test_server_errors_exhaust_then_raise(sleeper):
    sleeps, sleep = sleeper
    transport = FakeTransport([(500, {}, b"bad")] * 5)
    with pytest.raises(ServerError):
        chat(make_settings(), [{"role": "user", "content": "hi"}],
             max_retries=1, sleep=sleep, transport=transport)
    assert len(transport.calls) == 2
    assert sleeps == [1.0]


def test_malformed_and_empty_responses(sleeper):
    _, sleep = sleeper
    transport = FakeTransport([(200, {}, b"not json")])
    with pytest.raises(ServerError):
        chat(make_settings(), [{"role": "user", "content": "hi"}],
             max_retries=0, sleep=sleep, transport=transport)
    transport = FakeTransport([(200, {}, {"choices": []})])
    with pytest.raises(ServerError):
        chat(make_settings(), [{"role": "user", "content": "hi"}],
             max_retries=0, sleep=sleep, transport=transport)


def test_missing_usage_defaults_to_zero(sleeper):
    _, sleep = sleeper
    body = json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()
    transport = FakeTransport([(200, {}, body)])
    resp = chat(make_settings(), [{"role": "user", "content": "hi"}],
                sleep=sleep, transport=transport)
    assert (resp.prompt_tokens, resp.total_tokens,
            resp.cost_usd) == (0, 0, 0.0)


def test_dry_run_makes_no_network_call():
    def explode(*args):
        raise AssertionError("transport must not be called")

    resp = chat(load_config({"DRY_RUN": "true"}),
                [{"role": "user", "content": "hi"}],
                transport=explode)
    assert resp.content.startswith("[dry-run]")
    assert resp.attempts == 1


def test_vaultwarden_content_refused():
    def explode(*args):
        raise AssertionError("transport must not be called")

    with pytest.raises(VaultwardenRefusal):
        chat(make_settings(),
             [{"role": "user",
               "content": "summarize VAULTWARDEN logs at /etc/vaultwarden"}],
             transport=explode)


def test_empty_messages_rejected(sleeper):
    _, sleep = sleeper
    with pytest.raises(BadRequestError):
        chat(make_settings(), [], sleep=sleep,
             transport=FakeTransport([]))


def test_call_logging_and_totals():
    conn = store.init_db(":memory:")
    store.log_llm_call(conn, purpose="triage", model="nano",
                       prompt_tokens=100, completion_tokens=50,
                       total_tokens=150, cost_usd=0.002, latency_s=1.5,
                       redaction_count=2, attempts=1, ok=True)
    store.log_llm_call(conn, purpose="plan", model="super",
                       prompt_tokens=200, completion_tokens=0,
                       total_tokens=200, cost_usd=0.004, latency_s=3.0,
                       redaction_count=0, attempts=3, ok=False,
                       error="boom")
    totals = store.llm_usage_totals(conn)
    assert totals["calls"] == 2
    assert totals["prompt_tokens"] == 300
    assert totals["completion_tokens"] == 50
    assert totals["total_tokens"] == 350
    assert totals["cost_usd"] == pytest.approx(0.006)
    row = conn.execute("SELECT * FROM llm_calls WHERE model='super'").fetchone()
    assert row["ok"] == 0 and row["error"] == "boom"
    conn.close()
