"""Tests for the model router (Nano/Super/Ultra + escalation)."""

import pytest

from steward.config import load_config
from steward.router import (escalate, model_for_kind, select_model, tier_of)


@pytest.fixture
def settings():
    return load_config({
        "DRY_RUN": "true",
        "MODEL_NANO": "nano",
        "MODEL_SUPER": "super",
        "MODEL_ULTRA": "ultra",
    })


def test_kind_mapping(settings):
    assert model_for_kind(settings, "triage") == "nano"
    assert model_for_kind(settings, "plan") == "super"
    assert model_for_kind(settings, "hard") == "ultra"
    with pytest.raises(ValueError, match="Unknown routing kind"):
        model_for_kind(settings, "fix")


def test_confident_calls_stay_on_base(settings):
    decision = select_model(settings, "triage", confidence=0.9)
    assert (decision.model, decision.escalated) == ("nano", False)
    assert select_model(settings, "plan").model == "super"


def test_low_confidence_escalates_one_tier(settings):
    decision = select_model(settings, "triage", confidence=0.2)
    assert decision.model == "super"
    assert decision.escalated is True
    assert "confidence" in decision.reason
    # Boundary: threshold itself does not escalate.
    assert select_model(settings, "triage",
                        confidence=0.5).escalated is False


def test_failure_escalates(settings):
    decision = select_model(settings, "plan", previous_failure=True)
    assert (decision.model, decision.escalated) == ("ultra", True)
    assert "failure" in decision.reason


def test_top_tier_stays_put(settings):
    decision = select_model(settings, "hard", confidence=0.1)
    assert (decision.model, decision.escalated) == ("ultra", False)
    assert "Ultra" in decision.reason
    decision = select_model(settings, "hard", previous_failure=True)
    assert (decision.model, decision.escalated) == ("ultra", False)


def test_escalate_chain_and_tiers(settings):
    assert tier_of(settings, "nano") == 0
    assert tier_of(settings, "ultra") == 2
    assert escalate(settings, "nano") == "super"
    assert escalate(settings, "super") == "ultra"
    assert escalate(settings, "ultra") is None
    with pytest.raises(ValueError, match="not in routing tiers"):
        tier_of(settings, "gpt-zzz")
