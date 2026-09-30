"""Model router: Nemotron Nano for triage, Super for planning,
Ultra for hard or ambiguous cases. Escalates one tier on low confidence
or on failure of the previous attempt. Pure selection logic -- no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Settings

# Below this triage/planning confidence we escalate one tier instead.
CONFIDENCE_THRESHOLD = 0.5

_KINDS = ("triage", "plan", "hard")


@dataclass(frozen=True)
class RouteDecision:
    model: str
    kind: str
    escalated: bool
    reason: str


def _tier_models(settings: Settings) -> tuple[str, str, str]:
    return (settings.model_nano, settings.model_super, settings.model_ultra)


def model_for_kind(settings: Settings, kind: str) -> str:
    """Base model for a task kind. Raises for unknown kinds."""
    if kind == "triage":
        return settings.model_nano
    if kind == "plan":
        return settings.model_super
    if kind == "hard":
        return settings.model_ultra
    raise ValueError(f"Unknown routing kind: {kind!r}"
                     f" (expected one of {_KINDS})")


def tier_of(settings: Settings, model: str) -> int:
    """0=Nano, 1=Super, 2=Ultra. Raises for unconfigured models."""
    try:
        return _tier_models(settings).index(model)
    except ValueError:
        raise ValueError(f"Model not in routing tiers: {model!r}") from None


def escalate(settings: Settings, model: str) -> str | None:
    """Next-tier model after *model*, or None when already at Ultra."""
    tier = tier_of(settings, model)
    models = _tier_models(settings)
    if tier >= len(models) - 1:
        return None
    return models[tier + 1]


def select_model(settings: Settings, kind: str, *,
                 confidence: float | None = None,
                 previous_failure: bool = False) -> RouteDecision:
    """Pick a model, escalating on low confidence or previous failure."""
    base = model_for_kind(settings, kind)
    if previous_failure:
        higher = escalate(settings, base)
        if higher is None:
            return RouteDecision(base, kind, False,
                                 "previous failure but already at Ultra")
        return RouteDecision(higher, kind, True,
                             "escalated after previous failure")
    if confidence is not None and confidence < CONFIDENCE_THRESHOLD:
        higher = escalate(settings, base)
        if higher is None:
            return RouteDecision(base, kind, False,
                                 f"low confidence ({confidence})"
                                 " but already at Ultra")
        return RouteDecision(higher, kind, True,
                             f"escalated on low confidence ({confidence})")
    return RouteDecision(base, kind, False, f"base model for {kind}")


__all__ = [
    "CONFIDENCE_THRESHOLD",
    "RouteDecision",
    "escalate",
    "model_for_kind",
    "select_model",
    "tier_of",
]
