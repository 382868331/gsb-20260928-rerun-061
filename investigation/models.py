from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventKind(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"

    @classmethod
    def coerce(cls, value: str | "EventKind") -> "EventKind":
        if isinstance(value, EventKind):
            return value
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(f"unknown event kind: {value!r}") from exc


@dataclass(frozen=True)
class RecordRef:
    """Pointer to the record that asserted a piece of evidence."""

    source_id: str
    record_id: str

    def as_dict(self) -> dict[str, str]:
        return {"source_id": self.source_id, "record_id": self.record_id}


@dataclass
class Source:
    """One import batch: a feed, a collector export, a hand-written note."""

    source_id: str
    description: str = ""
    imported_at: float | None = None
    record_ids: set[str] = field(default_factory=set)
    trust: float | None = None
    scopes: tuple[str, ...] = ()


@dataclass
class Event:
    event_id: str
    kind: EventKind
    ts: float | None
    attrs: dict[str, Any]
    aliases: set[str] = field(default_factory=set)
    claims: set[RecordRef] = field(default_factory=set)

    def identity(self) -> str:
        return self.event_id


@dataclass(frozen=True)
class Edge:
    """A directed causal link: cause -> effect.

    Every edge exists only because at least one record explicitly asserted
    it. ``claims`` records exactly which import records made the assertion,
    so every link on a trace can be explained.
    """

    cause_id: str
    effect_id: str
    relation: str
    claims: frozenset[RecordRef]

    def key(self) -> tuple[str, str, str]:
        return (self.cause_id, self.effect_id, self.relation)


@dataclass(frozen=True)
class PendingRef:
    """An explicit reference whose target event has not arrived yet."""

    claimant_id: str
    relation: str
    direction: str  # "incoming" (target -> claimant) or "outgoing" (claimant -> target)
    target: str
    claim: RecordRef


@dataclass(frozen=True)
class ManualLink:
    """An analyst-asserted causal link, revocable independently of sources."""

    link_id: str
    cause: str
    effect: str
    relation: str
    note: str = ""
    confidence: float = 0.5
    scopes: tuple[str, ...] = ("manual",)
    retracts: tuple[RecordRef, ...] = ()
    created_at: float | None = None
    valid_from: float | None = None
    valid_to: float | None = None

    def claim(self) -> RecordRef:
        return RecordRef(MANUAL_SOURCE, self.link_id)

    def applies_at(self, ts: float | None) -> bool:
        """Whether this judgment holds at one moment in time.

        A time-bounded judgment is local to its window: it must never be
        generalized to the object's whole history.  An unknown timestamp
        cannot be excluded, so the judgment applies.
        """
        if ts is None:
            return True
        if self.valid_from is not None and ts < self.valid_from:
            return False
        if self.valid_to is not None and ts > self.valid_to:
            return False
        return True


MANUAL_SOURCE = "manual"


@dataclass
class Hypothesis:
    """One candidate causal explanation for one (effect, relation) slot.

    Conflicting sources produce distinct Hypothesis objects in the same
    conflict group; every claim (including retracted ones) is retained so
    that each explanation keeps its evidence and its trust scope.
    """

    hypothesis_id: str
    effect_id: str
    relation: str
    cause_id: str
    claims: frozenset[RecordRef]
    retracted_claims: frozenset[RecordRef] = frozenset()
    scopes: frozenset[str] = frozenset()
    confidence: float = 0.5
    origins: frozenset[str] = frozenset()

    @staticmethod
    def make_id(effect_id: str, relation: str, cause_id: str) -> str:
        return f"h:{effect_id}#{relation}<-{cause_id}"

    @property
    def active_claims(self) -> frozenset[RecordRef]:
        return self.claims - self.retracted_claims

    @property
    def is_retracted(self) -> bool:
        return not self.active_claims

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "effect_id": self.effect_id,
            "relation": self.relation,
            "cause_id": self.cause_id,
            "claims": [c.as_dict() for c in sorted(self.claims)],
            "retracted_claims": [c.as_dict() for c in sorted(self.retracted_claims)],
            "scopes": sorted(self.scopes),
            "confidence": self.confidence,
            "origins": sorted(self.origins),
            "retracted": self.is_retracted,
        }
