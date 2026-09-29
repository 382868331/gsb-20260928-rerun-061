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

