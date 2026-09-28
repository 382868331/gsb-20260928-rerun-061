from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum


class EventKind(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"


class LinkKind(str, Enum):
    PARENT = "parent"
    SUBJECT = "subject"
    OBJECT = "object"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class Source:
    source_id: str
    producer: str = "manual"


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    kind: EventKind
    attributes: dict[str, object] = field(default_factory=dict)
    observed_at: float | None = None
    source_id: str = ""
    record_id: str = ""

    def with_source(self, source_id: str, record_id: str) -> "Event":
        return replace(self, source_id=source_id, record_id=record_id)


@dataclass(frozen=True, slots=True)
class Relation:
    other_id: str
    kind: LinkKind = LinkKind.OTHER
    direction: str = "out"
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.direction not in {"in", "out"}:
            raise ValueError("relation direction must be 'in' or 'out'")
        if not self.other_id:
            raise ValueError("relation other_id is required")


@dataclass(frozen=True, slots=True)
class Link:
    source_event_id: str
    target_event_id: str
    kind: LinkKind
    source_id: str
    record_id: str
    rationale: str = ""
