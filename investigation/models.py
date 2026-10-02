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
    valid_start: float | None = None
    valid_end: float | None = None

    def claim(self) -> RecordRef:
        return RecordRef(MANUAL_SOURCE, self.link_id)


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
    valid_start: float | None = None
    valid_end: float | None = None

    @staticmethod
    def make_id(effect_id: str, relation: str, cause_id: str,
                valid_start: float | None = None,
                valid_end: float | None = None) -> str:
        window = ""
        if valid_start is not None or valid_end is not None:
            start = "" if valid_start is None else valid_start
            end = "" if valid_end is None else valid_end
            window = f"@[{start},{end}]"
        return f"h:{effect_id}#{relation}<-{cause_id}{window}"

    @property
    def active_claims(self) -> frozenset[RecordRef]:
        return self.claims - self.retracted_claims

    @property
    def is_retracted(self) -> bool:
        return not self.active_claims

    def active_at(self, moment: float | None) -> bool:
        if moment is None:
            return True
        if self.valid_start is not None and moment < self.valid_start:
            return False
        if self.valid_end is not None and moment > self.valid_end:
            return False
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "effect_id": self.effect_id,
            "relation": self.relation,
            "cause_id": self.cause_id,
            "claims": [c.as_dict() for c in sorted(
                self.claims, key=lambda item: (item.source_id, item.record_id))],
            "retracted_claims": [c.as_dict() for c in sorted(
                self.retracted_claims,
                key=lambda item: (item.source_id, item.record_id))],
            "scopes": sorted(self.scopes),
            "confidence": self.confidence,
            "origins": sorted(self.origins),
            "valid_start": self.valid_start,
            "valid_end": self.valid_end,
            "retracted": self.is_retracted,
        }


@dataclass
class PlannedOutcome:
    """One explicitly hypothetical result of a planned check."""

    outcome_id: str
    label: str
    records: tuple[dict[str, Any], ...] = ()
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome_id": self.outcome_id,
            "label": self.label,
            "records": [dict(record) for record in self.records],
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlannedOutcome":
        return cls(
            outcome_id=str(data["outcome_id"]),
            label=str(data.get("label", data["outcome_id"])),
            records=tuple(dict(record) for record in data.get("records", ())),
            note=str(data.get("note", "")),
        )


@dataclass
class PlannedCheck:
    """A relationship/result source that analysts intend to verify."""

    check_id: str
    label: str
    source_id: str
    relation: str
    target: str | None = None
    direction: str = "incoming"
    outcomes: tuple[PlannedOutcome, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "source_id": self.source_id,
            "relation": self.relation,
            "target": self.target,
            "direction": self.direction,
            "outcomes": [outcome.as_dict() for outcome in self.outcomes],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlannedCheck":
        return cls(
            check_id=str(data["check_id"]),
            label=str(data.get("label", data["check_id"])),
            source_id=str(data["source_id"]),
            relation=str(data["relation"]),
            target=data.get("target"),
            direction=str(data.get("direction", "incoming")),
            outcomes=tuple(PlannedOutcome.from_dict(item)
                           for item in data.get("outcomes", ())),
        )


@dataclass
class VerificationPlan:
    """A saved round of planned checks plus the hypotheses then visible."""

    plan_id: str
    checks: tuple[PlannedCheck, ...]
    created_at: float | None
    set_id: str | None
    hypothesis_ids: frozenset[str]
    seeds: tuple[str, ...] = ()
    description: str = ""
    baseline_snapshot: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "checks": [check.as_dict() for check in self.checks],
            "created_at": self.created_at,
            "set_id": self.set_id,
            "hypothesis_ids": sorted(self.hypothesis_ids),
            "seeds": list(self.seeds),
            "description": self.description,
            "baseline_snapshot": self.baseline_snapshot,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationPlan":
        return cls(
            plan_id=str(data["plan_id"]),
            checks=tuple(PlannedCheck.from_dict(item)
                         for item in data.get("checks", ())),
            created_at=data.get("created_at"),
            set_id=data.get("set_id"),
            hypothesis_ids=frozenset(data.get("hypothesis_ids", ())),
            seeds=tuple(data.get("seeds", ())),
            description=str(data.get("description", "")),
            baseline_snapshot=dict(data.get("baseline_snapshot", {})),
        )


@dataclass
class ReceivedBatch:
    """Incoming material held outside accepted evidence until reviewed."""

    batch_id: str
    source_id: str
    records: tuple[dict[str, Any], ...]
    received_at: float | None
    plan_id: str | None = None
    check_id: str | None = None
    outcome_id: str | None = None
    description: str = ""
    status: str = "pending"

    def as_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "source_id": self.source_id,
            "records": [dict(record) for record in self.records],
            "received_at": self.received_at,
            "plan_id": self.plan_id,
            "check_id": self.check_id,
            "outcome_id": self.outcome_id,
            "description": self.description,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReceivedBatch":
        return cls(
            batch_id=str(data["batch_id"]),
            source_id=str(data["source_id"]),
            records=tuple(dict(record) for record in data.get("records", ())),
            received_at=data.get("received_at"),
            plan_id=data.get("plan_id"),
            check_id=data.get("check_id"),
            outcome_id=data.get("outcome_id"),
            description=str(data.get("description", "")),
            status=str(data.get("status", "pending")),
        )


@dataclass
class EvidenceDecision:
    """Audit record for material accepted, rejected, or withdrawn."""

    decision_id: str
    batch_id: str
    source_id: str
    action: str
    recorded_at: float | None
    record_ids: frozenset[str]
    reason: str = ""
    supersedes: frozenset[str] = frozenset()
    excluded_hypotheses: frozenset[str] = frozenset()

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "batch_id": self.batch_id,
            "source_id": self.source_id,
            "action": self.action,
            "recorded_at": self.recorded_at,
            "record_ids": sorted(self.record_ids),
            "reason": self.reason,
            "supersedes": sorted(self.supersedes),
            "excluded_hypotheses": sorted(self.excluded_hypotheses),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceDecision":
        return cls(
            decision_id=str(data["decision_id"]),
            batch_id=str(data["batch_id"]),
            source_id=str(data["source_id"]),
            action=str(data["action"]),
            recorded_at=data.get("recorded_at"),
            record_ids=frozenset(data.get("record_ids", ())),
            reason=str(data.get("reason", "")),
            supersedes=frozenset(data.get("supersedes", ())),
            excluded_hypotheses=frozenset(data.get("excluded_hypotheses", ())),
        )
