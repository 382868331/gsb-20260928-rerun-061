from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Hypothesis, RecordRef
from .store import TraceResult


@dataclass(frozen=True)
class PlannedOutcome:
    outcome_id: str
    cause_id: str | None = None
    retracts: tuple[RecordRef, ...] = ()
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome_id": self.outcome_id,
            "cause_id": self.cause_id,
            "retracts": [r.as_dict() for r in sorted(self.retracts)],
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlannedOutcome":
        return cls(
            outcome_id=str(data["outcome_id"]),
            cause_id=data.get("cause_id"),
            retracts=tuple(RecordRef(str(r["source_id"]), str(r["record_id"]))
                           for r in data.get("retracts", ())),
            note=data.get("note", ""),
        )


@dataclass(frozen=True)
class PlannedCheck:
    check_id: str
    effect_id: str
    relation: str
    source_id: str
    record_id: str
    outcomes: tuple[PlannedOutcome, ...]
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "effect_id": self.effect_id,
            "relation": self.relation,
            "source_id": self.source_id,
            "record_id": self.record_id,
            "outcomes": [o.as_dict() for o in self.outcomes],
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlannedCheck":
        return cls(
            check_id=str(data["check_id"]),
            effect_id=str(data["effect_id"]),
            relation=str(data["relation"]),
            source_id=str(data["source_id"]),
            record_id=str(data["record_id"]),
            outcomes=tuple(PlannedOutcome.from_dict(o)
                           for o in data.get("outcomes", ())),
            note=data.get("note", ""),
        )


@dataclass
class OutcomePreview:
    plan_id: str
    check_id: str
    outcome_id: str
    supported_hypothesis_ids: tuple[str, ...]
    excluded_hypothesis_ids: tuple[str, ...]
    retained_paths: tuple[TraceResult, ...]
    indistinguishable_groups: tuple[tuple[str, ...], ...]
    evidence_claim: RecordRef | None
    shared_source_plan_ids: tuple[str, ...] = ()
    duplicate_check_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "check_id": self.check_id,
            "outcome_id": self.outcome_id,
            "supported_hypothesis_ids": list(self.supported_hypothesis_ids),
            "excluded_hypothesis_ids": list(self.excluded_hypothesis_ids),
            "retained_paths": [_trace_to_dict(path) for path in self.retained_paths],
            "indistinguishable_groups": [list(group)
                                        for group in self.indistinguishable_groups],
            "evidence_claim": self.evidence_claim.as_dict() if self.evidence_claim else None,
            "shared_source_plan_ids": list(self.shared_source_plan_ids),
            "duplicate_check_ids": list(self.duplicate_check_ids),
        }


@dataclass
class VerificationPlan:
    plan_id: str
    checks: tuple[PlannedCheck, ...]
    seeds: tuple[str, ...]
    baseline_set_id: str | None
    description: str
    created_at: float | None
    hypothesis_snapshot: tuple[Hypothesis, ...]
    previews: tuple[OutcomePreview, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "checks": [check.as_dict() for check in self.checks],
            "seeds": list(self.seeds),
            "baseline_set_id": self.baseline_set_id,
            "description": self.description,
            "created_at": self.created_at,
            "hypothesis_snapshot": [h.as_dict() for h in self.hypothesis_snapshot],
            "previews": [preview.as_dict() for preview in self.previews],
        }


@dataclass
class VerificationMaterial:
    material_id: str
    plan_id: str
    check_id: str
    claimed_outcome_id: str | None
    source_id: str
    record_id: str
    record: dict[str, Any]
    status: str = "staged"
    contradictions: tuple[str, ...] = ()
    duplicate_material_ids: tuple[str, ...] = ()
    shared_source_plan_ids: tuple[str, ...] = ()
    received_at: float | None = None

    @property
    def claim(self) -> RecordRef:
        return RecordRef(self.source_id, self.record_id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "material_id": self.material_id,
            "plan_id": self.plan_id,
            "check_id": self.check_id,
            "claimed_outcome_id": self.claimed_outcome_id,
            "source_id": self.source_id,
            "record_id": self.record_id,
            "record": dict(self.record),
            "status": self.status,
            "contradictions": list(self.contradictions),
            "duplicate_material_ids": list(self.duplicate_material_ids),
            "shared_source_plan_ids": list(self.shared_source_plan_ids),
            "received_at": self.received_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationMaterial":
        return cls(
            material_id=str(data["material_id"]),
            plan_id=str(data["plan_id"]),
            check_id=str(data["check_id"]),
            claimed_outcome_id=data.get("claimed_outcome_id"),
            source_id=str(data["source_id"]),
            record_id=str(data["record_id"]),
            record=dict(data.get("record", {})),
            status=data.get("status", "staged"),
            contradictions=tuple(data.get("contradictions", ())),
            duplicate_material_ids=tuple(data.get("duplicate_material_ids", ())),
            shared_source_plan_ids=tuple(data.get("shared_source_plan_ids", ())),
            received_at=data.get("received_at"),
        )


@dataclass
class VerificationDecision:
    material_id: str
    action: str
    recorded_at: float | None
    plan_id: str
    check_id: str
    outcome_id: str | None
    claim: RecordRef | None
    reason: str = ""
    excluded_hypothesis_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "material_id": self.material_id,
            "action": self.action,
            "recorded_at": self.recorded_at,
            "plan_id": self.plan_id,
            "check_id": self.check_id,
            "outcome_id": self.outcome_id,
            "claim": self.claim.as_dict() if self.claim else None,
            "reason": self.reason,
            "excluded_hypothesis_ids": list(self.excluded_hypothesis_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationDecision":
        claim = data.get("claim")
        return cls(
            material_id=str(data["material_id"]),
            action=str(data["action"]),
            recorded_at=data.get("recorded_at"),
            plan_id=str(data["plan_id"]),
            check_id=str(data["check_id"]),
            outcome_id=data.get("outcome_id"),
            claim=RecordRef(str(claim["source_id"]), str(claim["record_id"]))
            if claim else None,
            reason=data.get("reason", ""),
            excluded_hypothesis_ids=tuple(data.get("excluded_hypothesis_ids", ())),
        )


def _trace_to_dict(result: TraceResult) -> dict[str, Any]:
    def hops(items):
        return [{"cause_id": hop.cause_id, "effect_id": hop.effect_id,
                 "relation": hop.relation,
                 "claims": [claim.as_dict() for claim in hop.claims]}
                for hop in items]

    return {
        "origin_id": result.origin_id,
        "upstream": hops(result.upstream),
        "downstream": hops(result.downstream),
        "events": sorted(result.events),
        "unresolved": [
            {"claimant_id": ref.claimant_id, "relation": ref.relation,
             "direction": ref.direction, "target": ref.target,
             "claim": ref.claim.as_dict()}
            for ref in result.unresolved],
    }
