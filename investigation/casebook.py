"""Append-only archive of saved investigations.

A *finding* freezes the analyst's judgment (chosen hypothesis set and
traced paths) together with the exact evidence then available.  Saving a
new finding never overwrites an earlier one: an old finding can be
reopened exactly as decided, or replayed against the latest evidence to
see what changed.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .store import EdgeHop, InvestigationStore, TraceResult


@dataclass(frozen=True)
class FindingSummary:
    finding_id: str
    title: str
    created_at: float | None
    set_id: str | None
    seeds: tuple[str, ...]


@dataclass
class PathDiff:
    seed: str
    added_upstream: tuple[EdgeHop, ...]
    removed_upstream: tuple[EdgeHop, ...]
    added_downstream: tuple[EdgeHop, ...]
    removed_downstream: tuple[EdgeHop, ...]
    new_unresolved: tuple[str, ...]
    resolved_unresolved: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return any((self.added_upstream, self.removed_upstream,
                    self.added_downstream, self.removed_downstream,
                    self.new_unresolved, self.resolved_unresolved))


@dataclass
class FindingComparison:
    finding_id: str
    path_diffs: list[PathDiff]
    selected_hypotheses_missing: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.selected_hypotheses_missing) or any(
            d.changed for d in self.path_diffs)


@dataclass
class Casebook:
    case_id: str
    findings: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------- writing

    def save_finding(
        self,
        store: InvestigationStore,
        *,
        seeds: list[str] | None = None,
        title: str = "",
        finding_id: str | None = None,
        max_depth: int | None = None,
        note: str = "",
    ) -> str:
        """Freeze evidence + the analyst's current selection and judgment.

        The live store is not mutated.  Findings are append-only: the same
        title never overwrites an earlier judgment.
        """
        set_id = store.active_set
        chosen: set[str] = set()
        if set_id is not None:
            hyp_sets = {h.set_id: h for h in store.hypothesis_sets()}
            chosen = set(hyp_sets[set_id].hypothesis_ids)
        if seeds is None:
            seeds = sorted({state.seed for state in store.saved_paths()
                            if state.set_id == set_id})
        seeds = list(seeds)
        traces: dict[str, TraceResult] = {}
        for seed in seeds:
            traces[seed] = store.trace(seed, max_depth, set_id=set_id,
                                       save=True, refresh=True)
        existing = {f["finding_id"] for f in self.findings}
        if finding_id is None:
            finding_id = f"finding-{len(self.findings) + 1}"
        if finding_id in existing:
            raise ValueError(f"finding {finding_id!r} already exists; "
                             "saved judgments are append-only")
        frozen = {
            "finding_id": finding_id,
            "title": title or finding_id,
            "note": note,
            "created_at": time.time(),
            "set_id": set_id,
            "selected_hypotheses": sorted(chosen),
            "max_depth": max_depth,
            "seeds": seeds,
            "paths": {
                seed: _trace_to_dict(traces[seed]) for seed in seeds
            },
            "store": store.snapshot(),
        }
        self.findings.append(frozen)
        return finding_id

    def summaries(self) -> list[FindingSummary]:
        return [
            FindingSummary(
                finding_id=f["finding_id"], title=f["title"],
                created_at=f.get("created_at"), set_id=f.get("set_id"),
                seeds=tuple(f.get("seeds", ())))
            for f in self.findings
        ]

    def finding(self, finding_id: str) -> dict[str, Any]:
        for frozen in self.findings:
            if frozen["finding_id"] == finding_id:
                return frozen
        raise KeyError(f"unknown finding: {finding_id!r}")

    # ------------------------------------------------------------- reading

    def reopen(self, finding_id: str) -> InvestigationStore:
        """Restore the exact store as it was when the finding was saved."""
        frozen = self.finding(finding_id)
        return InvestigationStore.restore(frozen["store"])

    def frozen_trace(self, finding_id: str, seed: str) -> TraceResult:
        """Reconstruct the trace recorded by the historical judgment."""
        frozen = self.finding(finding_id)
        return _trace_from_dict(frozen["paths"][seed])

    def compare_with_latest(
        self, finding_id: str, latest: InvestigationStore
    ) -> FindingComparison:
        """Diff the old judgment's paths against current evidence.

        The same hypothesis selection is re-applied to the latest store;
        the historical finding itself is left untouched.
        """
        frozen = self.finding(finding_id)
        old_set = frozen.get("set_id")
        set_id = old_set
        latest_sets = {h.set_id: h for h in latest.hypothesis_sets()}
        if old_set is not None and old_set not in latest_sets:
            ids = [h for h in frozen.get("selected_hypotheses", ())
                   if h in {x.hypothesis_id for x in latest.hypotheses()}]
            if ids:
                latest.create_hypothesis_set(
                    f"{old_set}@{finding_id}", ids,
                    description=f"selection carried from {finding_id}",
                    activate=False)
                set_id = f"{old_set}@{finding_id}"
            else:
                set_id = None
        diffs: list[PathDiff] = []
        depth = frozen.get("max_depth")
        for seed in frozen.get("seeds", ()):
            old_result = _trace_from_dict(frozen["paths"][seed])
            try:
                new_result = latest.trace(seed, depth, set_id=set_id)
            except KeyError:
                new_result = TraceResult(seed, [], [], {}, [])
            diffs.append(_diff_paths(old_result, new_result))
        live = {h.hypothesis_id for h in latest.hypotheses(include_retracted=True)}
        missing = tuple(h for h in frozen.get("selected_hypotheses", ())
                        if h not in live)
        return FindingComparison(
            finding_id=finding_id, path_diffs=diffs,
            selected_hypotheses_missing=missing)

    # ---------------------------------------------------------- persistence

    def to_dict(self) -> dict[str, Any]:
        return {"casebook_version": 1, "case_id": self.case_id,
                "findings": self.findings}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Casebook":
        if data.get("casebook_version") != 1:
            raise ValueError("unsupported casebook version")
        return cls(case_id=data["case_id"], findings=list(data["findings"]))

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False,
                                   indent=2, sort_keys=True),
                        encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Casebook":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _hop_key(hop: EdgeHop) -> tuple[str, str, str]:
    return (hop.cause_id, hop.relation, hop.effect_id)


def _diff_paths(old: TraceResult, new: TraceResult) -> PathDiff:
    def split(old_hops, new_hops):
        old_map = {_hop_key(h): h for h in old_hops}
        new_map = {_hop_key(h): h for h in new_hops}
        added = tuple(new_map[k] for k in sorted(set(new_map) - set(old_map)))
        removed = tuple(old_map[k] for k in sorted(set(old_map) - set(new_map)))
        return added, removed

    added_up, removed_up = split(old.upstream, new.upstream)
    added_down, removed_down = split(old.downstream, new.downstream)
    old_pending = {(p.claimant_id, p.relation, p.target) for p in old.unresolved}
    new_pending = {(p.claimant_id, p.relation, p.target) for p in new.unresolved}
    return PathDiff(
        seed=old.origin_id,
        added_upstream=added_up, removed_upstream=removed_up,
        added_downstream=added_down, removed_downstream=removed_down,
        new_unresolved=tuple(sorted(new_pending - old_pending)),
        resolved_unresolved=tuple(sorted(old_pending - new_pending)),
    )


def _trace_to_dict(result: TraceResult) -> dict[str, Any]:
    def hops(items):
        return [{"cause_id": h.cause_id, "effect_id": h.effect_id,
                 "relation": h.relation,
                 "claims": [c.as_dict() for c in h.claims]} for h in items]
    return {
        "origin_id": result.origin_id,
        "upstream": hops(result.upstream),
        "downstream": hops(result.downstream),
        "events": sorted(result.events),
        "unresolved": [
            {"claimant_id": p.claimant_id, "relation": p.relation,
             "direction": p.direction, "target": p.target,
             "claim": p.claim.as_dict()}
            for p in result.unresolved],
    }


def _trace_from_dict(data: dict[str, Any]) -> TraceResult:
    from .models import PendingRef, RecordRef as _Ref

    def hops(items):
        return [EdgeHop(
            cause_id=h["cause_id"], effect_id=h["effect_id"],
            relation=h["relation"],
            claims=tuple(_Ref(c["source_id"], c["record_id"])
                         for c in h["claims"]))
            for h in items]
    unresolved = [
        PendingRef(
            claimant_id=p["claimant_id"], relation=p["relation"],
            direction=p["direction"], target=p["target"],
            claim=_Ref(p["claim"]["source_id"], p["claim"]["record_id"]))
        for p in data.get("unresolved", ())]
    return TraceResult(
        origin_id=data["origin_id"],
        upstream=hops(data.get("upstream", [])),
        downstream=hops(data.get("downstream", [])),
        events={}, unresolved=unresolved)
