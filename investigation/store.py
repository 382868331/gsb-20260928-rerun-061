from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import (
    CausalHypothesis,
    Edge,
    Event,
    EventKind,
    Evidence,
    PendingRef,
    RecordRef,
    Source,
)


class ImportError(ValueError):
    pass


@dataclass(frozen=True)
class EdgeHop:
    cause_id: str
    effect_id: str
    relation: str
    claims: tuple[RecordRef, ...]
    hypothesis_id: str
    confidence_range: tuple[float, float]


@dataclass
class TraceResult:
    origin_id: str
    upstream: list[EdgeHop]
    downstream: list[EdgeHop]
    events: dict[str, Event]
    unresolved: list[PendingRef]
    hypothesis_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationRecord:
    investigation_id: str
    seed: str
    title: str
    created_at: float
    closed_at: float | None
    judgment: str
    selected_hypothesis_ids: tuple[str, ...]
    hypotheses: tuple[CausalHypothesis, ...]
    trace_keys: tuple[tuple[str, str, str], ...]
    latest_trace_keys: tuple[tuple[str, str, str], ...] = field(default=())
    status: str = "current"

@dataclass(frozen=True)
class InvestigationComparison:
    investigation_id: str
    still_current: tuple[str, ...]
    missing: tuple[str, ...]
    contradicted: tuple[str, ...]
    new_alternatives: tuple[str, ...]


class InvestigationStore:
    """In-memory evidence graph, rebuilt deterministically from raw records.

    The store keeps imported *records* as the source of truth.  Events,
    aliases, edges and pending references are all derived state, rebuilt
    after every import/revoke.  That replay makes revocation idempotent and
    guarantees that removing a source leaves no orphan events or
    "ghost" edges behind.
    """

    def __init__(self) -> None:
        self._sources: dict[str, Source] = {}
        # source_id -> record_id -> raw record dict
        self._records: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        # Derived state (rebuilt by _rebuild).
        self._events: dict[str, Event] = {}
        self._alias_index: dict[str, str] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}
        self._pending: dict[tuple[str, str, str, str, str, str], PendingRef] = {}
        self._hypotheses: dict[str, CausalHypothesis] = {}
        self._hypothesis_by_edge: dict[tuple[str, str, str], str] = {}
        self._selected_hypotheses: set[str] = set()
        self._investigations: dict[str, InvestigationRecord] = {}

    # ---------------------------------------------------------------- import

    def import_source(
        self,
        source_id: str,
        records: Iterable[dict[str, Any]],
        description: str = "",
        imported_at: float | None = None,
    ) -> int:
        """Import (or fully replace) one source's record batch.

        Re-importing the same source replaces the previous batch instead of
        duplicating it.  Importing identical records twice is a no-op.
        """
        if not source_id or not isinstance(source_id, str):
            raise ImportError("source_id must be a non-empty string")
        batch: dict[str, dict[str, Any]] = {}
        for record in records:
            normalized = self._normalize_record(source_id, record)
            record_id = normalized["record_id"]
            if record_id in batch:
                raise ImportError(
                    f"duplicate record_id {record_id!r} within source {source_id!r}"
                )
            batch[record_id] = normalized
        self._sources[source_id] = Source(
            source_id=source_id,
            description=description,
            imported_at=imported_at if imported_at is not None else time.time(),
            record_ids=set(batch),
        )
        self._records[source_id] = batch
        self._rebuild()
        return len(batch)

    def add_manual_link(
        self,
        cause: str,
        effect: str,
        relation: str,
        *,
        record_id: str | None = None,
        note: str = "manual analyst association",
        confidence_low: float = 0.0,
        confidence_high: float = 1.0,
    ) -> str:
        """Add a revocable manual causal assertion without joining identities."""
        if self.get_event(cause) is None:
            raise KeyError(f"unknown cause event or alias: {cause!r}")
        if self.get_event(effect) is None:
            raise KeyError(f"unknown effect event or alias: {effect!r}")
        source_id = "manual"
        cause_id = self.get_event(cause).event_id
        effect_id = self.get_event(effect).event_id
        if cause_id == effect_id:
            raise ValueError("cause and effect must be different events")
        record_id = record_id or f"{relation}:{cause_id}:{effect_id}"
        batch = dict(self._records.get(source_id, {}))
        record = {
            "record_id": record_id,
            "kind": None,
            "event_id": cause_id,
            "manual": True,
            "note": note,
            "refs": [{
                "relation": relation,
                "target": effect_id,
                "direction": "outgoing",
                "confidence_low": confidence_low,
                "confidence_high": confidence_high,
                "note": note,
            }],
        }
        batch[record_id] = self._normalize_record(source_id, record)
        self._records[source_id] = batch
        self._sources.setdefault(source_id, Source(
            source_id=source_id,
            description="Analyst-authored associations",
            imported_at=time.time(),
            record_ids=set(batch),
        )).record_ids = set(batch)
        self._rebuild()
        return record_id

    def revoke_manual_link(self, record_id: str) -> bool:
        """Revoke one analyst assertion while retaining other manual links."""
        batch = self._records.get("manual")
        if batch is None or record_id not in batch:
            return False
        del batch[record_id]
        self._sources["manual"].record_ids = set(batch)
        if not batch:
            del self._records["manual"]
            del self._sources["manual"]
        self._rebuild()
        return True

    def revoke_source(self, source_id: str) -> bool:
        """Remove a whole source and every evidence item it alone asserted."""
        if source_id not in self._records:
            return False
        del self._records[source_id]
        del self._sources[source_id]
        self._rebuild()
        return True

    def sources(self) -> list[Source]:
        return [self._sources[key] for key in sorted(self._sources)]

    def _normalize_record(
        self, source_id: str, record: dict[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ImportError(f"record in source {source_id!r} must be a dict")
        record_id = record.get("record_id")
        if not record_id:
            raise ImportError(f"record in source {source_id!r} is missing record_id")
        kind = record.get("kind")
        out = dict(record)
        out["record_id"] = str(record_id)
        out["kind"] = EventKind.coerce(kind) if kind is not None else None
        out["source_id"] = source_id
        if "event_id" not in out or not out["event_id"]:
            out["event_id"] = f"{source_id}:{out['record_id']}"
        return out

    # ---------------------------------------------------------------- rebuild

    def _rebuild(self) -> None:
        old_signatures = {
            key: self._hypotheses[hid].evidence
            for key, hid in self._hypothesis_by_edge.items()
        }
        # 1. Aggregate events across sources.
        merged: dict[str, Event] = {}
        aliases: dict[str, set[str]] = defaultdict(set)
        for source_id in sorted(self._records):
            for record_id in sorted(self._records[source_id]):
                record = self._records[source_id][record_id]
                claim = RecordRef(source_id, record_id)
                event_id = record["event_id"]
                if record["kind"] is None:
                    continue
                event = merged.get(event_id)
                if event is None:
                    event = Event(
                        event_id=event_id,
                        kind=record["kind"],
                        ts=record.get("ts"),
                        attrs={k: v for k, v in record.items()
                               if k not in {"source_id", "record_id", "event_id",
                                            "kind", "aliases", "refs"}},
                    )
                    merged[event_id] = event
                else:
                    if event.kind != record["kind"]:
                        raise ImportError(
                            f"event {event_id!r} claimed as both {event.kind.value!r} "
                            f"and {record['kind'].value!r}"
                        )
                    record_attrs = {k: v for k, v in record.items()
                                    if k not in {"source_id", "record_id", "event_id",
                                                 "kind", "aliases", "refs"}}
                    for key, value in record_attrs.items():
                        if key == "ts":
                            if event.ts is None and value is not None:
                                event.ts = value
                            continue
                        if value is not None and key not in event.attrs:
                            event.attrs[key] = value
                event.claims.add(claim)
                event.aliases.add(event_id)
                aliases[event_id].add(event_id)
                for alias in record.get("aliases", ()) or ():
                    alias = str(alias)
                    event.aliases.add(alias)
                    aliases[event_id].add(alias)

        # 2. Union events that share any alias (e.g. the same process GUID
        #    reported by two collectors), then map aliases to one root.
        parent = {event_id: event_id for event_id in merged}

        def root_of(node: str) -> str:
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        alias_owners: dict[str, str] = {}
        for event_id in merged:
            for alias in aliases[event_id]:
                if alias in alias_owners:
                    a = root_of(alias_owners[alias])
                    b = root_of(event_id)
                    if a != b:
                        hi, lo = (a, b) if a > b else (b, a)
                        parent[hi] = lo
                else:
                    alias_owners[alias] = event_id

        groups: dict[str, list[str]] = defaultdict(list)
        for event_id in merged:
            groups[root_of(event_id)].append(event_id)
        canonical: dict[str, Event] = {}
        alias_index: dict[str, str] = {}
        for root in sorted(groups):
            members = sorted(groups[root])
            base = merged[members[0]]
            for other_id in members[1:]:
                other = merged[other_id]
                if base.kind != other.kind:
                    raise ImportError(
                        f"events {base.event_id!r} and {other.event_id!r} share an "
                        f"alias but have kinds {base.kind.value!r} and "
                        f"{other.kind.value!r}"
                    )
                base.claims |= other.claims
                base.aliases |= other.aliases
                for key, value in other.attrs.items():
                    if key == "ts":
                        if base.ts is None:
                            base.ts = other.ts
                    elif value is not None and key not in base.attrs:
                        base.attrs[key] = value
            canonical[root] = base
            for alias in base.aliases:
                alias_index[alias] = root

        # 3. Resolve every explicit reference into an edge or a pending ref.
        evidence_by_edge: dict[tuple[str, str, str], set[Evidence]] = defaultdict(set)
        pending: dict[tuple[str, str, str, str, str, str], PendingRef] = {}
        for source_id in sorted(self._records):
            for record_id in sorted(self._records[source_id]):
                record = self._records[source_id][record_id]
                claim = RecordRef(source_id, record_id)
                claimant = alias_index.get(record["event_id"], record["event_id"])
                for ref in record.get("refs", ()) or ():
                    relation = str(ref.get("relation", "related"))
                    direction = ref.get("direction", "incoming")
                    target = str(ref["target"])
                    resolved = alias_index.get(target)
                    if resolved is None and ":" in target:
                        other_source, other_record = target.split(":", 1)
                        other = self._records.get(other_source, {}).get(other_record)
                        if other is not None:
                            resolved = alias_index[other["event_id"]]
                    if resolved is None:
                        key = (claimant, relation, direction, target,
                               claim.source_id, claim.record_id)
                        pending[key] = PendingRef(claimant, relation, direction,
                                                  target, claim)
                        continue
                    if direction == "incoming":
                        cause, effect = resolved, claimant
                    else:
                        cause, effect = claimant, resolved
                    if cause == effect:
                        continue
                    evidence_by_edge[(cause, effect, relation)].add(
                        self._evidence(claim, ref)
                    )

        self._events = canonical
        self._alias_index = alias_index
        self._edges = {
            key: Edge(key[0], key[1], key[2],
                      frozenset(item.claim for item in evidence))
            for key, evidence in evidence_by_edge.items()
        }
        self._pending = pending
        self._rebuild_hypotheses(evidence_by_edge)
        self._refresh_investigations(old_signatures)

    @staticmethod
    def _evidence(claim: RecordRef, ref: dict[str, Any]) -> Evidence:
        low = float(ref.get("confidence_low", 0.0))
        high = float(ref.get("confidence_high", 1.0))
        if not 0.0 <= low <= high <= 1.0:
            raise ImportError(
                "confidence range must satisfy 0 <= low <= high <= 1"
            )
        note = ref.get("note")
        return Evidence(
            claim=claim,
            confidence_low=low,
            confidence_high=high,
            note=str(note) if note is not None else None,
        )

    def _rebuild_hypotheses(
        self,
        evidence_by_edge: dict[tuple[str, str, str], set[Evidence]],
    ) -> None:
        previous = self._hypotheses
        rebuilt: dict[str, CausalHypothesis] = {}
        by_edge: dict[tuple[str, str, str], str] = {}
        next_id = max(
            (int(hid[2:]) for hid in previous if hid.startswith("h:")
             and hid[2:].isdigit()),
            default=0,
        )
        for key in sorted(evidence_by_edge):
            evidence = frozenset(evidence_by_edge[key])
            old = next((item for item in previous.values()
                        if item.key() == key and item.evidence == evidence), None)
            if old is None:
                overlap = [
                    item for item in previous.values()
                    if item.relation == key[2]
                    and item.evidence & evidence
                    and self._same_current_identity(item.cause_id, key[0])
                    and self._same_current_identity(item.effect_id, key[1])
                ]
                old = overlap[0] if len(overlap) == 1 else None
            if old is not None:
                stable = old.hypothesis_id
            else:
                next_id += 1
                stable = f"h:{next_id}"
            manual = any(item.claim.source_id == "manual" for item in evidence)
            hypothesis = CausalHypothesis(
                hypothesis_id=stable,
                cause_id=key[0],
                effect_id=key[1],
                relation=key[2],
                evidence=evidence,
                manual=manual,
            )
            rebuilt[stable] = hypothesis
            by_edge[key] = stable
        self._hypotheses = rebuilt
        self._hypothesis_by_edge = by_edge
        self._selected_hypotheses.intersection_update(rebuilt)

    def _same_current_identity(self, old_id: str, new_id: str) -> bool:
        old_current = self._current_identity_for_old_id(old_id)
        new_current = self._current_identity_for_old_id(new_id)
        if old_current is None or new_current is None:
            return False
        return old_current == new_current

    def _current_identity_for_old_id(self, old_id: str) -> str | None:
        if old_id in self._events:
            return old_id
        if old_id in self._alias_index:
            return self._alias_index[old_id]
        if ":" not in old_id:
            return None
        source_id, record_id = old_id.split(":", 1)
        claim = RecordRef(source_id, record_id)
        for event in self._events.values():
            if claim in event.claims:
                return event.event_id
        return None


    # ---------------------------------------------------------------- access

    @property
    def events(self) -> dict[str, Event]:
        return dict(self._events)

    def get_event(self, event_or_alias: str) -> Event | None:
        canonical = self._alias_index.get(event_or_alias, event_or_alias)
        return self._events.get(canonical)

    def edges(self) -> list[Edge]:
        return [self._edges[k] for k in sorted(self._edges)]

    def pending_refs(self) -> list[PendingRef]:
        return [self._pending[k] for k in sorted(self._pending)]

    def causal_hypotheses(self) -> list[CausalHypothesis]:
        return [self._hypotheses[hid] for hid in sorted(self._hypotheses)]

    def hypothesis(self, hypothesis_id: str) -> CausalHypothesis | None:
        return self._hypotheses.get(hypothesis_id)

    def hypotheses_for_effect(
        self, effect: str, relation: str | None = None
    ) -> list[CausalHypothesis]:
        event = self.get_event(effect)
        if event is None:
            return []
        return [
            item for item in self.causal_hypotheses()
            if item.effect_id == event.event_id
            and (relation is None or item.relation == relation)
        ]

    def conflicting_hypotheses(
        self, effect: str, relation: str
    ) -> list[CausalHypothesis]:
        items = self.hypotheses_for_effect(effect, relation)
        return items if len({item.cause_id for item in items}) > 1 else []

    def selected_hypothesis_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._selected_hypotheses))

    def select_hypotheses(self, hypothesis_ids: Iterable[str]) -> tuple[str, ...]:
        ids = set(hypothesis_ids)
        unknown = sorted(ids - set(self._hypotheses))
        if unknown:
            raise KeyError(f"unknown hypothesis ids: {unknown!r}")
        self._selected_hypotheses = ids
        return self.selected_hypothesis_ids()

    def clear_hypothesis_selection(self) -> None:
        self._selected_hypotheses.clear()

    def edge_evidence(self, cause_id: str, effect_id: str,
                      relation: str) -> tuple[RecordRef, ...]:
        edge = self._edges.get((cause_id, effect_id, relation))
        return tuple(sorted(edge.claims, key=lambda c: (c.source_id, c.record_id))) \
            if edge else ()

    # ------------------------------------------------------- investigations

    def investigations(self) -> list[InvestigationRecord]:
        return [self._investigations[key] for key in sorted(self._investigations)]

    def get_investigation(self, investigation_id: str) -> InvestigationRecord | None:
        return self._investigations.get(investigation_id)

    def close_investigation(
        self,
        investigation_id: str,
        seed: str,
        judgment: str,
        *,
        title: str = "",
        hypothesis_ids: Iterable[str] | None = None,
    ) -> InvestigationRecord:
        """Freeze the analyst's selected hypotheses and judgment at closure."""
        if not investigation_id:
            raise ValueError("investigation_id must be non-empty")
        seed_event = self.get_event(seed)
        if seed_event is None:
            raise KeyError(f"unknown event or alias: {seed!r}")
        seed_id = seed_event.event_id
        if hypothesis_ids is None:
            if self._selected_hypotheses:
                chosen_default = self.selected_hypothesis_ids()
            else:
                reachable = {seed_id}
                changed = True
                while changed:
                    changed = False
                    for hypothesis in self._hypotheses.values():
                        if (
                            hypothesis.cause_id in reachable
                            and hypothesis.effect_id in reachable
                        ):
                            continue
                        if hypothesis.cause_id in reachable:
                            reachable.add(hypothesis.effect_id)
                            changed = True
                        elif hypothesis.effect_id in reachable:
                            reachable.add(hypothesis.cause_id)
                            changed = True
                chosen_default = tuple(sorted(
                    hid for hid, hypothesis in self._hypotheses.items()
                    if hypothesis.cause_id in reachable
                    and hypothesis.effect_id in reachable
                ))
        else:
            chosen_default = tuple(sorted(set(hypothesis_ids)))
        ids = (
            chosen_default
        )
        if not ids:
            raise ValueError("at least one causal hypothesis must be selected")
        hypotheses = tuple(self._hypotheses[hid] for hid in ids)
        result = self.trace(seed, hypothesis_ids=ids)
        record = InvestigationRecord(
            investigation_id=investigation_id,
            seed=seed_id,
            title=title,
            created_at=time.time(),
            closed_at=time.time(),
            judgment=judgment,
            selected_hypothesis_ids=ids,
            hypotheses=hypotheses,
            trace_keys=tuple(sorted(
                (hop.cause_id, hop.effect_id, hop.relation)
                for hop in (*result.upstream, *result.downstream)
            )),
        )
        self._investigations[investigation_id] = record
        return record

    def reopen_investigation(
        self, investigation_id: str
    ) -> TraceResult | None:
        record = self._investigations.get(investigation_id)
        if record is None:
            raise KeyError(f"unknown investigation: {investigation_id!r}")
        surviving = tuple(
            hid for hid in record.selected_hypothesis_ids
            if hid in self._hypotheses
        )
        if not surviving or self.get_event(record.seed) is None:
            self._selected_hypotheses = set()
            return None
        self.select_hypotheses(surviving)
        return self.trace(record.seed, hypothesis_ids=surviving)

    def compare_investigation(
        self, investigation_id: str
    ) -> InvestigationComparison:
        record = self._investigations.get(investigation_id)
        if record is None:
            raise KeyError(f"unknown investigation: {investigation_id!r}")
        selected = set(record.selected_hypothesis_ids)
        saved_by_id = {item.hypothesis_id: item for item in record.hypotheses}
        current = set(self._hypotheses)
        missing = tuple(sorted(selected - current))
        still = tuple(sorted(
            hid for hid in selected & current
            if self._hypotheses[hid].evidence == saved_by_id[hid].evidence
        ))
        contradicted: set[str] = set()
        alternative: set[str] = set()
        for saved in record.hypotheses:
            current_effect = self._current_id_for_saved_hypothesis(saved)
            if current_effect is None:
                continue
            current_candidates = self.hypotheses_for_effect(
                current_effect, saved.relation
            )
            if any(item.cause_id != saved.cause_id for item in current_candidates):
                contradicted.add(saved.hypothesis_id)
            alternative.update(
                item.hypothesis_id for item in current_candidates
                if item.hypothesis_id not in selected
            )
        return InvestigationComparison(
            investigation_id=investigation_id,
            still_current=still,
            missing=missing,
            contradicted=tuple(sorted(contradicted)),
            new_alternatives=tuple(sorted(alternative)),
        )

    def _current_id_for_saved_hypothesis(
        self, saved: CausalHypothesis
    ) -> str | None:
        if self.get_event(saved.effect_id) is not None:
            return self.get_event(saved.effect_id).event_id
        for event in self._events.values():
            if any(claim in event.claims for claim in saved.claims):
                return event.event_id
        return None

    def _refresh_investigations(
        self,
        old_signatures: dict[tuple[str, str, str], frozenset[Evidence]],
    ) -> None:
        new_signatures = {
            key: self._hypotheses[hid].evidence
            for key, hid in self._hypothesis_by_edge.items()
        }
        affected_edges = {
            key for key in old_signatures.keys() | new_signatures.keys()
            if old_signatures.get(key) != new_signatures.get(key)
        }
        refreshed: dict[str, InvestigationRecord] = {}
        for investigation_id, record in self._investigations.items():
            if not affected_edges.intersection(record.trace_keys) and all(
                hid in self._hypotheses
                and self._hypotheses[hid].evidence
                == self._stored_evidence(record, hid)
                for hid in record.selected_hypothesis_ids
            ):
                refreshed[investigation_id] = record
                continue
            surviving = tuple(
                hid for hid in record.selected_hypothesis_ids
                if hid in self._hypotheses
            )
            if not surviving or self.get_event(record.seed) is None:
                latest_keys: tuple[tuple[str, str, str], ...] = ()
                status = "missing"
            else:
                trace = self.trace(record.seed, hypothesis_ids=surviving)
                latest_keys = tuple(sorted(
                    (hop.cause_id, hop.effect_id, hop.relation)
                    for hop in (*trace.upstream, *trace.downstream)
                ))
                if latest_keys != record.trace_keys:
                    status = "path_changed"
                elif any(
                    self._hypotheses[hid].evidence
                    != self._stored_evidence(record, hid)
                    for hid in surviving
                ):
                    status = "evidence_changed"
                else:
                    status = "current"
            refreshed[investigation_id] = InvestigationRecord(
                investigation_id=record.investigation_id,
                seed=record.seed,
                title=record.title,
                created_at=record.created_at,
                closed_at=record.closed_at,
                judgment=record.judgment,
                selected_hypothesis_ids=record.selected_hypothesis_ids,
                hypotheses=record.hypotheses,
                trace_keys=record.trace_keys,
                latest_trace_keys=latest_keys,
                status=status,
            )
        self._investigations = refreshed

    @staticmethod
    def _stored_evidence(
        record: InvestigationRecord, hypothesis_id: str
    ) -> frozenset[Evidence] | None:
        for hypothesis in record.hypotheses:
            if hypothesis.hypothesis_id == hypothesis_id:
                return hypothesis.evidence
        return None

    # ---------------------------------------------------------------- tracing

    def trace(
        self,
        seed: str,
        max_depth: int | None = None,
        hypothesis_ids: Iterable[str] | None = None,
    ) -> TraceResult:
        """Walk explicit assertions using all candidates or a chosen set."""
        origin = self.get_event(seed)
        if origin is None:
            raise KeyError(f"unknown event or alias: {seed!r}")
        origin_id = origin.event_id
        if hypothesis_ids is None:
            chosen = (
                set(self._selected_hypotheses)
                if self._selected_hypotheses
                else set(self._hypotheses)
            )
        else:
            chosen = set(hypothesis_ids)
            unknown = sorted(chosen - set(self._hypotheses))
            if unknown:
                raise KeyError(f"unknown hypothesis ids: {unknown!r}")

        hypotheses = [self._hypotheses[hid] for hid in chosen]
        out_adj: dict[str, list[CausalHypothesis]] = defaultdict(list)
        in_adj: dict[str, list[CausalHypothesis]] = defaultdict(list)
        for hypothesis in hypotheses:
            out_adj[hypothesis.cause_id].append(hypothesis)
            in_adj[hypothesis.effect_id].append(hypothesis)

        def walk(adj: dict[str, list[CausalHypothesis]]) -> list[EdgeHop]:
            seen: set[str] = set()
            hops: list[EdgeHop] = []
            frontier = [(origin_id, 0)]
            visited = {origin_id}
            while frontier:
                node, depth = frontier.pop(0)
                if max_depth is not None and depth >= max_depth:
                    continue
                for hypothesis in sorted(
                    adj.get(node, []),
                    key=lambda h: (h.cause_id, h.effect_id, h.relation),
                ):
                    if hypothesis.hypothesis_id in seen:
                        continue
                    seen.add(hypothesis.hypothesis_id)
                    low, high = hypothesis.confidence_range()
                    hops.append(EdgeHop(
                        cause_id=hypothesis.cause_id,
                        effect_id=hypothesis.effect_id,
                        relation=hypothesis.relation,
                        claims=tuple(sorted(
                            hypothesis.claims,
                            key=lambda c: (c.source_id, c.record_id),
                        )),
                        hypothesis_id=hypothesis.hypothesis_id,
                        confidence_range=(low, high),
                    ))
                    nxt = (
                        hypothesis.effect_id
                        if node == hypothesis.cause_id
                        else hypothesis.cause_id
                    )
                    if nxt not in visited:
                        visited.add(nxt)
                        frontier.append((nxt, depth + 1))
            return hops

        upstream = walk(in_adj)
        downstream = walk(out_adj)
        reached = {origin_id}
        for hop in (*upstream, *downstream):
            reached.add(hop.cause_id)
            reached.add(hop.effect_id)
        unresolved = [p for p in self.pending_refs() if p.claimant_id in reached]
        return TraceResult(
            origin_id=origin_id,
            upstream=upstream,
            downstream=downstream,
            events={eid: self._events[eid] for eid in reached if eid in self._events},
            unresolved=unresolved,
            hypothesis_ids=tuple(sorted(chosen)),
        )

    # ------------------------------------------------------------- snapshot

    def snapshot(self) -> dict[str, Any]:
        return {
            "version": 2,
            "sources": {
                sid: {"description": src.description,
                      "imported_at": src.imported_at}
                for sid, src in self._sources.items()
            },
            "records": {
                    sid: [self._jsonable(rec) for rec_id in sorted(batch)
                      for rec in [batch[rec_id]]]
                for sid, batch in sorted(self._records.items())
            },
            "selected_hypothesis_ids": self.selected_hypothesis_ids(),
            "investigations": {
                key: self._investigation_to_dict(record)
                for key, record in sorted(self._investigations.items())
            },
        }

    @staticmethod
    def _jsonable(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: (value.value if isinstance(value, EventKind) else value)
            for key, value in record.items()
        }

    @classmethod
    def restore(cls, data: dict[str, Any]) -> "InvestigationStore":
        version = data.get("version")
        if version not in (1, 2):
            raise ValueError("unsupported snapshot version")
        store = cls()
        for source_id in sorted(data.get("records", {})):
            batch = data["records"][source_id]
            meta = data.get("sources", {}).get(source_id, {})
            store.import_source(source_id, batch,
                                description=meta.get("description", ""),
                                imported_at=meta.get("imported_at"))
        if version == 2:
            selected = data.get("selected_hypothesis_ids", ())
            if selected:
                store.select_hypotheses(selected)
            store._investigations = {
                key: cls._investigation_from_dict(item)
                for key, item in data.get("investigations", {}).items()
            }
        return store

    @staticmethod
    def _evidence_to_dict(evidence: Evidence) -> dict[str, Any]:
        return {
            "claim": evidence.claim.as_dict(),
            "confidence_low": evidence.confidence_low,
            "confidence_high": evidence.confidence_high,
            "note": evidence.note,
        }

    @staticmethod
    def _evidence_from_dict(data: dict[str, Any]) -> Evidence:
        claim = data["claim"]
        return Evidence(
            claim=RecordRef(claim["source_id"], claim["record_id"]),
            confidence_low=float(data["confidence_low"]),
            confidence_high=float(data["confidence_high"]),
            note=data.get("note"),
        )

    def _hypothesis_to_dict(self, hypothesis: CausalHypothesis) -> dict[str, Any]:
        return {
            "hypothesis_id": hypothesis.hypothesis_id,
            "cause_id": hypothesis.cause_id,
            "effect_id": hypothesis.effect_id,
            "relation": hypothesis.relation,
            "manual": hypothesis.manual,
            "evidence": [
                self._evidence_to_dict(item)
                for item in sorted(hypothesis.evidence, key=lambda e: e.key())
            ],
        }

    @classmethod
    def _hypothesis_from_dict(cls, data: dict[str, Any]) -> CausalHypothesis:
        return CausalHypothesis(
            hypothesis_id=data["hypothesis_id"],
            cause_id=data["cause_id"],
            effect_id=data["effect_id"],
            relation=data["relation"],
            manual=bool(data.get("manual", False)),
            evidence=frozenset(
                cls._evidence_from_dict(item) for item in data["evidence"]
            ),
        )

    def _investigation_to_dict(self, record: InvestigationRecord) -> dict[str, Any]:
        return {
            "investigation_id": record.investigation_id,
            "seed": record.seed,
            "title": record.title,
            "created_at": record.created_at,
            "closed_at": record.closed_at,
            "judgment": record.judgment,
            "selected_hypothesis_ids": list(record.selected_hypothesis_ids),
            "hypotheses": [
                self._hypothesis_to_dict(item) for item in record.hypotheses
            ],
            "trace_keys": [list(key) for key in record.trace_keys],
            "latest_trace_keys": [list(key) for key in record.latest_trace_keys],
            "status": record.status,
        }

    @classmethod
    def _investigation_from_dict(cls, data: dict[str, Any]) -> InvestigationRecord:
        return InvestigationRecord(
            investigation_id=data["investigation_id"],
            seed=data["seed"],
            title=data.get("title", ""),
            created_at=data["created_at"],
            closed_at=data.get("closed_at"),
            judgment=data["judgment"],
            selected_hypothesis_ids=tuple(data["selected_hypothesis_ids"]),
            hypotheses=tuple(
                cls._hypothesis_from_dict(item) for item in data["hypotheses"]
            ),
            trace_keys=tuple(tuple(key) for key in data["trace_keys"]),
            latest_trace_keys=tuple(
                tuple(key) for key in data.get("latest_trace_keys", ())
            ),
            status=data.get("status", "current"),
        )
