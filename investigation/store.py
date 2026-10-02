from __future__ import annotations

import copy
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import (
    MANUAL_SOURCE,
    Edge,
    Event,
    EventKind,
    Hypothesis,
    EvidenceDecision,
    ManualLink,
    PlannedCheck,
    PendingRef,
    ReceivedBatch,
    RecordRef,
    Source,
    VerificationPlan,
)


class ImportError(ValueError):
    pass


@dataclass(frozen=True)
class EdgeHop:
    cause_id: str
    effect_id: str
    relation: str
    claims: tuple[RecordRef, ...]


@dataclass
class TraceResult:
    origin_id: str
    upstream: list[EdgeHop]
    downstream: list[EdgeHop]
    events: dict[str, Event]
    unresolved: list[PendingRef]


@dataclass
class ConflictGroup:
    """Competing explanations of the same (effect, relation) slot."""

    effect_id: str
    relation: str
    hypotheses: list[Hypothesis]

    @property
    def valid_start(self) -> float | None:
        values = [h.valid_start for h in self.hypotheses if h.valid_start is not None]
        return min(values) if values else None

    @property
    def valid_end(self) -> float | None:
        values = [h.valid_end for h in self.hypotheses if h.valid_end is not None]
        return max(values) if values else None

    @property
    def conflicting(self) -> bool:
        return len([h for h in self.hypotheses if not h.is_retracted]) > 1


@dataclass
class HypothesisSet:
    set_id: str
    hypothesis_ids: frozenset[str]
    description: str = ""
    created_at: float | None = None
    excluded_hypothesis_ids: frozenset[str] = frozenset()
    judgments: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ManualJudgment:
    link_id: str
    action: str
    link: ManualLink | None
    recorded_at: float | None
    note: str = ""


@dataclass
class HypothesisSetExplanation:
    set_id: str
    selected: tuple[Hypothesis, ...]
    excluded: tuple[Hypothesis, ...]
    explained_events: tuple[str, ...]
    conflicting_sources: tuple[str, ...]
    unexplained_events: tuple[str, ...]
    unresolved: tuple[PendingRef, ...]


@dataclass
class PathState:
    seed: str
    set_id: str | None
    max_depth: int | None
    at_time: float | None
    result: TraceResult
    reached: frozenset[str]
    anchors: frozenset[str]
    edge_anchors: frozenset[str] = frozenset()
    valid: bool = True


@dataclass(frozen=True)
class OutcomeAssessment:
    outcome_id: str
    label: str
    excluded_hypothesis_ids: tuple[str, ...]
    retained_hypothesis_ids: tuple[str, ...]
    supported_hypothesis_ids: tuple[str, ...]
    indistinguishable_groups: tuple[tuple[str, ...], ...]
    retained_paths: dict[str, TraceResult]
    prospective: bool = True


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
        # Analyst-asserted links (never replaced by source imports).
        self._manual_links: dict[str, ManualLink] = {}
        self._manual_judgments: list[ManualJudgment] = []
        # Hypothesis-derived state (rebuilt alongside the graph).
        self._hypotheses: dict[str, Hypothesis] = {}
        self._hypothesis_ledger: dict[str, Hypothesis] = {}
        self._claim_meta: dict[RecordRef, tuple[float, frozenset[str]]] = {}
        self._retractions: dict[RecordRef, frozenset[RecordRef]] = {}
        # Analyst-selected working sets of hypotheses.
        self._hyp_sets: dict[str, HypothesisSet] = {}
        self.active_set: str | None = None
        # Saved investigation paths, invalidated incrementally on change.
        self._paths: dict[tuple[str, str | None, int | None], PathState] = {}
        self._verification_plans: dict[str, VerificationPlan] = {}
        self._received_batches: dict[str, ReceivedBatch] = {}
        self._evidence_decisions: list[EvidenceDecision] = []

    # ---------------------------------------------------------------- import

    def import_source(
        self,
        source_id: str,
        records: Iterable[dict[str, Any]],
        description: str = "",
        trust: float | None = None,
        scopes: Iterable[str] = (),
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
        meta_trust = trust
        meta_scopes = tuple(str(s) for s in scopes)
        self._sources[source_id] = Source(
            source_id=source_id,
            description=description,
            imported_at=time.time(),
            record_ids=set(batch),
            trust=meta_trust,
            scopes=meta_scopes,
        )
        self._records[source_id] = batch
        self._rebuild(affected_source=source_id)
        return len(batch)

    def revoke_source(self, source_id: str) -> bool:
        """Remove a whole source and every evidence item it alone asserted."""
        if source_id not in self._records:
            return False
        del self._records[source_id]
        del self._sources[source_id]
        self._rebuild(affected_source=source_id)
        return True

    # ------------------------------------------------------- manual evidence

    def add_manual_link(
        self,
        cause: str,
        effect: str,
        relation: str = "parent",
        *,
        link_id: str | None = None,
        note: str = "",
        confidence: float = 0.5,
        scopes: Iterable[str] = ("manual",),
        retracts: Iterable[RecordRef | tuple[str, str]] = (),
        valid_start: float | None = None,
        valid_end: float | None = None,
    ) -> str:
        """Record an analyst-made association.

        The link is first-class evidence with its own provenance; it never
        silently merges with a source claim and can be revoked on its own.
        """
        cause = str(cause)
        effect = str(effect)
        relation = str(relation)
        if cause == effect:
            raise ImportError("manual link cannot connect an event to itself")
        existing = self._manual_links.get(str(link_id)) if link_id is not None else None
        if link_id is None:
            link_id = f"link-{len(self._manual_judgments) + 1}"
        link_id = str(link_id)
        refs = tuple(
            r if isinstance(r, RecordRef) else RecordRef(r[0], r[1])
            for r in retracts
        )
        if existing is not None:
            refs += (existing.claim(),)
        valid_start = self._coerce_time(valid_start)
        valid_end = self._coerce_time(valid_end)
        if valid_start is not None and valid_end is not None and valid_start > valid_end:
            raise ImportError("manual link valid_start cannot be later than valid_end")
        created_at = time.time()
        link = ManualLink(
            link_id=link_id,
            cause=cause,
            effect=effect,
            relation=relation,
            note=note,
            confidence=float(confidence),
            scopes=tuple(str(s) for s in scopes),
            retracts=refs,
            created_at=created_at,
            valid_start=valid_start,
            valid_end=valid_end,
        )
        self._manual_links[link_id] = link
        if existing is not None:
            self._manual_judgments.append(ManualJudgment(
                link_id=link_id, action="superseded", link=existing,
                recorded_at=created_at, note=note))
        self._manual_judgments.append(ManualJudgment(
            link_id=link_id,
            action="revised" if existing is not None else "created",
            link=link, recorded_at=created_at, note=note))
        affected = {link}
        if existing is not None:
            affected.add(existing)
        self._rebuild(affected_manual=affected)
        return link_id

    def retract_manual_link(self, link_id: str) -> bool:
        """Revoke one analyst association; only its paths are recomputed."""
        link = self._manual_links.get(str(link_id))
        if link is None:
            return False
        del self._manual_links[str(link_id)]
        recorded_at = time.time()
        revision = sum(1 for judgment in self._manual_judgments
                       if judgment.link_id == link_id) + 1
        retraction = ManualLink(
            link_id=f"{link_id}#retraction-{revision}",
            cause=link.cause, effect=link.effect, relation=link.relation,
            note="manual judgment retracted", confidence=1.0,
            retracts=(link.claim(),), created_at=recorded_at,
            valid_start=link.valid_start, valid_end=link.valid_end)
        self._manual_judgments.extend([
            ManualJudgment(link_id=link_id, action="retracted", link=link,
                           recorded_at=recorded_at),
            ManualJudgment(link_id=retraction.link_id, action="retraction",
                           link=retraction, recorded_at=recorded_at),
        ])
        self._rebuild(affected_manual={link, retraction})
        return True

    def manual_links(self) -> list[ManualLink]:
        return [self._manual_links[k] for k in sorted(self._manual_links)]

    def manual_judgments(self) -> list[ManualJudgment]:
        return list(self._manual_judgments)

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
        EventKind.coerce(kind if kind is not None else "")
        out = dict(record)
        out["record_id"] = str(record_id)
        out["kind"] = EventKind.coerce(kind)
        out["source_id"] = source_id
        if "event_id" not in out or not out["event_id"]:
            out["event_id"] = f"{source_id}:{out['record_id']}"
        out["refs"] = [dict(r) for r in (out.get("refs") or ())]
        for ref in out["refs"]:
            if "valid_start" in ref:
                ref["valid_start"] = self._coerce_time(ref.get("valid_start"))
            if "valid_end" in ref:
                ref["valid_end"] = self._coerce_time(ref.get("valid_end"))
            if (ref.get("valid_start") is not None
                    and ref.get("valid_end") is not None
                    and ref["valid_start"] > ref["valid_end"]):
                raise ImportError("ref valid_start cannot be later than valid_end")
        retract = out.get("retracts")
        out["retracts"] = [dict(r) if isinstance(r, dict) else {"target": r}
                            for r in (retract or ())]
        return out

    # ---------------------------------------------------------------- rebuild

    # ---------------------------------------------------------------- rebuild

    @staticmethod
    def _coerce_trust(value: Any, default: float) -> float:
        if value is None:
            return default
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        return max(0.0, min(1.0, number))

    @staticmethod
    def _coerce_scopes(value: Any, default: tuple[str, ...] = ()) -> frozenset[str]:
        if value is None:
            return frozenset(default)
        if isinstance(value, str):
            value = [value]
        try:
            return frozenset(str(v) for v in value)
        except TypeError:
            return frozenset(default)

    @staticmethod
    def _coerce_time(value: Any) -> float | None:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _rebuild(self, *, affected_source: str | None = None,
                 affected_manual: set[ManualLink] | None = None) -> None:
        """Rebuild derived graph, hypotheses, and invalidate touched paths.

        Records remain the source of truth.  Identity resolution and edge
        claims are replayed in full (deterministic, cheap), while saved
        investigation *paths* are only recomputed for anchors whose
        supporting evidence changed.
        """
        affected_manual = affected_manual or set()
        # 1. Aggregate events across sources.
        merged: dict[str, Event] = {}
        aliases: dict[str, set[str]] = defaultdict(set)
        ref_counts: dict[str, int] = defaultdict(int)
        for source_id in sorted(self._records):
            for record_id in sorted(self._records[source_id]):
                record = self._records[source_id][record_id]
                claim = RecordRef(source_id, record_id)
                event_id = record["event_id"]
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
                    if event.ts is None and record.get("ts") is not None:
                        event.ts = record.get("ts")
                event.claims.add(claim)
                ref_counts[event_id] += len(record.get("refs", ()) or ())
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
            canonical_id = min(members, key=lambda event_id: (
                ref_counts[event_id] == 0, -ref_counts[event_id], event_id))
            base = merged[canonical_id]
            members = [member for member in members if member != canonical_id]
            for other_id in members:
                other = merged[other_id]
                if base.kind != other.kind:
                    raise ImportError(
                        f"events {base.event_id!r} and {other.event_id!r} share an "
                        f"alias but have kinds {base.kind.value!r} and "
                        f"{other.kind.value!r}"
                    )
                base.claims |= other.claims
                base.aliases |= other.aliases
                base.attrs = {**other.attrs, **base.attrs}
                if base.ts is None:
                    base.ts = other.ts
            canonical[canonical_id] = base
            for alias in base.aliases:
                alias_index[alias] = canonical_id

        # 3. Collect per-claim metadata, retractions and manual claims.
        claim_meta: dict[RecordRef, tuple[float, frozenset[str]]] = {}
        retractions: dict[RecordRef, set[RecordRef]] = defaultdict(set)

        for sid, src in self._sources.items():
            default_trust = self._coerce_trust(src.trust, 0.5)
            default_scopes = self._coerce_scopes(src.scopes)
            for rec_id, record in self._records[sid].items():
                claim = RecordRef(sid, rec_id)
                rec_trust = record.get("confidence", record.get("trust"))
                rec_scopes = record.get("scopes", default_scopes)
                claim_meta[claim] = (
                    self._coerce_trust(rec_trust, default_trust),
                    self._coerce_scopes(rec_scopes, default_scopes),
                )
                for item in record.get("retracts", ()) or ():
                    retractions[claim].add(self._ref_to_claim(sid, item))

        for link in self._manual_links.values():
            claim = link.claim()
            claim_meta[claim] = (
                self._coerce_trust(link.confidence, 0.5),
                self._coerce_scopes(link.scopes, {"manual"}),
            )
            for target in link.retracts:
                retractions[claim].add(target)
        for judgment in self._manual_judgments:
            if judgment.action == "retraction" and judgment.link is not None:
                claim_meta.setdefault(judgment.link.claim(), (1.0, frozenset({"manual"})))
                for target in judgment.link.retracts:
                    retractions[judgment.link.claim()].add(target)

        global_retracted: set[RecordRef] = set()
        for targets in retractions.values():
            global_retracted |= targets

        # 4. Resolve every explicit reference into a raw claim or a pending.
        edge_claims: dict[tuple[str, str, str], set[tuple[RecordRef, float | None, float | None]]] = defaultdict(set)
        pending: dict[tuple[str, str, str, str, str, str], PendingRef] = {}
        for source_id in sorted(self._records):
            for record_id in sorted(self._records[source_id]):
                record = self._records[source_id][record_id]
                claim = RecordRef(source_id, record_id)
                claimant = self._alias_index_get(
                    alias_index, record["event_id"], source_id, record_id,
                    fallback_identity=True)
                for ref in record.get("refs", ()) or ():
                    relation = str(ref.get("relation", "related"))
                    direction = ref.get("direction", "incoming")
                    target = str(ref["target"])
                    resolved = self._alias_index_get(alias_index, target,
                                                     optional=True)
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
                    edge_claims[(cause, effect, relation)].add(
                        (claim, ref.get("valid_start"), ref.get("valid_end")))

        # 5. Analyst-asserted links contribute claims just like records do.
        for link in self._manual_links.values():
            claim = link.claim()
            resolved_cause = self._resolve_link_end(link.cause)
            resolved_effect = self._resolve_link_end(link.effect)
            if resolved_cause is None or resolved_effect is None:
                key = (link.effect, link.relation, "incoming", link.cause,
                       claim.source_id, claim.record_id)
                pending[key] = PendingRef(
                    link.effect, link.relation, "incoming", link.cause, claim)
                continue
            if resolved_cause == resolved_effect:
                continue
            edge_claims[(resolved_cause, resolved_effect, link.relation)].add(
                (claim, link.valid_start, link.valid_end))

        # 6. Group raw claims into competing hypotheses per (effect, rel).
        hypotheses: dict[str, Hypothesis] = {}
        grouped: dict[tuple[str, str, float | None, float | None], dict[str, set[tuple[RecordRef, float | None, float | None]]]] = defaultdict(lambda: defaultdict(set))
        for (cause_id, effect_id, relation), claim_entries in edge_claims.items():
            for claim, valid_start, valid_end in claim_entries:
                slot_key = (effect_id, relation, valid_start, valid_end)
                grouped[slot_key][cause_id].add((claim, valid_start, valid_end))

        for (effect_id, relation, valid_start, valid_end), by_cause in grouped.items():
            for cause_id, claim_entries in by_cause.items():
                claims = {entry[0] for entry in claim_entries}
                retracted = {c for c in claims if c in global_retracted}
                scopes: set[str] = set()
                confidences: list[float] = []
                origins: set[str] = set()
                for claim in claims:
                    conf, claim_scopes = claim_meta.get(
                        claim, (0.5, frozenset()))
                    confidences.append(conf)
                    scopes |= claim_scopes
                    origins.add(claim.source_id)
                hypothesis_id = Hypothesis.make_id(
                    effect_id, relation, cause_id, valid_start, valid_end)
                hypotheses[hypothesis_id] = Hypothesis(
                    hypothesis_id=hypothesis_id,
                    effect_id=effect_id,
                    relation=relation,
                    cause_id=cause_id,
                    claims=frozenset(claims),
                    retracted_claims=frozenset(retracted),
                    scopes=frozenset(scopes),
                    confidence=(max(confidences) if confidences else 0.5),
                    origins=frozenset(origins),
                    valid_start=valid_start,
                    valid_end=valid_end,
                )

        for hypothesis_id, historical in self._hypothesis_ledger.items():
            current = hypotheses.get(hypothesis_id)
            if current is None:
                retracted = historical.claims | historical.retracted_claims
                hypotheses[hypothesis_id] = Hypothesis(
                    hypothesis_id=historical.hypothesis_id,
                    effect_id=historical.effect_id,
                    relation=historical.relation,
                    cause_id=historical.cause_id,
                    claims=historical.claims,
                    retracted_claims=frozenset(retracted),
                    scopes=historical.scopes,
                    confidence=historical.confidence,
                    origins=historical.origins,
                    valid_start=historical.valid_start,
                    valid_end=historical.valid_end,
                )
            else:
                hypotheses[hypothesis_id] = Hypothesis(
                    hypothesis_id=current.hypothesis_id,
                    effect_id=current.effect_id,
                    relation=current.relation,
                    cause_id=current.cause_id,
                    claims=historical.claims | current.claims,
                    retracted_claims=(
                        current.retracted_claims
                        | (historical.claims - current.claims)),
                    scopes=historical.scopes | current.scopes,
                    confidence=max(historical.confidence, current.confidence),
                    origins=historical.origins | current.origins,
                    valid_start=current.valid_start,
                    valid_end=current.valid_end,
                )

        # 7. Preserve analyst sets exactly and determine which saved paths
        #    actually changed.  Missing selected candidates remain recorded
        #    so later reviews can show why the saved judgment no longer maps
        #    to live evidence.
        live_ids = set(hypotheses)
        pruned_sets: dict[str, set[str]] = {}
        for set_id, hyp_set in list(self._hyp_sets.items()):
            missing = set(hyp_set.hypothesis_ids) - live_ids
            if missing:
                pruned_sets[set_id] = missing

        changed_anchors = self._changed_anchors(
            affected_source=affected_source,
            affected_manual=affected_manual,
            prev_hypotheses=self._hypotheses,
            new_hypotheses=hypotheses,
            pruned_sets=pruned_sets,
        )
        # Paths whose seed or reached nodes vanished entirely are stale too.
        live_nodes = set(canonical)

        self._events = canonical
        self._alias_index = alias_index
        self._edges = {
            key: Edge(key[0], key[1], key[2],
                      frozenset(entry[0] for entry in claim_entries))
            for key, claim_entries in edge_claims.items()
        }
        self._pending = pending
        self._hypotheses = hypotheses
        self._hypothesis_ledger = dict(hypotheses)
        self._claim_meta = claim_meta
        self._retractions = {k: frozenset(v) for k, v in retractions.items()}
        for state in self._paths.values():
            changed = state.anchors if state.at_time is None else state.edge_anchors
            if (changed & changed_anchors
                    or any(a not in live_nodes for a in state.anchors)
                    or not state.valid):
                state.valid = False

    def _resolve_link_end(self, endpoint: str) -> str | None:
        return self._alias_index_get(self._alias_index, endpoint, optional=True)

    def _alias_index_get(self, alias_index: dict[str, str], endpoint: str,
                         source_id: str | None = None,
                         record_id: str | None = None,
                         optional: bool = False,
                         fallback_identity: bool = False) -> str | None:
        """Resolve an alias, a source:record pointer, or a raw event id."""
        def lookup(raw_endpoint: str) -> str | None:
            direct = alias_index.get(raw_endpoint)
            if direct is not None:
                return direct
            # Only a source:record pointer may fall back to the pointed
            # record's own event identity; a stable alias (for example
            # guid:...) also contains a colon but is not a pointer.
            if ":" in raw_endpoint:
                other_source, other_record = raw_endpoint.split(":", 1)
                if other_source not in self._records:
                    return None
                other = self._records[other_source].get(other_record)
                if other is None:
                    return None
                resolved_owner = alias_index.get(other["event_id"])
                if resolved_owner is None:
                    return None
                # The pointed record still exists; its event may have been
                # merged away by revocation - require a live canonical node.
                if resolved_owner not in self._events:
                    return None
                return resolved_owner
            return None

        resolved = lookup(endpoint)
        if resolved is not None:
            return resolved
        if source_id is not None and record_id is not None:
            own = self._records.get(source_id, {}).get(record_id)
            if own is not None:
                resolved = lookup(own["event_id"])
                if resolved is not None:
                    return resolved
        return endpoint if fallback_identity else None

    @staticmethod
    def _ref_to_claim(source_id: str, item: dict[str, Any] | str) -> RecordRef:
        if isinstance(item, dict):
            return RecordRef(str(item["source_id"]), str(item["record_id"]))
        return RecordRef(source_id, str(item))

    def _changed_anchors(self, *, affected_source: str | None,
                         affected_manual: set[ManualLink],
                         prev_hypotheses: dict[str, Hypothesis],
                         new_hypotheses: dict[str, Hypothesis],
                         pruned_sets: dict[str, set[str]]) -> set[str]:
        """Union of event ids participating in any hypothesis that changed.

        A change means: appeared, disappeared, claim/evidence set changed,
        or retraction status changed.  Unrelated hypotheses do not touch
        saved paths, so revocation/re-import only recomputes affected
        investigation paths.
        """
        changed: set[str] = set()

        def touch_hypothesis(h: Hypothesis) -> None:
            changed.add(h.cause_id)
            changed.add(h.effect_id)

        if affected_source is None and not affected_manual:
            for hypothesis in new_hypotheses.values():
                touch_hypothesis(hypothesis)
            return changed

        candidate_ids: set[str] = set()
        if affected_source is not None:
            for hypothesis in (*prev_hypotheses.values(), *new_hypotheses.values()):
                if any(c.source_id == affected_source for c in hypothesis.claims):
                    candidate_ids.add(hypothesis.hypothesis_id)
        manual_claims = {link.claim() for link in affected_manual}
        manual_retractions = {target for link in affected_manual
                              for target in link.retracts}
        for hypothesis in (*prev_hypotheses.values(), *new_hypotheses.values()):
            if (manual_claims & hypothesis.claims
                    or manual_retractions & hypothesis.claims):
                candidate_ids.add(hypothesis.hypothesis_id)

        for hypothesis_id in candidate_ids:
            old = prev_hypotheses.get(hypothesis_id)
            new = new_hypotheses.get(hypothesis_id)
            if old is None or new is None:
                h = old or new
                touch_hypothesis(h)
                continue
            evidence_changed = (old.claims != new.claims
                                or old.retracted_claims != new.retracted_claims)
            window_changed = (old.valid_start != new.valid_start
                              or old.valid_end != new.valid_end)
            if evidence_changed:
                touch_hypothesis(new)
            elif window_changed:
                for state in self._paths.values():
                    if state.at_time is None or (
                            self._hypothesis_applies_at(old, state.at_time)
                            or self._hypothesis_applies_at(new, state.at_time)):
                        changed.add(old.effect_id)
                        changed.add(old.cause_id)

        for set_id, missing in pruned_sets.items():
            for state in self._paths.values():
                if state.set_id == set_id:
                    state.valid = False
        return changed

    @staticmethod
    def _hypothesis_applies_at(hypothesis: Hypothesis,
                               moment: float | None) -> bool:
        if moment is None:
            return True
        return hypothesis.active_at(moment)

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

    def edge_evidence(self, cause_id: str, effect_id: str,
                      relation: str) -> tuple[RecordRef, ...]:
        edge = self._edges.get((cause_id, effect_id, relation))
        return tuple(sorted(edge.claims, key=lambda c: (c.source_id, c.record_id))) \
            if edge else ()

    # ----------------------------------------------------------- hypotheses

    def hypotheses(self, include_retracted: bool = False,
                   at_time: float | None = None) -> list[Hypothesis]:
        items = [h for h in self._hypotheses.values()
                 if (include_retracted or not h.is_retracted)
                 and h.active_at(at_time)]
        return sorted(items, key=lambda h: (h.effect_id, h.relation,
                                            h.valid_start if h.valid_start is not None else float("-inf"),
                                            h.valid_end if h.valid_end is not None else float("inf"),
                                            -h.confidence, h.cause_id))

    def conflict_groups(self, include_retracted: bool = False,
                        at_time: float | None = None
                        ) -> list[ConflictGroup]:
        slots: dict[tuple[str, str], list[Hypothesis]] = defaultdict(list)
        for hypothesis in self.hypotheses(include_retracted=include_retracted,
                                         at_time=at_time):
            slots[(hypothesis.effect_id, hypothesis.relation)].append(hypothesis)
        groups: list[ConflictGroup] = []
        for (effect_id, relation), hyps in sorted(slots.items()):
            clusters: list[list[Hypothesis]] = []
            for hypothesis in hyps:
                placed = False
                for cluster in clusters:
                    if any(self._windows_overlap(hypothesis, other)
                           for other in cluster):
                        cluster.append(hypothesis)
                        placed = True
                        break
                if not placed:
                    clusters.append([hypothesis])
            for cluster in clusters:
                if len(cluster) > 1:
                    groups.append(ConflictGroup(effect_id=effect_id,
                                                relation=relation,
                                                hypotheses=cluster))
        return groups

    @staticmethod
    def _windows_overlap(left: Hypothesis, right: Hypothesis) -> bool:
        if left.valid_start is None and left.valid_end is None:
            return True
        if right.valid_start is None and right.valid_end is None:
            return True
        left_start = left.valid_start if left.valid_start is not None else float("-inf")
        left_end = left.valid_end if left.valid_end is not None else float("inf")
        right_start = right.valid_start if right.valid_start is not None else float("-inf")
        right_end = right.valid_end if right.valid_end is not None else float("inf")
        return left_start <= right_end and right_start <= left_end

    def hypothesis_evidence(self, hypothesis_id: str) -> Hypothesis:
        return self._hypotheses[hypothesis_id]

    def retractions(self) -> dict[RecordRef, tuple[RecordRef, ...]]:
        return {claim: tuple(sorted(targets,
                                    key=lambda c: (c.source_id, c.record_id)))
                for claim, targets in sorted(
                    self._retractions.items(),
                    key=lambda kv: (kv[0].source_id, kv[0].record_id))}

    # ------------------------------------------------- verification planning

    def create_verification_plan(
        self, plan_id: str, checks: Iterable[PlannedCheck | dict[str, Any]],
        *,
        seeds: Iterable[str] = (),
        set_id: str | None = "__active__",
        description: str = "",
    ) -> VerificationPlan:
        if not plan_id or not isinstance(plan_id, str):
            raise ImportError("plan_id must be a non-empty string")
        if plan_id in self._verification_plans:
            raise ImportError(f"verification plan {plan_id!r} already exists")
        normalized_checks = tuple(
            check if isinstance(check, PlannedCheck)
            else self._planned_check_from_dict(check)
            for check in checks)
        if not normalized_checks:
            raise ImportError("a verification plan requires at least one check")
        self._validate_planned_checks(normalized_checks)
        if set_id == "__active__":
            set_id = self.active_set
        if set_id is not None and set_id not in self._hyp_sets:
            raise KeyError(f"unknown hypothesis set: {set_id!r}")
        seed_list = [str(seed) for seed in seeds]
        plan = VerificationPlan(
            plan_id=plan_id,
            checks=normalized_checks,
            created_at=time.time(),
            set_id=set_id,
            hypothesis_ids=frozenset(self._hypotheses),
            seeds=tuple(seed_list),
            description=description,
            baseline_snapshot=copy.deepcopy(self.snapshot()),
        )
        self._verification_plans[plan_id] = plan
        return plan

    @staticmethod
    def _validate_planned_checks(checks: tuple[PlannedCheck, ...]) -> None:
        check_ids = [check.check_id for check in checks]
        if len(check_ids) != len(set(check_ids)):
            raise ImportError("check_id values must be unique within a plan")
        for check in checks:
            outcome_ids = [outcome.outcome_id for outcome in check.outcomes]
            if not check.outcomes:
                raise ImportError(
                    f"check {check.check_id!r} requires possible outcomes")
            if len(outcome_ids) != len(set(outcome_ids)):
                raise ImportError(
                    f"outcome ids in check {check.check_id!r} must be unique")

    @staticmethod
    def _planned_check_from_dict(data: dict[str, Any]) -> PlannedCheck:
        from .models import PlannedOutcome

        return PlannedCheck(
            check_id=str(data["check_id"]),
            label=str(data.get("label", data["check_id"])),
            source_id=str(data["source_id"]),
            relation=str(data["relation"]),
            target=data.get("target"),
            direction=str(data.get("direction", "incoming")),
            outcomes=tuple(
                PlannedOutcome(
                    outcome_id=str(item["outcome_id"]),
                    label=str(item.get("label", item["outcome_id"])),
                    records=tuple(dict(record)
                                  for record in item.get("records", ())),
                    note=str(item.get("note", "")),
                )
                for item in data.get("outcomes", ())),
        )

    def verification_plans(self) -> list[VerificationPlan]:
        return [self._verification_plans[key]
                for key in sorted(self._verification_plans)]

    def verification_plan(self, plan_id: str) -> VerificationPlan:
        return self._verification_plans[plan_id]

    def assess_plan_outcome(self, plan_id: str, check_id: str,
                            outcome_id: str) -> OutcomeAssessment:
        plan = self.verification_plan(plan_id)
        check = self._find_planned_check(plan, check_id)
        outcome = self._find_planned_outcome(check, outcome_id)
        trial = self._open_planned_outcome(plan, check, outcome)
        baseline_ids = set(plan.hypothesis_ids)
        after = {h.hypothesis_id: h for h in trial.hypotheses(True)}
        retained = tuple(sorted(
            hid for hid in baseline_ids
            if hid in after and not after[hid].is_retracted))
        excluded = tuple(sorted(baseline_ids - set(retained)))
        before = {hid: self._hypotheses[hid] for hid in baseline_ids
                  if hid in self._hypotheses}
        supported = tuple(sorted(
            hid for hid, hypothesis in after.items()
            if not hypothesis.is_retracted and self._outcome_supports(
                plan, check, outcome, hypothesis, before.get(hid))))
        groups = self._indistinguishable_groups(
            [after[hid] for hid in retained])
        seeds = plan.seeds or tuple(sorted({
            self._hypotheses[hid].effect_id
            for hid in plan.hypothesis_ids
            if hid in self._hypotheses}))
        paths: dict[str, TraceResult] = {}
        for seed in seeds:
            try:
                paths[seed] = trial.trace(seed, set_id=plan.set_id)
            except KeyError:
                continue
        return OutcomeAssessment(
            outcome_id=outcome.outcome_id,
            label=outcome.label,
            excluded_hypothesis_ids=excluded,
            retained_hypothesis_ids=retained,
            supported_hypothesis_ids=supported,
            indistinguishable_groups=groups,
            retained_paths=paths,
        )

    def open_plan_outcome(self, plan_id: str, check_id: str,
                          outcome_id: str) -> "InvestigationStore":
        plan = self.verification_plan(plan_id)
        check = self._find_planned_check(plan, check_id)
        outcome = self._find_planned_outcome(check, outcome_id)
        return self._open_planned_outcome(plan, check, outcome)

    def _open_planned_outcome(self, plan: VerificationPlan,
                              check: PlannedCheck, outcome
                              ) -> "InvestigationStore":
        trial = InvestigationStore.restore(
            copy.deepcopy(plan.baseline_snapshot))
        records = [self._prospective_record(plan, check, outcome, record)
                   for record in outcome.records]
        existing = list(plan.baseline_snapshot.get("records", {})
                        .get(check.source_id, ()))
        trial.import_source(check.source_id, [*existing, *records],
                            description=f"prospective:{plan.plan_id}:"
                                        f"{check.check_id}:{outcome.outcome_id}")
        return trial

    @staticmethod
    def _prospective_record(plan: VerificationPlan, check: PlannedCheck,
                            outcome, record: dict[str, Any]) -> dict[str, Any]:
        item = dict(record)
        original_id = item.get("record_id", "result")
        item["record_id"] = (
            f"__plan__:{plan.plan_id}:{check.check_id}:"
            f"{outcome.outcome_id}:{original_id}")
        return item

    @staticmethod
    def _find_planned_check(plan: VerificationPlan, check_id: str) -> PlannedCheck:
        for check in plan.checks:
            if check.check_id == check_id:
                return check
        raise KeyError(f"unknown planned check: {check_id!r}")

    @staticmethod
    def _find_planned_outcome(check: PlannedCheck, outcome_id: str):
        for outcome in check.outcomes:
            if outcome.outcome_id == outcome_id:
                return outcome
        raise KeyError(f"unknown planned outcome: {outcome_id!r}")

    @staticmethod
    def _indistinguishable_groups(
        hypotheses: list[Hypothesis]
    ) -> tuple[tuple[str, ...], ...]:
        groups: list[tuple[str, ...]] = []
        for index, left in enumerate(hypotheses):
            peers = tuple(sorted(
                right.hypothesis_id for right in hypotheses[index + 1:]
                if left.effect_id == right.effect_id
                and left.relation == right.relation
                and left.cause_id != right.cause_id
                and InvestigationStore._windows_overlap(left, right)))
            if peers:
                groups.append(tuple(sorted((left.hypothesis_id, *peers))))
        return tuple(groups)

    @staticmethod
    def _outcome_supports(plan: VerificationPlan, check: PlannedCheck,
                          outcome, after: Hypothesis,
                          before: Hypothesis | None) -> bool:
        prefix = (f"__plan__:{plan.plan_id}:{check.check_id}:"
                  f"{outcome.outcome_id}:")
        new_claims = {claim for claim in after.active_claims
                      if claim.source_id == check.source_id
                      and claim.record_id.startswith(prefix)}
        return bool(new_claims) or (
            before is not None
            and after.active_claims != before.active_claims)

    # ------------------------------------------------ received evidence flow

    def receive_evidence(
        self, source_id: str, records: Iterable[dict[str, Any]],
        *,
        batch_id: str | None = None,
        description: str = "",
        plan_id: str | None = None,
        check_id: str | None = None,
        outcome_id: str | None = None,
    ) -> str:
        source_id = str(source_id)
        items = tuple(dict(record) for record in records)
        if not items:
            raise ImportError("received evidence requires records")
        if batch_id is None:
            batch_id = f"batch-{len(self._received_batches) + 1}"
        batch_id = str(batch_id)
        if batch_id in self._received_batches:
            raise ImportError(f"received batch {batch_id!r} already exists")
        if plan_id is not None:
            plan = self.verification_plan(plan_id)
            if check_id is not None:
                check = self._find_planned_check(plan, check_id)
                if outcome_id is not None:
                    self._find_planned_outcome(check, outcome_id)
        batch = ReceivedBatch(
            batch_id=batch_id,
            source_id=source_id,
            records=items,
            received_at=time.time(),
            plan_id=plan_id,
            check_id=check_id,
            outcome_id=outcome_id,
            description=description,
        )
        self._received_batches[batch_id] = batch
        return batch_id

    def received_batches(self, status: str | None = None) -> list[ReceivedBatch]:
        return [batch for batch in (self._received_batches[key]
                                    for key in sorted(self._received_batches))
                if status is None or batch.status == status]

    def received_batch(self, batch_id: str) -> ReceivedBatch:
        return self._received_batches[str(batch_id)]

    def review_received_evidence(self, batch_id: str) -> dict[str, Any]:
        batch = self.received_batch(batch_id)
        mismatches: list[str] = []
        contradictions: list[str] = []
        expected_records: list[dict[str, Any]] = []
        if batch.plan_id and batch.check_id:
            plan = self.verification_plan(batch.plan_id)
            check = self._find_planned_check(plan, batch.check_id)
            planned_outcomes = [self._find_planned_outcome(check, batch.outcome_id)] \
                if batch.outcome_id else list(check.outcomes)
            for outcome in planned_outcomes:
                expected_records.extend(outcome.records)
                if not self._records_match_plan(batch.records, outcome.records):
                    mismatches.append(
                        f"material does not match outcome {outcome.outcome_id!r}")
            if batch.outcome_id:
                outcome = planned_outcomes[0]
                contradictions.extend(self._contradictions_to_outcome(
                    check, outcome, batch.records))
            else:
                if not any(self._records_match_plan(batch.records, outcome.records)
                           for outcome in check.outcomes):
                    contradictions.append(
                        "material matches none of the planned possible outcomes")
        duplicate_claims = self._duplicate_claims(batch)
        shared_sources = self._shared_planned_sources(batch)
        return {
            "batch_id": batch.batch_id,
            "status": batch.status,
            "mismatches": tuple(mismatches),
            "contradictions": tuple(contradictions),
            "duplicate_claims": tuple(duplicate_claims),
            "shared_planned_sources": tuple(shared_sources),
            "unexpected": not bool(batch.plan_id and batch.check_id),
        }

    @staticmethod
    def _records_match_plan(actual: tuple[dict[str, Any], ...],
                           expected: tuple[dict[str, Any], ...]) -> bool:
        def fingerprint(record: dict[str, Any]) -> tuple:
            return tuple(sorted((key, str(value)) for key, value in record.items()
                                if key not in {"record_id", "source_id"}))

        return {fingerprint(item) for item in actual} == \
            {fingerprint(item) for item in expected}

    def _contradictions_to_outcome(self, check: PlannedCheck, outcome,
                                   records: tuple[dict[str, Any], ...]) -> list[str]:
        problems: list[str] = []
        expected_relations = {
            (str(ref.get("relation", "related")),
             str(ref.get("direction", "incoming")), str(ref.get("target", "")))
            for record in outcome.records for ref in record.get("refs", ())}
        for record in records:
            for ref in record.get("refs", ()):
                actual = (str(ref.get("relation", "related")),
                          str(ref.get("direction", "incoming")),
                          str(ref.get("target", "")))
                if check.target is not None and actual[0] == check.relation and (
                        actual[1] != check.direction or actual[2] != check.target):
                    problems.append(
                        f"record {record.get('record_id')!r} asserts "
                        f"{actual[1]} {actual[0]} -> {actual[2]}, planned "
                        f"{check.direction} {check.relation} -> {check.target}")
                if expected_relations and not any(
                        actual[0] == item[0] and actual[1] == item[1]
                        for item in expected_relations):
                    problems.append(
                        f"record {record.get('record_id')!r} has relationship "
                        f"{actual[0]!r} not present in the planned outcome")
        return problems

    def _duplicate_claims(self, batch: ReceivedBatch) -> tuple[str, ...]:
        duplicates: set[str] = set()
        for record in batch.records:
            fingerprint = self._claim_fingerprint(record)
            for sid, existing_batch in self._records.items():
                for record_id, existing in existing_batch.items():
                    if self._claim_fingerprint(existing) == fingerprint:
                        duplicates.add(f"accepted:{sid}:{record_id}")
            for other in self._received_batches.values():
                if other.batch_id == batch.batch_id:
                    continue
                for other_record in other.records:
                    if self._claim_fingerprint(other_record) == fingerprint:
                        duplicates.add(
                            f"pending:{other.batch_id}:"
                            f"{other_record.get('record_id')}")
        return tuple(sorted(duplicates))

    @staticmethod
    def _claim_fingerprint(record: dict[str, Any]) -> tuple:
        return tuple(sorted((key, str(value)) for key, value in record.items()
                            if key not in {"record_id", "source_id"}))

    def _shared_planned_sources(self, batch: ReceivedBatch) -> tuple[str, ...]:
        shared = {
            plan.plan_id
            for plan in self._verification_plans.values()
            if plan.plan_id != batch.plan_id
            and any(check.source_id == batch.source_id for check in plan.checks)}
        return tuple(sorted(shared))

    def accept_evidence(
        self, batch_id: str, *,
        record_ids: Iterable[str] | None = None,
        reason: str = "",
    ) -> EvidenceDecision:
        batch = self.received_batch(batch_id)
        if batch.status not in {"pending", "partially_accepted"}:
            raise ImportError(f"batch {batch.batch_id!r} is {batch.status}")
        wanted = None if record_ids is None else {str(item) for item in record_ids}
        selected = tuple(record for record in batch.records
                         if wanted is None
                         or str(record.get("record_id")) in wanted)
        if wanted and len(selected) != len(wanted):
            raise KeyError("unknown record id in acceptance scope")
        before = dict(self._hypotheses)
        current = list(self._records.get(batch.source_id, {}).values())
        current_ids = {str(record.get("record_id")) for record in current}
        selected_ids = {str(record.get("record_id")) for record in selected}
        merged = current + [record for record in selected
                            if str(record.get("record_id")) not in current_ids]
        if merged:
            self.import_source(batch.source_id, merged)
        after = dict(self._hypotheses)
        decision = EvidenceDecision(
            decision_id=f"decision-{len(self._evidence_decisions) + 1}",
            batch_id=batch.batch_id,
            source_id=batch.source_id,
            action="accepted" if wanted is None else "partially_accepted",
            recorded_at=time.time(),
            record_ids=frozenset(selected_ids),
            reason=reason,
            excluded_hypotheses=frozenset(
                hid for hid, hypothesis in before.items()
                if not hypothesis.is_retracted
                and hid in after and after[hid].is_retracted),
        )
        self._evidence_decisions.append(decision)
        batch.status = "accepted" if wanted is None else "partially_accepted"
        return decision

    def reject_evidence(self, batch_id: str, *, reason: str = "") -> EvidenceDecision:
        batch = self.received_batch(batch_id)
        decision = EvidenceDecision(
            decision_id=f"decision-{len(self._evidence_decisions) + 1}",
            batch_id=batch.batch_id,
            source_id=batch.source_id,
            action="rejected",
            recorded_at=time.time(),
            record_ids=frozenset(str(record.get("record_id"))
                                 for record in batch.records),
            reason=reason,
        )
        self._evidence_decisions.append(decision)
        batch.status = "rejected"
        return decision

    def withdraw_evidence(
        self, batch_id: str, *,
        record_ids: Iterable[str] | None = None,
        reason: str = "",
    ) -> EvidenceDecision:
        batch = self.received_batch(batch_id)
        accepted_ids = self._accepted_record_ids(batch)
        wanted = None if record_ids is None else {str(item) for item in record_ids}
        withdraw_ids = accepted_ids if wanted is None else accepted_ids & wanted
        if wanted and not withdraw_ids:
            raise KeyError("no accepted record from that batch is in scope")
        remaining = [record for record_id, record
                     in self._records.get(batch.source_id, {}).items()
                     if record_id not in withdraw_ids]
        if remaining:
            self.import_source(batch.source_id, remaining)
        elif batch.source_id in self._records:
            self.revoke_source(batch.source_id)
        decision = EvidenceDecision(
            decision_id=f"decision-{len(self._evidence_decisions) + 1}",
            batch_id=batch.batch_id,
            source_id=batch.source_id,
            action="withdrawn",
            recorded_at=time.time(),
            record_ids=frozenset(withdraw_ids),
            reason=reason,
        )
        self._evidence_decisions.append(decision)
        batch.status = "withdrawn"
        return decision

    def _accepted_record_ids(self, batch: ReceivedBatch) -> set[str]:
        accepted = set()
        for decision in self._evidence_decisions:
            if decision.batch_id == batch.batch_id and decision.action in {
                    "accepted", "partially_accepted"}:
                accepted |= decision.record_ids
            if decision.batch_id == batch.batch_id and decision.action == "withdrawn":
                accepted -= decision.record_ids
        return accepted

    def evidence_decisions(self) -> list[EvidenceDecision]:
        return list(self._evidence_decisions)

    # -------------------------------------------------------- working sets

    def create_hypothesis_set(
        self, set_id: str, hypothesis_ids: Iterable[str],
        description: str = "", activate: bool = False,
        excluded_hypothesis_ids: Iterable[str] = (),
        judgments: dict[str, str] | None = None,
    ) -> HypothesisSet:
        """Save a complete, independently reopenable group of judgments."""
        if not set_id or not isinstance(set_id, str):
            raise ImportError("set_id must be a non-empty string")
        if set_id in self._hyp_sets:
            raise ImportError(f"hypothesis set {set_id!r} already exists; "
                              "saved hypothesis groups are append-only")
        selected = {str(h) for h in hypothesis_ids}
        unknown = selected - set(self._hypotheses)
        if unknown:
            raise KeyError(f"unknown hypothesis ids: {sorted(unknown)}")
        selected_hyps = [self._hypotheses[h] for h in selected]
        for index, left in enumerate(selected_hyps):
            for right in selected_hyps[index + 1:]:
                if (left.effect_id == right.effect_id
                        and left.relation == right.relation
                        and left.cause_id != right.cause_id
                        and self._windows_overlap(left, right)):
                    raise ImportError(
                        "a hypothesis set may pick at most one overlapping "
                        "explanation per (effect, relation) slot")
        excluded = {str(h) for h in excluded_hypothesis_ids}
        unknown |= excluded - set(self._hypotheses)
        if unknown:
            raise KeyError(f"unknown hypothesis ids: {sorted(unknown)}")
        overlap = selected & excluded
        if overlap:
            raise ImportError(
                "a hypothesis cannot be both selected and explicitly excluded")
        hyp_set = HypothesisSet(set_id=set_id,
                                hypothesis_ids=frozenset(selected),
                                description=description,
                                created_at=time.time(),
                                excluded_hypothesis_ids=frozenset(excluded),
                                judgments=dict(judgments or {}))
        self._hyp_sets[set_id] = hyp_set
        if activate:
            self.active_set = set_id
        for state in self._paths.values():
            if state.set_id == set_id:
                state.valid = False
        return hyp_set

    def hypothesis_sets(self) -> list[HypothesisSet]:
        return [self._hyp_sets[k] for k in sorted(self._hyp_sets)]

    def activate_set(self, set_id: str | None) -> None:
        if set_id is not None and set_id not in self._hyp_sets:
            raise KeyError(f"unknown hypothesis set: {set_id!r}")
        self.active_set = set_id

    def explain_hypothesis_set(
        self, set_id: str, *, max_depth: int | None = None,
        at_time: float | None = None,
    ) -> HypothesisSetExplanation:
        hyp_set = self._hyp_sets[set_id]
        selected = tuple(self._hypotheses[h] for h in sorted(hyp_set.hypothesis_ids)
                         if h in self._hypotheses)
        excluded = tuple(self._hypotheses[h]
                         for h in sorted(hyp_set.excluded_hypothesis_ids)
                         if h in self._hypotheses)
        explained: set[str] = set()
        unresolved: set[PendingRef] = set()
        conflicting: set[str] = set()
        for hypothesis in selected:
            result = self.trace(hypothesis.effect_id, max_depth,
                                set_id=set_id, at_time=at_time)
            explained.update(result.events)
            unresolved.update(result.unresolved)
        for hypothesis in selected:
            selected_sources = {claim.source_id for claim in hypothesis.claims}
            for other in self._hypotheses.values():
                if (other.effect_id == hypothesis.effect_id
                        and other.relation == hypothesis.relation
                        and other.cause_id != hypothesis.cause_id
                        and self._windows_overlap(other, hypothesis)):
                    conflicting.update(
                        claim.source_id for claim in other.active_claims
                        if claim.source_id not in selected_sources)
        unexplained = {ref.claimant_id for ref in unresolved}
        for hypothesis_id in hyp_set.hypothesis_ids:
            hypothesis = self._hypotheses.get(hypothesis_id)
            if hypothesis is None or hypothesis.is_retracted or not hypothesis.active_at(at_time):
                unexplained.add(self._missing_set_effect(hypothesis_id))
        return HypothesisSetExplanation(
            set_id=set_id,
            selected=selected,
            excluded=excluded,
            explained_events=tuple(sorted(explained)),
            conflicting_sources=tuple(sorted(conflicting)),
            unexplained_events=tuple(sorted(v for v in unexplained if v)),
            unresolved=tuple(sorted(unresolved,
                                    key=lambda p: (p.claimant_id, p.relation,
                                                   p.target, p.claim.source_id))),
        )

    @staticmethod
    def _missing_set_effect(hypothesis_id: str) -> str:
        try:
            _, rest = hypothesis_id.split("h:", 1)
            effect, _ = rest.split("#", 1)
            return effect
        except ValueError:
            return ""

    def _selected_edges(self, set_id: str | None,
                        at_time: float | None = None
                        ) -> tuple[dict[tuple[str, str, str], Edge], bool]:
        """Edges visible under a working set.

        Unambiguous hypotheses are always visible.  For a disputed slot,
        only the set's pick is traversed; raw evidence for the rejected
        alternatives is still retained on the Hypothesis objects.
        """
        active_hypotheses = [h for h in self._hypotheses.values()
                             if h.active_at(at_time)]
        if set_id is None:
            edges: dict[tuple[str, str, str], Edge] = {}
            for h in active_hypotheses:
                if h.is_retracted:
                    continue
                key = (h.cause_id, h.effect_id, h.relation)
                existing = edges.get(key)
                claims = h.active_claims
                if existing is not None:
                    claims |= existing.claims
                edges[key] = Edge(key[0], key[1], key[2], frozenset(claims))
            return edges, False
        chosen = self._hyp_sets[set_id].hypothesis_ids
        edges = {}
        for hypothesis_id in chosen:
            h = self._hypotheses.get(hypothesis_id)
            if h is not None and h.active_at(at_time) and not h.is_retracted:
                edges[(h.cause_id, h.effect_id, h.relation)] = Edge(
                    h.cause_id, h.effect_id, h.relation,
                    h.active_claims or h.claims)
        ambiguous: set[tuple[str, str, float | None, float | None]] = set()
        for index, left in enumerate(active_hypotheses):
            for right in active_hypotheses[index + 1:]:
                if (left.effect_id == right.effect_id
                        and left.relation == right.relation
                        and left.cause_id != right.cause_id
                        and self._windows_overlap(left, right)):
                    ambiguous.add((left.effect_id, left.relation,
                                   left.valid_start, left.valid_end))
                    ambiguous.add((right.effect_id, right.relation,
                                   right.valid_start, right.valid_end))
        for h in active_hypotheses:
            if h.is_retracted:
                continue
            slot = (h.effect_id, h.relation, h.valid_start, h.valid_end)
            if slot in ambiguous:
                continue
            key = (h.cause_id, h.effect_id, h.relation)
            existing = edges.get(key)
            claims = h.active_claims
            if existing is not None:
                claims |= existing.claims
            edges[key] = Edge(key[0], key[1], key[2], frozenset(claims))
        return edges, True

    # ---------------------------------------------------------------- tracing

    def trace(
        self, seed: str, max_depth: int | None = None,
        *,
        set_id: str | None = "__active__",
        use_set: bool | None = None,
        save: bool = False,
        refresh: bool = False,
        at_time: float | None = None,
    ) -> TraceResult:
        """Walk explicit causal links in both directions from one event.

        Time proximity is never used: only asserted, evidence-backed edges
        are traversed.  When a hypothesis set is active (or ``set_id`` is
        given), disputed slots follow the analyst's chosen explanation.

        ``save=True`` caches the investigation path; after source/manual
        changes only paths whose evidence changed are invalidated, so a
        repeat call recomputes merely the affected investigation paths.
        """
        if set_id == "__active__":
            set_id = self.active_set
        if use_set is False:
            set_id = None
        origin = self.get_event(seed)
        if origin is None:
            raise KeyError(f"unknown event or alias: {seed!r}")
        origin_id = origin.event_id
        depth_key = max_depth
        cache_key = (origin_id, set_id, depth_key, at_time)
        if (not refresh) and (save or cache_key in self._paths):
            state = self._paths.get(cache_key)
            if state is not None and state.valid:
                return state.result

        edge_view, _ = self._selected_edges(set_id, at_time=at_time)
        out_adj: dict[str, list[Edge]] = defaultdict(list)
        in_adj: dict[str, list[Edge]] = defaultdict(list)
        for edge in edge_view.values():
            out_adj[edge.cause_id].append(edge)
            in_adj[edge.effect_id].append(edge)

        def walk(adj: dict[str, list[Edge]]) -> list[EdgeHop]:
            seen_edges: set[tuple[str, str, str]] = set()
            hops: list[EdgeHop] = []
            frontier = [(origin_id, 0)]
            visited = {origin_id}
            while frontier:
                node, depth = frontier.pop(0)
                if max_depth is not None and depth >= max_depth:
                    continue
                for edge in sorted(adj.get(node, []),
                                   key=lambda e: (e.cause_id, e.effect_id, e.relation)):
                    if edge.key() in seen_edges:
                        continue
                    seen_edges.add(edge.key())
                    hops.append(EdgeHop(
                        cause_id=edge.cause_id,
                        effect_id=edge.effect_id,
                        relation=edge.relation,
                        claims=tuple(sorted(edge.claims,
                                            key=lambda c: (c.source_id, c.record_id))),
                    ))
                    nxt = edge.effect_id if node == edge.cause_id else edge.cause_id
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
        result = TraceResult(
            origin_id=origin_id,
            upstream=upstream,
            downstream=downstream,
            events={eid: self._events[eid] for eid in reached if eid in self._events},
            unresolved=unresolved,
        )
        if save or cache_key in self._paths:
            anchors = set(reached)
            for hop in (*upstream, *downstream):
                anchors.add(hop.cause_id)
                anchors.add(hop.effect_id)
            self._paths[cache_key] = PathState(
                seed=origin_id, set_id=set_id, max_depth=depth_key,
                at_time=at_time,
                result=result, reached=frozenset(reached),
                anchors=frozenset(anchors),
                edge_anchors=frozenset(anchors - {origin_id}))
        return result

    def saved_paths(self) -> list[PathState]:
        return [self._paths[k] for k in sorted(self._paths,
                                               key=lambda item: (item[0], item[1] or "",
                                                                 item[2] or -1,
                                                                 item[3] if item[3] is not None else float("-inf")))]

    def stale_paths(self) -> list[PathState]:
        return [state for state in self.saved_paths() if not state.valid]

    # ------------------------------------------------------------- snapshot

    def snapshot(self) -> dict[str, Any]:
        return {
            "version": 4,
            "sources": {
                sid: {"description": src.description,
                      "imported_at": src.imported_at,
                      "trust": src.trust,
                      "scopes": list(src.scopes)}
                for sid, src in self._sources.items()
            },
            "records": {
                sid: [self._jsonable(rec) for rec_id in sorted(batch)
                      for rec in [batch[rec_id]]]
                for sid, batch in sorted(self._records.items())
            },
            "manual_links": [
                {
                    "link_id": link.link_id,
                    "cause": link.cause,
                    "effect": link.effect,
                    "relation": link.relation,
                    "note": link.note,
                    "confidence": link.confidence,
                    "scopes": list(link.scopes),
                    "retracts": [r.as_dict() for r in link.retracts],
                    "created_at": link.created_at,
                    "valid_start": link.valid_start,
                    "valid_end": link.valid_end,
                }
                for link in self.manual_links()
            ],
            "hypothesis_sets": [
                {"set_id": hyp_set.set_id,
                 "hypothesis_ids": sorted(hyp_set.hypothesis_ids),
                 "description": hyp_set.description,
                 "created_at": hyp_set.created_at,
                 "excluded_hypothesis_ids": sorted(hyp_set.excluded_hypothesis_ids),
                 "judgments": hyp_set.judgments}
                for hyp_set in self.hypothesis_sets()
            ],
            "active_set": self.active_set,
            "saved_paths": [
                {"seed": state.seed, "set_id": state.set_id,
                 "max_depth": state.max_depth, "at_time": state.at_time,
                 "valid": state.valid}
                for state in self.saved_paths()
            ],
            "verification_plans": [
                plan.as_dict() for plan in self.verification_plans()
            ],
            "received_batches": [
                batch.as_dict() for batch in self.received_batches()
            ],
            "evidence_decisions": [
                decision.as_dict() for decision in self._evidence_decisions
            ],
            "manual_judgments": [
                {"link_id": judgment.link_id, "action": judgment.action,
                 "recorded_at": judgment.recorded_at, "note": judgment.note,
                 "link": self._manual_link_to_judgment_dict(judgment.link)}
                for judgment in self._manual_judgments
            ],
            "hypothesis_ledger": [h.as_dict() for h in self._hypothesis_ledger.values()],
        }

    @staticmethod
    def _jsonable(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: (value.value if isinstance(value, EventKind) else value)
            for key, value in record.items()
        }

    @staticmethod
    def _manual_link_to_judgment_dict(link: ManualLink | None) -> dict[str, Any] | None:
        if link is None:
            return None
        return {
            "link_id": link.link_id, "cause": link.cause,
            "effect": link.effect, "relation": link.relation,
            "note": link.note, "confidence": link.confidence,
            "scopes": list(link.scopes),
            "retracts": [r.as_dict() for r in link.retracts],
            "created_at": link.created_at,
            "valid_start": link.valid_start,
            "valid_end": link.valid_end,
        }

    @classmethod
    def restore(cls, data: dict[str, Any]) -> "InvestigationStore":
        if data.get("version") not in (1, 2, 3, 4):
            raise ValueError("unsupported snapshot version")
        store = cls()
        for source_id in sorted(data.get("records", {})):
            batch = data["records"][source_id]
            meta = data.get("sources", {}).get(source_id, {})
            store.import_source(source_id, batch,
                                description=meta.get("description", ""),
                                trust=meta.get("trust"),
                                scopes=meta.get("scopes", ()))
            if meta.get("imported_at") is not None:
                store._sources[source_id].imported_at = meta["imported_at"]
        for link in data.get("manual_links", ()):
            created = ManualLink(
                link_id=link["link_id"], cause=link["cause"],
                effect=link["effect"], relation=link["relation"],
                note=link.get("note", ""),
                confidence=link.get("confidence", 0.5),
                scopes=tuple(link.get("scopes", ["manual"])),
                retracts=tuple(RecordRef(r["source_id"], r["record_id"])
                               for r in link.get("retracts", ())),
                created_at=link.get("created_at"),
                valid_start=link.get("valid_start"),
                valid_end=link.get("valid_end"),
            )
            store._manual_links[created.link_id] = created
        store._rebuild()
        for item in data.get("hypothesis_ledger", ()):
            hypothesis = Hypothesis(
                hypothesis_id=item["hypothesis_id"],
                effect_id=item["effect_id"], relation=item["relation"],
                cause_id=item["cause_id"],
                claims=frozenset(RecordRef(c["source_id"], c["record_id"])
                                for c in item.get("claims", ())),
                retracted_claims=frozenset(
                    RecordRef(c["source_id"], c["record_id"])
                    for c in item.get("retracted_claims", ())),
                scopes=frozenset(item.get("scopes", ())),
                confidence=item.get("confidence", 0.5),
                origins=frozenset(item.get("origins", ())),
                valid_start=item.get("valid_start"),
                valid_end=item.get("valid_end"))
            store._hypothesis_ledger[hypothesis.hypothesis_id] = hypothesis
            store._hypotheses.setdefault(hypothesis.hypothesis_id, hypothesis)
        for hyp_set in data.get("hypothesis_sets", ()):
            ids = frozenset(hyp_set["hypothesis_ids"])
            store._hyp_sets[hyp_set["set_id"]] = HypothesisSet(
                set_id=hyp_set["set_id"], hypothesis_ids=ids,
                description=hyp_set.get("description", ""),
                created_at=hyp_set.get("created_at"),
                excluded_hypothesis_ids=frozenset(
                    hyp_set.get("excluded_hypothesis_ids", ())),
                judgments=dict(hyp_set.get("judgments", {})))
        active = data.get("active_set")
        store.active_set = active if active in store._hyp_sets else None
        for item in data.get("saved_paths", ()):
            try:
                result = store.trace(item["seed"], item.get("max_depth"),
                                     set_id=item.get("set_id"),
                                     save=True, refresh=True,
                                     at_time=item.get("at_time"))
            except KeyError:
                continue
            state = store._paths[(result.origin_id, item.get("set_id"),
                                  item.get("max_depth"), item.get("at_time"))]
            state.valid = item.get("valid", True)
        for item in data.get("manual_judgments", ()):
            link_data = item.get("link")
            judgment_link = None
            if link_data is not None:
                judgment_link = ManualLink(
                    link_id=link_data["link_id"], cause=link_data["cause"],
                    effect=link_data["effect"],
                    relation=link_data["relation"],
                    note=link_data.get("note", ""),
                    confidence=link_data.get("confidence", 0.5),
                    scopes=tuple(link_data.get("scopes", ["manual"])),
                    retracts=tuple(RecordRef(r["source_id"], r["record_id"])
                                   for r in link_data.get("retracts", ())),
                    created_at=link_data.get("created_at"),
                    valid_start=link_data.get("valid_start"),
                    valid_end=link_data.get("valid_end"))
            store._manual_judgments.append(ManualJudgment(
                link_id=item["link_id"], action=item.get("action", "created"),
                link=judgment_link, recorded_at=item.get("recorded_at"),
                note=item.get("note", "")))
        if not data.get("manual_judgments"):
            for link in store.manual_links():
                store._manual_judgments.append(ManualJudgment(
                    link_id=link.link_id, action="created", link=link,
                    recorded_at=link.created_at))
        for item in data.get("verification_plans", ()):
            plan = VerificationPlan.from_dict(item)
            store._verification_plans[plan.plan_id] = plan
        for item in data.get("received_batches", ()):
            batch = ReceivedBatch.from_dict(item)
            store._received_batches[batch.batch_id] = batch
        for item in data.get("evidence_decisions", ()):
            store._evidence_decisions.append(EvidenceDecision.from_dict(item))
        return store
