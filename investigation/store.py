from __future__ import annotations

import time
from copy import deepcopy
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import (
    MANUAL_SOURCE,
    Edge,
    Event,
    EventKind,
    Hypothesis,
    ManualLink,
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
        self._verification_plans: dict[str, Any] = {}
        self._verification_materials: dict[str, Any] = {}
        self._verification_decisions: list[Any] = []

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

    # ------------------------------------------------------ verification plans

    def create_verification_plan(
        self, plan_id: str, checks: Iterable[Any], *,
        seeds: Iterable[str] | None = None,
        description: str = "",
        set_id: str | None = "__active__",
        max_depth: int | None = None,
        at_time: float | None = None,
    ) -> Any:
        from .verification import (
            OutcomePreview, PlannedCheck, VerificationPlan,
        )

        if not plan_id or not isinstance(plan_id, str):
            raise ImportError("plan_id must be a non-empty string")
        if plan_id in self._verification_plans:
            raise ImportError(f"verification plan {plan_id!r} already exists")
        if set_id == "__active__":
            set_id = self.active_set
        if set_id is not None and set_id not in self._hyp_sets:
            raise KeyError(f"unknown hypothesis set: {set_id!r}")

        normalized_checks: list[PlannedCheck] = []
        source_uses: dict[tuple[str, str], list[str]] = defaultdict(list)
        seen_checks: set[str] = set()
        for raw_check in checks:
            check = (raw_check if isinstance(raw_check, PlannedCheck)
                     else PlannedCheck.from_dict(raw_check))
            if check.check_id in seen_checks:
                raise ImportError(f"duplicate planned check {check.check_id!r}")
            seen_checks.add(check.check_id)
            if not check.outcomes:
                raise ImportError(
                    f"planned check {check.check_id!r} must list possible outcomes")
            if self.get_event(check.effect_id) is None:
                raise KeyError(f"unknown planned effect: {check.effect_id!r}")
            effect_id = self.get_event(check.effect_id).event_id
            outcome_ids = set()
            for outcome in check.outcomes:
                if outcome.outcome_id in outcome_ids:
                    raise ImportError(
                        f"duplicate outcome {outcome.outcome_id!r} in "
                        f"check {check.check_id!r}")
                outcome_ids.add(outcome.outcome_id)
                if outcome.cause_id is not None and self.get_event(outcome.cause_id) is None:
                    raise KeyError(f"unknown planned cause: {outcome.cause_id!r}")
                for claim in outcome.retracts:
                    if claim not in self._claim_meta:
                        raise KeyError(f"unknown planned retraction claim: {claim}")
            normalized_checks.append(PlannedCheck(
                check_id=check.check_id, effect_id=effect_id,
                relation=check.relation, source_id=check.source_id,
                record_id=check.record_id, outcomes=check.outcomes,
                note=check.note))
            source_uses[(check.source_id, check.record_id)].append(check.check_id)

        if seeds is None:
            seed_ids = sorted({check.effect_id for check in normalized_checks})
        else:
            seed_ids = []
            for seed in seeds:
                event = self.get_event(str(seed))
                if event is None:
                    raise KeyError(f"unknown planned trace seed: {seed!r}")
                seed_ids.append(event.event_id)

        plan = VerificationPlan(
            plan_id=plan_id, checks=tuple(normalized_checks),
            seeds=tuple(seed_ids), baseline_set_id=set_id,
            description=description, created_at=time.time(),
            hypothesis_snapshot=tuple(self.hypotheses(include_retracted=True,
                                                      at_time=at_time)))
        previews: list[OutcomePreview] = []
        for check in plan.checks:
            repeated_checks = sorted(cid for cid in source_uses[(check.source_id, check.record_id)]
                                     if cid != check.check_id)
            shared_plans = sorted(
                other.plan_id for other in self._verification_plans.values()
                for other_check in other.checks
                if other_check.source_id == check.source_id
                and other.plan_id != plan_id)
            for outcome in check.outcomes:
                preview = self._preview_planned_outcome(
                    plan, check, outcome, seed_ids, set_id,
                    max_depth=max_depth, at_time=at_time)
                preview.shared_source_plan_ids = tuple(dict.fromkeys(
                    tuple(preview.shared_source_plan_ids) + tuple(shared_plans)))
                if repeated_checks:
                    preview.duplicate_check_ids = tuple(repeated_checks)
                previews.append(preview)
        plan.previews = tuple(previews)
        self._verification_plans[plan_id] = plan
        return plan

    def verification_plans(self) -> list[Any]:
        return [self._verification_plans[key]
                for key in sorted(self._verification_plans)]

    def verification_plan(self, plan_id: str) -> Any:
        return self._verification_plans[plan_id]

    def _preview_planned_outcome(
        self, plan: Any, check: Any, outcome: Any, seeds: list[str],
        set_id: str | None, *, max_depth: int | None,
        at_time: float | None,
    ) -> Any:
        from .verification import OutcomePreview

        clone = InvestigationStore.restore(deepcopy(self.snapshot()))
        clone.active_set = set_id
        record = self._planned_record(check, outcome)
        existing = clone._records.get(check.source_id, {})
        clone.import_source(
            check.source_id, [*existing.values(), record],
            description=clone._sources.get(check.source_id, Source("")).description,
            trust=(clone._sources[check.source_id].trust
                   if check.source_id in clone._sources else None),
            scopes=(clone._sources[check.source_id].scopes
                    if check.source_id in clone._sources else ()))
        supported = self._matching_hypothesis_ids(
            clone, check.effect_id, check.relation, outcome, at_time)
        slot_ids = {
            h.hypothesis_id for h in clone.hypotheses(at_time=at_time)
            if h.effect_id == check.effect_id and h.relation == check.relation
            and self._windows_overlap_at(h, None, at_time)
        }
        retracted_ids = set()
        for hypothesis in clone.hypotheses(include_retracted=True, at_time=at_time):
            if outcome.retracts and any(claim in outcome.retracts
                                        for claim in hypothesis.claims):
                retracted_ids.add(hypothesis.hypothesis_id)
        excluded = tuple(sorted((slot_ids | retracted_ids) - set(supported)))
        trial_set_id = self._create_preview_set(
            clone, plan.plan_id, check.check_id, outcome.outcome_id,
            set_id, supported, excluded, at_time=at_time)
        paths = tuple(clone.trace(seed, max_depth, set_id=trial_set_id,
                                  at_time=at_time)
                      for seed in seeds)
        excluded_set = set(excluded)
        remaining_slots: dict[tuple[str, str], list[str]] = defaultdict(list)
        for hypothesis in clone.hypotheses(at_time=at_time):
            if hypothesis.hypothesis_id not in excluded_set:
                remaining_slots[(hypothesis.effect_id,
                                 hypothesis.relation)].append(hypothesis.hypothesis_id)
        groups = [tuple(sorted(ids)) for ids in remaining_slots.values()
                  if len(ids) > 1]
        return OutcomePreview(
            plan_id=plan.plan_id, check_id=check.check_id,
            outcome_id=outcome.outcome_id,
            supported_hypothesis_ids=tuple(sorted(supported)),
            excluded_hypothesis_ids=excluded,
            retained_paths=paths,
            indistinguishable_groups=tuple(groups),
            evidence_claim=RecordRef(check.source_id, check.record_id))

    def _planned_record(self, check: Any, outcome: Any) -> dict[str, Any]:
        event = self.get_event(check.effect_id)
        record = {
            "record_id": check.record_id,
            "kind": event.kind.value,
            "ts": event.ts,
            "aliases": list(event.aliases),
            "refs": [],
        }
        if outcome.cause_id is not None:
            cause = self.get_event(outcome.cause_id)
            record["refs"].append({
                "relation": check.relation,
                "target": cause.event_id,
                "direction": "incoming",
            })
        if outcome.retracts:
            record["retracts"] = [claim.as_dict() for claim in outcome.retracts]
        return record

    def _matching_hypothesis_ids(self, store: "InvestigationStore", effect_id: str,
                                 relation: str, outcome: Any,
                                 at_time: float | None) -> set[str]:
        if outcome.cause_id is None:
            return set()
        cause = store.get_event(outcome.cause_id)
        cause_id = cause.event_id if cause is not None else None
        matched = set()
        for hypothesis in store.hypotheses(at_time=at_time):
            if (hypothesis.effect_id == effect_id
                    and hypothesis.relation == relation
                    and hypothesis.cause_id == cause_id):
                matched.add(hypothesis.hypothesis_id)
        return matched

    @staticmethod
    def _windows_overlap_at(hypothesis: Hypothesis, _: Any,
                            at_time: float | None) -> bool:
        return hypothesis.active_at(at_time)

    def _create_preview_set(self, clone: "InvestigationStore", plan_id: str,
                            check_id: str, outcome_id: str,
                            baseline_set_id: str | None, supported: set[str],
                            excluded: tuple[str, ...], *,
                            at_time: float | None) -> str:
        selected = set(supported)
        if baseline_set_id is not None:
            selected |= set(clone._hyp_sets[baseline_set_id].hypothesis_ids)
        else:
            excluded_by_slot: dict[tuple[str, str], set[str]] = defaultdict(set)
            for hid in excluded:
                hypothesis = clone._hypotheses.get(hid)
                if hypothesis is not None:
                    excluded_by_slot[(hypothesis.effect_id,
                                      hypothesis.relation)].add(hid)
            for hypothesis in clone.hypotheses(at_time=at_time):
                slot = (hypothesis.effect_id, hypothesis.relation)
                if slot not in excluded_by_slot or hypothesis.hypothesis_id in selected:
                    selected.add(hypothesis.hypothesis_id)
        selected = {hid for hid in selected
                    if hid in clone._hypotheses
                    and not clone._hypotheses[hid].is_retracted
                    and hid not in excluded}
        set_id = f"trial:{plan_id}:{check_id}:{outcome_id}"
        clone.create_hypothesis_set(
            set_id, selected,
            description=f"counterfactual preview for {outcome_id}",
            activate=False)
        return set_id

    def study_alternative_outcome(self, plan_id: str, check_id: str,
                                  outcome_id: str) -> "InvestigationStore":
        plan = self.verification_plan(plan_id)
        check = next(c for c in plan.checks if c.check_id == check_id)
        outcome = next(o for o in check.outcomes if o.outcome_id == outcome_id)
        preview = next(p for p in plan.previews
                       if p.check_id == check_id and p.outcome_id == outcome_id)
        clone = InvestigationStore.restore(deepcopy(self.snapshot()))
        record = self._planned_record(check, outcome)
        existing = clone._records.get(check.source_id, {})
        clone.import_source(check.source_id, [*existing.values(), record])
        self._create_preview_set(
            clone, plan.plan_id, check.check_id, outcome_id,
            plan.baseline_set_id, set(preview.supported_hypothesis_ids),
            preview.excluded_hypothesis_ids, at_time=None)
        clone.activate_set(f"trial:{plan_id}:{check_id}:{outcome_id}")
        return clone

    @staticmethod
    def _merge_source_records(source_id: str, incoming: list[dict[str, Any]],
                              existing: dict[str, dict[str, Any]]
                              ) -> dict[str, dict[str, Any]]:
        merged = deepcopy(existing)
        for record in incoming:
            record_id = str(record["record_id"])
            if record_id in merged:
                merged[record_id] = deepcopy(record)
            else:
                merged[record_id] = deepcopy(record)
        return merged

    # ---------------------------------------------------- received materials

    def record_verification_result(
        self, plan_id: str, check_id: str, record: dict[str, Any], *,
        claimed_outcome_id: str | None = None,
        material_id: str | None = None,
    ) -> str:
        from .verification import VerificationMaterial

        plan = self.verification_plan(plan_id)
        check = next((c for c in plan.checks if c.check_id == check_id), None)
        if check is None:
            raise KeyError(f"unknown planned check {check_id!r} in {plan_id!r}")
        record = dict(record)
        record_id = str(record.get("record_id", check.record_id))
        record["record_id"] = record_id
        source_id = str(record.get("source_id", check.source_id))
        record.pop("source_id", None)
        material_id = material_id or f"material-{len(self._verification_materials) + 1}"
        if material_id in self._verification_materials:
            raise ImportError(f"verification material {material_id!r} already exists")
        if claimed_outcome_id is not None and not any(
                o.outcome_id == claimed_outcome_id for o in check.outcomes):
            raise KeyError(f"outcome {claimed_outcome_id!r} was not planned")
        contradictions = self._material_contradictions(
            check, claimed_outcome_id, source_id, record_id, record)
        duplicates = tuple(
            other.material_id for other in self._verification_materials.values()
            if other.source_id == source_id and other.record_id == record_id
            and other.status in {"staged", "accepted"})
        shared_plans = tuple(dict.fromkeys(
            other.plan_id for other in self._verification_materials.values()
            if other.source_id == source_id
            and other.plan_id != plan_id
            and other.status in {"staged", "accepted"}))
        material = VerificationMaterial(
            material_id=material_id, plan_id=plan_id, check_id=check_id,
            claimed_outcome_id=claimed_outcome_id, source_id=source_id,
            record_id=record_id, record=record,
            contradictions=tuple(contradictions),
            duplicate_material_ids=duplicates,
            shared_source_plan_ids=shared_plans,
            received_at=time.time())
        self._verification_materials[material_id] = material
        return material_id

    def _material_contradictions(self, check: Any, claimed_outcome_id: str | None,
                                 source_id: str, record_id: str,
                                 record: dict[str, Any]) -> list[str]:
        contradictions = []
        if claimed_outcome_id is None:
            contradictions.append("unplanned_outcome")
        if (source_id, record_id) != (check.source_id, check.record_id):
            contradictions.append("source_or_record_differs_from_plan")
        observed_cause = self._record_relation_cause(
            record, check.effect_id, check.relation)
        if claimed_outcome_id is not None:
            outcome = next(o for o in check.outcomes
                           if o.outcome_id == claimed_outcome_id)
            expected = None if outcome.cause_id is None else self.get_event(outcome.cause_id)
            expected_id = expected.event_id if expected is not None else None
            if observed_cause != expected_id:
                contradictions.append("observed_relation_differs_from_claimed_outcome")
            expected_retractions = {(r.source_id, r.record_id)
                                    for r in outcome.retracts}
            actual_retractions = {
                (str(r.get("source_id", check.source_id)),
                 str(r.get("record_id", r.get("target"))))
                if isinstance(r, dict) else (check.source_id, str(r))
                for r in record.get("retracts", ())}
            if actual_retractions != expected_retractions:
                contradictions.append("retractions_differ_from_claimed_outcome")
        for other in self._verification_materials.values():
            other_check = self._find_check(other.plan_id, other.check_id)
            other_cause = self._record_relation_cause(
                other.record, other_check.effect_id, other_check.relation)
            if (other_check.effect_id == check.effect_id
                    and other_check.relation == check.relation
                    and other.status in {"staged", "accepted"}
                    and other_cause != observed_cause):
                contradictions.append(f"contradicts_material:{other.material_id}")
        return contradictions

    def _find_check(self, plan_id: str, check_id: str) -> Any:
        plan = self.verification_plan(plan_id)
        return next(c for c in plan.checks if c.check_id == check_id)

    def _record_relation_cause(self, record: dict[str, Any], effect_id: str,
                               relation: str) -> str | None:
        effect = self.get_event(effect_id)
        aliases = set(effect.aliases) if effect is not None else {effect_id}
        for ref in record.get("refs", ()):
            if ref.get("relation") != relation:
                continue
            target = self.get_event(str(ref.get("target", "")))
            if ref.get("direction", "incoming") == "incoming":
                return target.event_id if target is not None else str(ref.get("target"))
            event_aliases = set(record.get("aliases", ())) | {str(record.get("event_id", ""))}
            if event_aliases & aliases:
                return target.event_id if target is not None else str(ref.get("target"))
        return None

    def verification_materials(self, *, only_surprising: bool = False) -> list[Any]:
        items = [self._verification_materials[k]
                 for k in sorted(self._verification_materials)]
        if only_surprising:
            return [item for item in items if item.contradictions
                    or item.duplicate_material_ids or item.shared_source_plan_ids]
        return items

    def surprising_materials(self) -> list[Any]:
        return self.verification_materials(only_surprising=True)

    def accept_verification_materials(
        self, material_ids: Iterable[str], *,
        scope: str = "selected", reason: str = "",
    ) -> list[Any]:
        from .verification import VerificationDecision

        ids = [str(material_id) for material_id in material_ids]
        grouped: dict[str, list[Any]] = defaultdict(list)
        decisions = []
        for material_id in ids:
            material = self._verification_materials[material_id]
            if material.status != "staged":
                raise ImportError(f"material {material_id!r} is {material.status}")
            grouped[material.source_id].append(material)
        for source_id, source_materials in grouped.items():
            by_record = {m.record_id: deepcopy(m.record) for m in source_materials}
            if scope == "planned":
                records_to_import = list(by_record.values())
            elif scope == "selected":
                existing = deepcopy(self._records.get(source_id, {}))
                existing.update(by_record)
                records_to_import = list(existing.values())
            else:
                raise ImportError("scope must be 'selected' or 'planned'")
            source = self._sources.get(source_id)
            self.import_source(
                source_id, records_to_import,
                description=source.description if source else "",
                trust=source.trust if source else None,
                scopes=source.scopes if source else ())
        for material_id in ids:
            material = self._verification_materials[material_id]
            check = self._find_check(material.plan_id, material.check_id)
            outcome = next((o for o in check.outcomes
                            if o.outcome_id == material.claimed_outcome_id), None)
            preview = next((p for p in self.verification_plan(material.plan_id).previews
                            if p.check_id == material.check_id
                            and p.outcome_id == material.claimed_outcome_id), None)
            excluded = (preview.excluded_hypothesis_ids
                        if preview is not None and not material.contradictions else ())
            material.status = "accepted"
            decision = VerificationDecision(
                material_id=material.material_id, action="accepted",
                recorded_at=time.time(), plan_id=material.plan_id,
                check_id=material.check_id,
                outcome_id=material.claimed_outcome_id,
                claim=material.claim, reason=reason,
                excluded_hypothesis_ids=excluded)
            self._verification_decisions.append(decision)
            decisions.append(decision)
        return decisions

    def reject_verification_materials(self, material_ids: Iterable[str], *,
                                      reason: str = "") -> list[Any]:
        from .verification import VerificationDecision

        decisions = []
        for material_id in material_ids:
            material = self._verification_materials[str(material_id)]
            if material.status != "staged":
                raise ImportError(f"material {material_id!r} is {material.status}")
            material.status = "rejected"
            decision = VerificationDecision(
                material_id=material.material_id, action="rejected",
                recorded_at=time.time(), plan_id=material.plan_id,
                check_id=material.check_id,
                outcome_id=material.claimed_outcome_id, claim=None,
                reason=reason)
            self._verification_decisions.append(decision)
            decisions.append(decision)
        return decisions

    def retract_accepted_material(self, material_id: str, *,
                                  reason: str = "") -> bool:
        from .verification import VerificationDecision

        material = self._verification_materials.get(str(material_id))
        if material is None or material.status != "accepted":
            return False
        material.status = "retracted"
        source_batch = deepcopy(self._records.get(material.source_id, {}))
        source_batch.pop(material.record_id, None)
        source = self._sources.get(material.source_id)
        if source_batch:
            self.import_source(
                material.source_id, list(source_batch.values()),
                description=source.description if source else "",
                trust=source.trust if source else None,
                scopes=source.scopes if source else ())
        else:
            self.revoke_source(material.source_id)
        self._verification_decisions.append(VerificationDecision(
            material_id=material.material_id, action="retracted",
            recorded_at=time.time(), plan_id=material.plan_id,
            check_id=material.check_id, outcome_id=material.claimed_outcome_id,
            claim=material.claim, reason=reason))
        return True

    def verification_decisions(self) -> list[Any]:
        return list(self._verification_decisions)

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
            "version": 3,
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
            "manual_judgments": [
                {"link_id": judgment.link_id, "action": judgment.action,
                 "recorded_at": judgment.recorded_at, "note": judgment.note,
                 "link": self._manual_link_to_judgment_dict(judgment.link)}
                for judgment in self._manual_judgments
            ],
            "hypothesis_ledger": [h.as_dict() for h in self._hypothesis_ledger.values()],
            "verification_plans": [plan.as_dict()
                                   for plan in self.verification_plans()],
            "verification_materials": [
                material.as_dict()
                for material in self.verification_materials()],
            "verification_decisions": [
                decision.as_dict()
                for decision in self.verification_decisions()],
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
        if data.get("version") not in (1, 2, 3):
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
        store._restore_verification(data)
        return store

    def _restore_verification(self, data: dict[str, Any]) -> None:
        from .verification import (
            OutcomePreview, PlannedCheck, PlannedOutcome, VerificationDecision,
            VerificationMaterial, VerificationPlan,
        )

        for item in data.get("verification_plans", ()):
            checks = tuple(PlannedCheck.from_dict(check)
                           for check in item.get("checks", ()))
            previews = []
            for preview in item.get("previews", ()):
                previews.append(OutcomePreview(
                    plan_id=preview["plan_id"],
                    check_id=preview["check_id"],
                    outcome_id=preview["outcome_id"],
                    supported_hypothesis_ids=tuple(preview.get("supported_hypothesis_ids", ())),
                    excluded_hypothesis_ids=tuple(preview.get("excluded_hypothesis_ids", ())),
                    retained_paths=tuple(
                        _preview_trace_from_dict(path)
                        for path in preview.get("retained_paths", ())),
                    indistinguishable_groups=tuple(
                        tuple(group) for group in preview.get("indistinguishable_groups", ())),
                    evidence_claim=(RecordRef(preview["evidence_claim"]["source_id"],
                                              preview["evidence_claim"]["record_id"])
                                    if preview.get("evidence_claim") else None),
                    shared_source_plan_ids=tuple(preview.get("shared_source_plan_ids", ())),
                    duplicate_check_ids=tuple(preview.get("duplicate_check_ids", ())),
                ))
            self._verification_plans[item["plan_id"]] = VerificationPlan(
                plan_id=item["plan_id"], checks=checks,
                seeds=tuple(item.get("seeds", ())),
                baseline_set_id=item.get("baseline_set_id"),
                description=item.get("description", ""),
                created_at=item.get("created_at"),
                hypothesis_snapshot=tuple(
                    Hypothesis(
                        hypothesis_id=h["hypothesis_id"], effect_id=h["effect_id"],
                        relation=h["relation"], cause_id=h["cause_id"],
                        claims=frozenset(RecordRef(c["source_id"], c["record_id"])
                                         for c in h.get("claims", ())),
                        retracted_claims=frozenset(
                            RecordRef(c["source_id"], c["record_id"])
                            for c in h.get("retracted_claims", ())),
                        scopes=frozenset(h.get("scopes", ())),
                        confidence=h.get("confidence", 0.5),
                        origins=frozenset(h.get("origins", ())),
                        valid_start=h.get("valid_start"),
                        valid_end=h.get("valid_end"))
                    for h in item.get("hypothesis_snapshot", ())),
                previews=tuple(previews))
        for item in data.get("verification_materials", ()):
            material = VerificationMaterial.from_dict(item)
            self._verification_materials[material.material_id] = material
        for item in data.get("verification_decisions", ()):
            self._verification_decisions.append(
                VerificationDecision.from_dict(item))


def _preview_trace_from_dict(data: dict[str, Any]) -> TraceResult:
    from .models import PendingRef

    def hops(items):
        return [EdgeHop(
            cause_id=item["cause_id"], effect_id=item["effect_id"],
            relation=item["relation"],
            claims=tuple(RecordRef(claim["source_id"], claim["record_id"])
                         for claim in item.get("claims", ())))
            for item in items]

    return TraceResult(
        origin_id=data["origin_id"],
        upstream=hops(data.get("upstream", ())),
        downstream=hops(data.get("downstream", ())),
        events={},
        unresolved=[PendingRef(
            claimant_id=item["claimant_id"], relation=item["relation"],
            direction=item["direction"], target=item["target"],
            claim=RecordRef(item["claim"]["source_id"],
                            item["claim"]["record_id"]))
            for item in data.get("unresolved", ())])
