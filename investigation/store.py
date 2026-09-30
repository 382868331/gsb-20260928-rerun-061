from __future__ import annotations

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
    def conflicting(self) -> bool:
        return len([h for h in self.hypotheses if not h.is_retracted]) > 1


@dataclass
class HypothesisSet:
    set_id: str
    hypothesis_ids: frozenset[str]
    description: str = ""
    created_at: float | None = None


@dataclass
class PathState:
    seed: str
    set_id: str | None
    max_depth: int | None
    result: TraceResult
    reached: frozenset[str]
    anchors: frozenset[str]
    valid: bool = True
    at: float | None = None


@dataclass(frozen=True)
class ManualLinkStatus:
    """Whether a time-bounded analyst judgment currently applies."""

    link: ManualLink
    active: bool
    reason: str = ""


@dataclass
class HypothesisSetReport:
    """What one hypothesis group explains, conflicts with, and misses."""

    set_id: str
    explained_events: tuple[str, ...]
    selections: tuple[tuple[str, str, str], ...]  # (effect, relation, hypothesis_id)
    rejected_hypotheses: tuple[str, ...]
    conflicting_sources: tuple[str, ...]
    unexplained_slots: tuple[tuple[str, str], ...]
    unresolved_refs: tuple[PendingRef, ...]


@dataclass
class SetPathComparison:
    """Whole propagation paths of several hypothesis groups side by side."""

    seed: str
    set_ids: tuple[str | None, ...]
    traces: dict[str | None, TraceResult]
    shared_hops: tuple[EdgeHop, ...]
    unique_hops: dict[str | None, tuple[EdgeHop, ...]]


@dataclass
class SavedGroup:
    """A frozen hypothesis group: selection plus every rejected candidate
    and the rationale for excluding it.  Append-only: reopening never
    deletes the original candidates or their exclusion reasons."""

    group_id: str
    set_id: str
    note: str
    created_at: float | None
    selected: tuple[dict[str, Any], ...]
    excluded: tuple[dict[str, Any], ...]


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
        # Hypothesis-derived state (rebuilt alongside the graph).
        self._hypotheses: dict[str, Hypothesis] = {}
        self._claim_meta: dict[RecordRef, tuple[float, frozenset[str]]] = {}
        self._retractions: dict[RecordRef, frozenset[RecordRef]] = {}
        # Analyst-selected working sets of hypotheses.
        self._hyp_sets: dict[str, HypothesisSet] = {}
        self.active_set: str | None = None
        # Saved investigation paths, invalidated incrementally on change.
        self._paths: dict[tuple[str, str | None, int | None, float | None], PathState] = {}
        # Manual links whose time window excludes the events they name.
        self._manual_inactive: dict[str, str] = {}
        # Append-only archive of saved hypothesis groups.
        self._saved_groups: dict[str, SavedGroup] = {}

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
        valid_from: float | None = None,
        valid_to: float | None = None,
    ) -> str:
        """Record an analyst-made association.

        The link is first-class evidence with its own provenance; it never
         silently merges with a source claim and can be revoked on its own.
        ``valid_from``/``valid_to`` bound the judgment to a time range: a
        local judgment is never generalized to the object's whole history.
        """
        cause = str(cause)
        effect = str(effect)
        relation = str(relation)
        if cause == effect:
            raise ImportError("manual link cannot connect an event to itself")
        if valid_from is not None and valid_to is not None \
                and float(valid_from) > float(valid_to):
            raise ImportError("valid_from must not be after valid_to")
        if link_id is None:
            link_id = f"link-{len(self._manual_links) + 1}-{abs(hash((cause, effect, relation))) % 10_000}"
        link_id = str(link_id)
        refs = tuple(
            r if isinstance(r, RecordRef) else RecordRef(r[0], r[1])
            for r in retracts
        )
        link = ManualLink(
            link_id=link_id,
            cause=cause,
            effect=effect,
            relation=relation,
            note=note,
            confidence=float(confidence),
            scopes=tuple(str(s) for s in scopes),
            retracts=refs,
            created_at=time.time(),
            valid_from=None if valid_from is None else float(valid_from),
            valid_to=None if valid_to is None else float(valid_to),
        )
        self._manual_links[link_id] = link
        self._rebuild(affected_manual={link})
        return link_id

    def adjust_manual_link_window(
        self, link_id: str,
        valid_from: float | None = None,
        valid_to: float | None = None,
    ) -> bool:
        """Adjust the time range of one analyst judgment.

        Only investigation paths whose evidence actually changed are
        invalidated; unrelated records and paths stay untouched.
        """
        link = self._manual_links.get(str(link_id))
        if link is None:
            return False
        if valid_from is not None and valid_to is not None \
                and float(valid_from) > float(valid_to):
            raise ImportError("valid_from must not be after valid_to")
        updated = ManualLink(
            link_id=link.link_id, cause=link.cause, effect=link.effect,
            relation=link.relation, note=link.note,
            confidence=link.confidence, scopes=link.scopes,
            retracts=link.retracts, created_at=link.created_at,
            valid_from=None if valid_from is None else float(valid_from),
            valid_to=None if valid_to is None else float(valid_to),
        )
        self._manual_links[updated.link_id] = updated
        self._rebuild(affected_manual={link, updated})
        return True

    def retract_manual_link(self, link_id: str) -> bool:
        """Revoke one analyst association; only its paths are recomputed."""
        link = self._manual_links.get(str(link_id))
        if link is None:
            return False
        del self._manual_links[str(link_id)]
        self._rebuild(affected_manual={link})
        return True

    def manual_links(self) -> list[ManualLink]:
        return [self._manual_links[k] for k in sorted(self._manual_links)]

    def manual_link_status(self) -> list[ManualLinkStatus]:
        """Every analyst judgment and whether its time window applies."""
        return [
            ManualLinkStatus(
                link=link,
                active=link.link_id not in self._manual_inactive,
                reason=self._manual_inactive.get(link.link_id, ""),
            )
            for link in self.manual_links()
        ]

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
                base.attrs = {**other.attrs, **base.attrs}
                if base.ts is None:
                    base.ts = other.ts
            canonical[root] = base
            for alias in base.aliases:
                alias_index[alias] = root

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

        global_retracted: set[RecordRef] = set()
        for targets in retractions.values():
            global_retracted |= targets

        # 4. Resolve every explicit reference into a raw claim or a pending.
        edge_claims: dict[tuple[str, str, str], set[RecordRef]] = defaultdict(set)
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
                    edge_claims[(cause, effect, relation)].add(claim)

        # 5. Analyst-asserted links contribute claims just like records do.
        #    A time-bounded judgment applies only inside its window: if the
        #    events it names carry timestamps outside the range, the link is
        #    kept as evidence but stays inactive (never generalized).
        manual_inactive: dict[str, str] = {}
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
            effect_event = canonical.get(resolved_effect)
            cause_event = canonical.get(resolved_cause)
            known_ts = next(
                (e.ts for e in (effect_event, cause_event)
                 if e is not None and e.ts is not None), None)
            if not link.applies_at(known_ts):
                manual_inactive[link.link_id] = (
                    f"events outside window [{link.valid_from}, "
                    f"{link.valid_to}]")
                continue
            edge_claims[(resolved_cause, resolved_effect, link.relation)].add(claim)

        # 6. Group raw claims into competing hypotheses per (effect, rel).
        hypotheses: dict[str, Hypothesis] = {}
        grouped: dict[tuple[str, str], dict[str, tuple[set[RecordRef], set[str]]]] = \
            defaultdict(lambda: defaultdict(lambda: (set(), set())))
        for (cause_id, effect_id, relation), claims in edge_claims.items():
            slot = grouped[(effect_id, relation)]
            entry = slot[cause_id]
            entry[0].update(claims)

        for (effect_id, relation), by_cause in grouped.items():
            for cause_id, (claims, _unused) in by_cause.items():
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
                hypothesis_id = Hypothesis.make_id(effect_id, relation, cause_id)
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
                )

        # 7. Repair analyst working sets (drops/retractions pruned) and
        #    determine which saved paths actually changed.
        live_ids = set(hypotheses)
        pruned_sets: dict[str, set[str]] = {}
        for set_id, hyp_set in list(self._hyp_sets.items()):
            kept = hyp_set.hypothesis_ids & live_ids
            if kept != hyp_set.hypothesis_ids:
                pruned_sets[set_id] = set(hyp_set.hypothesis_ids - kept)
                self._hyp_sets[set_id] = HypothesisSet(
                    set_id=set_id,
                    hypothesis_ids=kept,
                    description=hyp_set.description,
                    created_at=hyp_set.created_at,
                )

        changed_anchors = self._changed_anchors(
            affected_source=affected_source,
            affected_manual=affected_manual,
            prev_hypotheses=self._hypotheses,
            new_hypotheses=hypotheses,
            pruned_sets=pruned_sets,
        )
        # Unresolved references are part of a path's conclusion too: a
        # new or retracted pending ref touching a reached event
        # invalidates that path.
        prev_pending = self._pending
        for key in prev_pending.keys() ^ pending.keys():
            ref = prev_pending.get(key) or pending.get(key)
            if ref is not None:
                changed_anchors.add(ref.claimant_id)
        # Paths whose seed or reached nodes vanished entirely are stale too.
        live_nodes = set(canonical)

        self._events = canonical
        self._alias_index = alias_index
        self._edges = {
            key: Edge(key[0], key[1], key[2], frozenset(claims))
            for key, claims in edge_claims.items()
        }
        self._pending = pending
        self._manual_inactive = manual_inactive
        self._hypotheses = hypotheses
        self._claim_meta = claim_meta
        self._retractions = {k: frozenset(v) for k, v in retractions.items()}
        for state in self._paths.values():
            if (state.anchors & changed_anchors
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
        # A window adjustment keeps the same claim but changes when it
        # applies; paths observed at a moment depend on it too.
        window_changed: set[RecordRef] = set()
        windows_by_claim: dict[RecordRef, set[tuple[float | None, float | None]]] = \
            defaultdict(set)
        for link in affected_manual:
            windows_by_claim[link.claim()].add((link.valid_from, link.valid_to))
        for claim, windows in windows_by_claim.items():
            if len(windows) > 1:
                window_changed.add(claim)
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
            if (old.claims != new.claims
                    or old.retracted_claims != new.retracted_claims
                    or window_changed & new.claims):
                touch_hypothesis(new)

        for set_id, missing in pruned_sets.items():
            for state in self._paths.values():
                if state.set_id == set_id:
                    state.valid = False
        return changed

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

    def hypotheses(self, include_retracted: bool = False) -> list[Hypothesis]:
        items = [h for h in self._hypotheses.values()
                 if include_retracted or not h.is_retracted]
        return sorted(items, key=lambda h: (h.effect_id, h.relation,
                                            -h.confidence, h.cause_id))

    def conflict_groups(self, include_retracted: bool = False
                        ) -> list[ConflictGroup]:
        slots: dict[tuple[str, str], list[Hypothesis]] = defaultdict(list)
        for hypothesis in self.hypotheses(include_retracted=include_retracted):
            slots[(hypothesis.effect_id, hypothesis.relation)].append(hypothesis)
        groups = [ConflictGroup(effect_id=effect_id, relation=relation,
                                hypotheses=hyps)
                  for (effect_id, relation), hyps in sorted(slots.items())
                  if len(hyps) > 1]
        return groups

    def hypothesis_evidence(self, hypothesis_id: str) -> Hypothesis:
        return self._hypotheses[hypothesis_id]

    def retractions(self) -> dict[RecordRef, tuple[RecordRef, ...]]:
        return {claim: tuple(sorted(targets,
                                    key=lambda c: (c.source_id, c.record_id)))
                for claim, targets in sorted(
                    self._retractions.items(),
                    key=lambda kv: (kv[0].source_id, kv[0].record_id))}

    # -------------------------------------------------------- working sets

    def create_hypothesis_set(
        self, set_id: str, hypothesis_ids: Iterable[str],
        description: str = "", activate: bool = False,
    ) -> HypothesisSet:
        """Pin one explanation per disputed slot for continued tracking."""
        if not set_id or not isinstance(set_id, str):
            raise ImportError("set_id must be a non-empty string")
        selected = {str(h) for h in hypothesis_ids}
        unknown = selected - set(self._hypotheses)
        if unknown:
            raise KeyError(f"unknown hypothesis ids: {sorted(unknown)}")
        slots = [(self._hypotheses[h].effect_id, self._hypotheses[h].relation)
                 for h in selected]
        if len(slots) != len(set(slots)):
            raise ImportError(
                "a hypothesis set may pick at most one explanation per "
                "(effect, relation) slot")
        hyp_set = HypothesisSet(set_id=set_id,
                                hypothesis_ids=frozenset(selected),
                                description=description,
                                created_at=time.time())
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

    # ---------------------------------------------------- group comparison

    def explain_set(self, set_id: str, seed: str | None = None,
                    max_depth: int | None = None) -> HypothesisSetReport:
        """Report what one hypothesis group explains and what it misses.

        The report covers the whole propagation path(s) reachable under
        the group's selections - not a single parent/child slot - and
        lists the sources behind rejected alternatives plus the events
        and references the group still cannot explain.
        """
        hyp_set = self._hyp_sets.get(set_id)
        if hyp_set is None:
            raise KeyError(f"unknown hypothesis set: {set_id!r}")
        selected = [self._hypotheses[h] for h in sorted(hyp_set.hypothesis_ids)
                    if h in self._hypotheses]
        explained: set[str] = set()
        for hypothesis in selected:
            explained.add(hypothesis.cause_id)
            explained.add(hypothesis.effect_id)
        seeds = [seed] if seed is not None else sorted(
            {state.seed for state in self._paths.values()
             if state.set_id == set_id})
        unresolved: dict[tuple[str, str, str], PendingRef] = {}
        for one_seed in seeds:
            try:
                result = self.trace(one_seed, max_depth, set_id=set_id)
            except KeyError:
                continue
            explained.update(result.events)
            for hop in (*result.upstream, *result.downstream):
                explained.add(hop.cause_id)
                explained.add(hop.effect_id)
            for pending_ref in result.unresolved:
                key = (pending_ref.claimant_id, pending_ref.relation,
                       pending_ref.target)
                unresolved[key] = pending_ref
        chosen_slots = {(h.effect_id, h.relation) for h in selected}
        rejected: list[Hypothesis] = []
        conflicting_sources: set[str] = set()
        for hypothesis in self._hypotheses.values():
            if (hypothesis.effect_id, hypothesis.relation) in chosen_slots \
                    and hypothesis.hypothesis_id not in hyp_set.hypothesis_ids:
                rejected.append(hypothesis)
                conflicting_sources |= hypothesis.origins
        unexplained_slots = tuple(sorted(
            (group.effect_id, group.relation)
            for group in self.conflict_groups()
            if group.effect_id in explained
            and (group.effect_id, group.relation) not in chosen_slots))
        return HypothesisSetReport(
            set_id=set_id,
            explained_events=tuple(sorted(explained)),
            selections=tuple(
                (h.effect_id, h.relation, h.hypothesis_id) for h in selected),
            rejected_hypotheses=tuple(
                h.hypothesis_id for h in sorted(
                    rejected, key=lambda item: item.hypothesis_id)),
            conflicting_sources=tuple(sorted(conflicting_sources)),
            unexplained_slots=unexplained_slots,
            unresolved_refs=tuple(
                unresolved[key] for key in sorted(unresolved)),
        )

    def compare_set_paths(
        self, seed: str, set_ids: Iterable[str | None] | None = None,
        max_depth: int | None = None, at: float | None = None,
    ) -> SetPathComparison:
        """Trace whole propagation paths under several hypothesis groups.

        Every group is traced independently from the same seed; the
        result shows the hops all groups share and the hops unique to
        each group, so conflicting assumptions can be compared path by
        path instead of relation by relation.
        """
        if set_ids is None:
            set_ids = [None, *sorted(self._hyp_sets)]
        set_ids = tuple(set_ids)
        traces: dict[str | None, TraceResult] = {}
        hop_sets: dict[str | None, set[tuple[str, str, str]]] = {}
        for one_set in set_ids:
            result = self.trace(seed, max_depth, set_id=one_set, at=at)
            traces[one_set] = result
            hop_sets[one_set] = {
                (h.cause_id, h.relation, h.effect_id)
                for h in (*result.upstream, *result.downstream)}
        if hop_sets:
            shared_keys = set.intersection(*hop_sets.values())
        else:
            shared_keys = set()

        def hops_of(result: TraceResult) -> dict[tuple[str, str, str], EdgeHop]:
            return {(h.cause_id, h.relation, h.effect_id): h
                    for h in (*result.upstream, *result.downstream)}

        shared: list[EdgeHop] = []
        unique: dict[str | None, tuple[EdgeHop, ...]] = {}
        for one_set in set_ids:
            hops = hops_of(traces[one_set])
            if one_set == set_ids[0]:
                shared = [hops[key] for key in sorted(shared_keys)
                          if key in hops]
            unique[one_set] = tuple(
                hops[key] for key in sorted(hop_sets[one_set] - shared_keys))
        return SetPathComparison(
            seed=traces[set_ids[0]].origin_id if set_ids else str(seed),
            set_ids=set_ids, traces=traces,
            shared_hops=tuple(shared), unique_hops=unique)

    # ------------------------------------------------------- saved groups

    def save_group(
        self, set_id: str, group_id: str | None = None, note: str = "",
        reasons: dict[str, str] | None = None,
    ) -> str:
        """Freeze one hypothesis group for independent reopening.

        The archive keeps the selected hypotheses *and* every rejected
        candidate with its exclusion rationale; neither is ever deleted,
        even if the live set or the underlying evidence later changes.
        """
        hyp_set = self._hyp_sets.get(set_id)
        if hyp_set is None:
            raise KeyError(f"unknown hypothesis set: {set_id!r}")
        if group_id is None:
            group_id = f"group-{len(self._saved_groups) + 1}"
        group_id = str(group_id)
        if group_id in self._saved_groups:
            raise ImportError(
                f"saved group {group_id!r} already exists; "
                "saved groups are append-only")
        reasons = reasons or {}
        chosen_slots = {
            (self._hypotheses[h].effect_id, self._hypotheses[h].relation)
            for h in hyp_set.hypothesis_ids if h in self._hypotheses}
        selected = tuple(
            self._hypotheses[h].as_dict()
            for h in sorted(hyp_set.hypothesis_ids)
            if h in self._hypotheses)
        excluded: list[dict[str, Any]] = []
        for hypothesis in self.hypotheses(include_retracted=True):
            if (hypothesis.effect_id, hypothesis.relation) in chosen_slots \
                    and hypothesis.hypothesis_id not in hyp_set.hypothesis_ids:
                entry = hypothesis.as_dict()
                entry["exclusion_reason"] = reasons.get(
                    hypothesis.hypothesis_id,
                    f"not selected in hypothesis set {set_id!r}")
                excluded.append(entry)
        self._saved_groups[group_id] = SavedGroup(
            group_id=group_id, set_id=set_id, note=note,
            created_at=time.time(), selected=selected,
            excluded=tuple(excluded))
        return group_id

    def saved_groups(self) -> list[SavedGroup]:
        return [self._saved_groups[k] for k in sorted(self._saved_groups)]

    def reopen_group(self, group_id: str) -> SavedGroup:
        """Reopen one saved group exactly as archived, independently of
        the live store and of any other saved group."""
        try:
            return self._saved_groups[str(group_id)]
        except KeyError:
            raise KeyError(f"unknown saved group: {group_id!r}") from None

    def activate_saved_group(
        self, group_id: str, set_id: str | None = None,
        activate: bool = False,
    ) -> HypothesisSet:
        """Re-create a working set from an archived group's selection.

        Candidates that no longer have live evidence are skipped, but the
        archive itself is left untouched.
        """
        group = self.reopen_group(group_id)
        live_ids = [entry["hypothesis_id"] for entry in group.selected
                    if entry["hypothesis_id"] in self._hypotheses]
        new_set_id = set_id or f"{group.group_id}-reopened"
        return self.create_hypothesis_set(
            new_set_id, live_ids,
            description=f"reopened from saved group {group.group_id!r}",
            activate=activate)

    def _selected_edges(self, set_id: str | None
                        ) -> tuple[dict[tuple[str, str, str], Edge], bool]:
        """Edges visible under a working set.

        Unambiguous hypotheses are always visible.  For a disputed slot,
        only the set's pick is traversed; raw evidence for the rejected
        alternatives is still retained on the Hypothesis objects.
        """
        if set_id is None:
            return dict(self._edges), False
        chosen = self._hyp_sets[set_id].hypothesis_ids
        disputed_slots = {(g.effect_id, g.relation)
                          for g in self.conflict_groups(include_retracted=True)}
        edges: dict[tuple[str, str, str], Edge] = {}
        for hypothesis_id in chosen:
            h = self._hypotheses[hypothesis_id]
            edges[(h.cause_id, h.effect_id, h.relation)] = Edge(
                h.cause_id, h.effect_id, h.relation,
                h.active_claims or h.claims)
        for key, edge in self._edges.items():
            if (key[1], key[2]) not in disputed_slots:
                edges[key] = edge
        return edges, True

    # ---------------------------------------------------------------- tracing

    def _edge_valid_at(self, edge: Edge, at: float | None) -> bool:
        """Whether any claim behind an edge holds at moment ``at``.

        Source-record claims are timeless; only time-bounded manual
        judgments can be excluded by the observation moment.
        """
        if at is None:
            return True
        for claim in edge.claims:
            if claim.source_id != MANUAL_SOURCE:
                return True
            link = self._manual_links.get(claim.record_id)
            if link is not None and link.applies_at(at):
                return True
        return False

    def trace(
        self, seed: str, max_depth: int | None = None,
        *,
        set_id: str | None = "__active__",
        use_set: bool | None = None,
        save: bool = False,
        refresh: bool = False,
        at: float | None = None,
    ) -> TraceResult:
        """Walk explicit causal links in both directions from one event.

        Time proximity is never used: only asserted, evidence-backed edges
        are traversed.  When a hypothesis set is active (or ``set_id`` is
        given), disputed slots follow the analyst's chosen explanation.

        ``save=True`` caches the investigation path; after source/manual
        changes only paths whose evidence changed are invalidated, so a
        repeat call recomputes merely the affected investigation paths.

        ``at`` observes the graph at one moment: time-bounded manual
        judgments outside their window do not apply then, so the same
        object can show different relations in different phases.
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
        cache_key = (origin_id, set_id, depth_key, at)
        if (not refresh) and (save or cache_key in self._paths):
            state = self._paths.get(cache_key)
            if state is not None and state.valid:
                return state.result

        edge_view, _ = self._selected_edges(set_id)
        if at is not None:
            edge_view = {key: edge for key, edge in edge_view.items()
                         if self._edge_valid_at(edge, at)}
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
                result=result, reached=frozenset(reached),
                anchors=frozenset(anchors), at=at)
        return result

    def saved_paths(self) -> list[PathState]:
        return [self._paths[k] for k in sorted(
            self._paths,
            key=lambda item: (item[0], item[1] or "", item[2] or -1,
                              item[3] if item[3] is not None else -1))]

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
                    "valid_from": link.valid_from,
                    "valid_to": link.valid_to,
                }
                for link in self.manual_links()
            ],
            "hypothesis_sets": [
                {"set_id": hyp_set.set_id,
                 "hypothesis_ids": sorted(hyp_set.hypothesis_ids),
                 "description": hyp_set.description,
                 "created_at": hyp_set.created_at}
                for hyp_set in self.hypothesis_sets()
            ],
            "active_set": self.active_set,
            "saved_paths": [
                {"seed": state.seed, "set_id": state.set_id,
                 "max_depth": state.max_depth, "valid": state.valid,
                 "at": state.at}
                for state in self.saved_paths()
            ],
            "saved_groups": [
                {"group_id": group.group_id, "set_id": group.set_id,
                 "note": group.note, "created_at": group.created_at,
                 "selected": list(group.selected),
                 "excluded": list(group.excluded)}
                for group in self.saved_groups()
            ],
        }

    @staticmethod
    def _jsonable(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: (value.value if isinstance(value, EventKind) else value)
            for key, value in record.items()
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
                valid_from=link.get("valid_from"),
                valid_to=link.get("valid_to"),
            )
            store._manual_links[created.link_id] = created
        store._rebuild()
        for hyp_set in data.get("hypothesis_sets", ()):
            ids = frozenset(hyp_set["hypothesis_ids"]) & set(store._hypotheses)
            store._hyp_sets[hyp_set["set_id"]] = HypothesisSet(
                set_id=hyp_set["set_id"], hypothesis_ids=ids,
                description=hyp_set.get("description", ""),
                created_at=hyp_set.get("created_at"))
        active = data.get("active_set")
        store.active_set = active if active in store._hyp_sets else None
        for item in data.get("saved_paths", ()):
            try:
                result = store.trace(item["seed"], item.get("max_depth"),
                                     set_id=item.get("set_id"),
                                     save=True, refresh=True,
                                     at=item.get("at"))
            except KeyError:
                continue
            state = store._paths[(result.origin_id, item.get("set_id"),
                                  item.get("max_depth"), item.get("at"))]
            state.valid = item.get("valid", True)
        for group in data.get("saved_groups", ()):
            store._saved_groups[group["group_id"]] = SavedGroup(
                group_id=group["group_id"], set_id=group["set_id"],
                note=group.get("note", ""),
                created_at=group.get("created_at"),
                selected=tuple(group.get("selected", ())),
                excluded=tuple(group.get("excluded", ())))
        return store
