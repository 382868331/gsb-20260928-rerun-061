from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .errors import DuplicateImportError
from .models import Event, EventKind, Link, LinkKind, Relation, Source


@dataclass(frozen=True, slots=True)
class Record:
    event: Event
    relations: tuple[Relation, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "relations", tuple(self.relations))


@dataclass(frozen=True, slots=True)
class PendingRelation:
    anchor_event_id: str
    missing_event_id: str
    kind: LinkKind
    direction: str
    rationale: str
    source_id: str
    record_id: str

    def key(self) -> tuple[object, ...]:
        return (
            self.anchor_event_id,
            self.missing_event_id,
            self.kind,
            self.source_id,
            self.record_id,
        )

@dataclass(frozen=True, slots=True)
class Hop:
    source_event_id: str
    target_event_id: str
    kind: LinkKind
    source_id: str
    record_id: str
    rationale: str


@dataclass(frozen=True, slots=True)
class TraceResult:
    start_event_id: str
    event_ids: tuple[str, ...]
    hops: tuple[Hop, ...]


class Investigation:
    def __init__(self) -> None:
        self._events: dict[str, Event] = {}
        self._event_records: dict[str, set[tuple[str, str]]] = {}
        self._links: dict[tuple[str, str, LinkKind], Link] = {}
        self._link_refs: dict[tuple[str, str, LinkKind], set[tuple[str, str]]] = {}
        self._pending: dict[str, set[PendingRelation]] = {}
        self._sources: dict[str, Source] = {}

    @property
    def imported_sources(self) -> tuple[str, ...]:
        return tuple(self._sources)

    def import_source(
        self,
        source: Source | str,
        records: Iterable[Record | tuple[Event, Iterable[Relation]] | Event],
    ) -> None:
        source = Source(source) if isinstance(source, str) else source
        if source.source_id in self._sources:
            raise DuplicateImportError(source.source_id)

        normalized = [self._normalize_record(record) for record in records]
        self._validate_new_events(normalized)
        self._sources[source.source_id] = source

        for record_index, record in enumerate(normalized):
            event = record.event
            relations = record.relations
            record_id = event.record_id or f"record-{record_index}"
            self._store_event(source.source_id, record_id, event)
            for relation in relations:
                self._store_relation(
                    source.source_id,
                    record_id,
                    event.event_id,
                    relation,
                )

    def revoke_source(self, source_id: str) -> None:
        if source_id not in self._sources:
            return

        deleted_events = {
            event_id
            for event_id, refs in self._event_records.items()
            if all(source == source_id for source, _ in refs)
        }

        for key, link in list(self._links.items()):
            src_id, dst_id, kind = key
            if src_id not in deleted_events and dst_id not in deleted_events:
                continue
            refs = self._link_refs.get(key, set())
            surviving_refs = {(s, r) for s, r in refs if s != source_id}
            anchor_id = dst_id if src_id in deleted_events else src_id
            anchor_alive = anchor_id in self._events and anchor_id not in deleted_events
            if anchor_alive:
                for surviving_source, surviving_record in surviving_refs:
                    direction = "out" if src_id == anchor_id else "in"
                    entry = PendingRelation(
                        anchor_event_id=anchor_id,
                        missing_event_id=deleted_events.intersection({src_id, dst_id}).pop(),
                        kind=kind,
                        direction=direction,
                        rationale=link.rationale,
                        source_id=surviving_source,
                        record_id=surviving_record,
                    )
                    self._pending.setdefault(entry.missing_event_id, set()).add(entry)
            self._links.pop(key, None)
            self._link_refs.pop(key, None)

        for event_id in deleted_events:
            del self._events[event_id]
            self._event_records.pop(event_id, None)
            self._pending.pop(event_id, None)

        for key, refs in list(self._link_refs.items()):
            remaining = {(s, r) for s, r in refs if s != source_id}
            if remaining:
                self._link_refs[key] = remaining
            else:
                self._links.pop(key, None)
                self._link_refs.pop(key, None)

        for event_id, refs in list(self._event_records.items()):
            remaining = {(s, r) for s, r in refs if s != source_id}
            if remaining:
                self._event_records[event_id] = remaining
            else:
                self._event_records.pop(event_id, None)

        for missing_id, entries in list(self._pending.items()):
            remaining = {entry for entry in entries if entry.source_id != source_id}
            if remaining:
                self._pending[missing_id] = remaining
            else:
                del self._pending[missing_id]

        del self._sources[source_id]

    def get_event(self, event_id: str) -> Event | None:
        return self._events.get(event_id)

    def link_between(
        self,
        source_event_id: str,
        target_event_id: str,
        kind: LinkKind = LinkKind.OTHER,
    ) -> Link | None:
        return self._links.get((source_event_id, target_event_id, kind))

    def unresolved_relations(self, missing_event_id: str | None = None) -> tuple[PendingRelation, ...]:
        if missing_event_id is not None:
            return tuple(sorted(self._pending.get(missing_event_id, set()), key=lambda p: p.key()))
        return tuple(
            sorted(
                (entry for entries in self._pending.values() for entry in entries),
                key=lambda p: p.key(),
            )
        )

    def trace(
        self,
        start_event_id: str,
        *,
        direction: str = "both",
        max_depth: int | None = None,
    ) -> TraceResult:
        if start_event_id not in self._events:
            raise KeyError(f"unknown event: {start_event_id}")
        if direction not in {"both", "in", "out"}:
            raise ValueError("direction must be 'both', 'in', or 'out'")

        visited = {start_event_id}
        events = [start_event_id]
        hops: list[Hop] = []
        queue = deque([(start_event_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if max_depth is not None and depth >= max_depth:
                continue
            for (src, dst, kind), link in self._links.items():
                if direction in {"out", "both"} and src == current:
                    hop = self._hop(link)
                    if hop not in hops:
                        hops.append(hop)
                    if dst not in visited:
                        visited.add(dst)
                        events.append(dst)
                        queue.append((dst, depth + 1))
                elif direction in {"in", "both"} and dst == current:
                    hop = self._hop(link)
                    if hop not in hops:
                        hops.append(hop)
                    if src not in visited:
                        visited.add(src)
                        events.append(src)
                        queue.append((src, depth + 1))

        return TraceResult(start_event_id, tuple(events), tuple(hops))

    def to_dict(self) -> dict[str, object]:
        return {
            "sources": [
                {"source_id": source.source_id, "producer": source.producer}
                for source in self._sources.values()
            ],
            "events": [
                {
                    "event_id": event.event_id,
                    "kind": event.kind.value,
                    "attributes": event.attributes,
                    "observed_at": event.observed_at,
                    "source_id": event.source_id,
                    "record_id": event.record_id,
                    "provenance": sorted(self._event_records[event.event_id]),
                }
                for event in sorted(self._events.values(), key=lambda item: item.event_id)
            ],
            "links": [
                {
                    "source_event_id": link.source_event_id,
                    "target_event_id": link.target_event_id,
                    "kind": link.kind.value,
                    "source_id": link.source_id,
                    "record_id": link.record_id,
                    "rationale": link.rationale,
                    "provenance": sorted(self._link_refs[key]),
                }
                for key, link in sorted(self._links.items(), key=lambda item: item[0])
            ],
            "unresolved_relations": [
                {
                    "anchor_event_id": entry.anchor_event_id,
                    "missing_event_id": entry.missing_event_id,
                    "kind": entry.kind.value,
                    "direction": entry.direction,
                    "rationale": entry.rationale,
                    "source_id": entry.source_id,
                    "record_id": entry.record_id,
                }
                for entry in self.unresolved_relations()
            ],
        }

    def save_snapshot(self, path: str | Path) -> Path:
        snapshot_path = Path(path)
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return snapshot_path

    @staticmethod
    def _normalize_record(
        record: Record | tuple[Event, Iterable[Relation]] | Event,
    ) -> Record:
        if isinstance(record, Record):
            return record
        if isinstance(record, Event):
            return Record(record)
        event, relations = record
        return Record(event, tuple(relations))

    def _validate_new_events(self, records: list[Record]) -> None:
        batch: dict[str, Event] = {}
        for record in records:
            event = record.event
            existing = self._events.get(event.event_id) or batch.get(event.event_id)
            if existing is not None and not self._same_identity(existing, event):
                raise ValueError(f"conflicting event identity: {event.event_id}")
            batch[event.event_id] = event

    @staticmethod
    def _same_identity(left: Event, right: Event) -> bool:
        return (
            left.kind == right.kind
            and left.attributes == right.attributes
            and left.observed_at == right.observed_at
        )

    def _store_event(self, source_id: str, record_id: str, event: Event) -> None:
        if event.event_id not in self._events:
            self._events[event.event_id] = event.with_source(source_id, record_id)
            self._event_records[event.event_id] = set()
        self._event_records[event.event_id].add((source_id, record_id))
        self._connect_pending(event.event_id)

    def _store_relation(
        self,
        source_id: str,
        record_id: str,
        anchor_id: str,
        relation: Relation,
    ) -> None:
        if relation.direction == "out":
            src_id, dst_id = anchor_id, relation.other_id
        else:
            src_id, dst_id = relation.other_id, anchor_id

        if src_id in self._events and dst_id in self._events:
            self._add_link(
                src_id,
                dst_id,
                relation.kind,
                source_id,
                record_id,
                relation.rationale,
            )
            return

        missing_id = dst_id if dst_id not in self._events else src_id
        entry = PendingRelation(
            anchor_event_id=anchor_id,
            missing_event_id=missing_id,
            kind=relation.kind,
            direction=relation.direction,
            rationale=relation.rationale,
            source_id=source_id,
            record_id=record_id,
        )
        self._pending.setdefault(missing_id, set()).add(entry)

    def _connect_pending(self, arrived_event_id: str) -> None:
        entries = self._pending.pop(arrived_event_id, set())
        for entry in entries:
            if entry.direction == "out":
                src_id, dst_id = entry.anchor_event_id, entry.missing_event_id
            else:
                src_id, dst_id = entry.missing_event_id, entry.anchor_event_id
            self._add_link(
                src_id,
                dst_id,
                entry.kind,
                entry.source_id,
                entry.record_id,
                entry.rationale,
            )

    def _add_link(
        self,
        src_id: str,
        dst_id: str,
        kind: LinkKind,
        source_id: str,
        record_id: str,
        rationale: str,
    ) -> None:
        key = (src_id, dst_id, kind)
        if key not in self._links:
            self._links[key] = Link(
                source_event_id=src_id,
                target_event_id=dst_id,
                kind=kind,
                source_id=source_id,
                record_id=record_id,
                rationale=rationale,
            )
            self._link_refs[key] = set()
        self._link_refs[key].add((source_id, record_id))

    @staticmethod
    def _hop(link: Link) -> Hop:
        return Hop(
            source_event_id=link.source_event_id,
            target_event_id=link.target_event_id,
            kind=link.kind,
            source_id=link.source_id,
            record_id=link.record_id,
            rationale=link.rationale,
        )
