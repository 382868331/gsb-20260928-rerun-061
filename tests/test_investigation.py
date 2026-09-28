from __future__ import annotations

import json

import pytest

from investigation import (
    DuplicateImportError,
    Event,
    EventKind,
    Investigation,
    LinkKind,
    Record,
    Relation,
    Source,
)


def process(event_id: str, pid: int, timestamp: float, **attributes: object) -> Event:
    attributes.update({"pid": pid, "process_name": attributes.get("process_name", "bash")})
    return Event(event_id, EventKind.PROCESS, attributes, timestamp)


def file_event(event_id: str, path: str, timestamp: float) -> Event:
    return Event(event_id, EventKind.FILE, {"path": path}, timestamp)


def conn_event(event_id: str, remote: str, timestamp: float) -> Event:
    return Event(event_id, EventKind.NETWORK, {"remote": remote}, timestamp)


def test_accepts_manual_events_with_source_provenance() -> None:
    case = Investigation()
    case.import_source(
        Source("analyst-note-1", "analyst"),
        [Record(process("proc-1", 4242, 10.0), [])],
    )

    event = case.get_event("proc-1")
    assert event is not None
    assert event.source_id == "analyst-note-1"
    assert case.imported_sources == ("analyst-note-1",)


def test_tracks_explicit_causality_and_ignores_similar_timestamps() -> None:
    case = Investigation()
    parent = process("proc-parent", 100, 10.0)
    child = process("proc-child", 101, 10.1)
    dropped = file_event("file-drop", "/tmp/payload", 10.15)
    callback = conn_event("conn-c2", "203.0.113.9:443", 10.2)
    unrelated = conn_event("conn-nearby", "198.51.100.1:443", 10.21)

    case.import_source(
        "ir-record",
        [
            Record(child, [Relation("proc-parent", LinkKind.PARENT, "in", "process fork from parent")]),
            Record(parent, []),
            Record(
                dropped,
                [Relation("proc-child", LinkKind.SUBJECT, "in", "child wrote executable")],
            ),
            Record(
                callback,
                [Relation("proc-child", LinkKind.SUBJECT, "in", "child opened connection")],
            ),
            Record(unrelated, []),
        ],
    )

    result = case.trace("proc-parent")
    assert set(result.event_ids) == {"proc-parent", "proc-child", "file-drop", "conn-c2"}
    assert "conn-nearby" not in result.event_ids
    assert {hop.target_event_id for hop in result.hops if hop.source_event_id == "proc-child"} == {
        "file-drop",
        "conn-c2",
    }
    assert {hop.source_id for hop in result.hops} == {"ir-record"}
    assert {hop.rationale for hop in result.hops}


def test_missing_parent_remains_unresolved_then_connects_on_later_import() -> None:
    case = Investigation()
    case.import_source(
        "child-source",
        [
            Record(
                process("child", 2, 20.0),
                [Relation("missing-parent", LinkKind.PARENT, "in", "ppid=1")],
            )
        ],
    )

    pending = case.unresolved_relations("missing-parent")
    assert len(pending) == 1
    assert pending[0].anchor_event_id == "child"
    assert case.link_between("missing-parent", "child", LinkKind.PARENT) is None

    case.import_source("parent-source", [process("missing-parent", 1, 5.0)])

    link = case.link_between("missing-parent", "child", LinkKind.PARENT)
    assert link is not None
    assert link.source_id == "child-source"
    assert case.unresolved_relations() == ()


def test_duplicate_import_is_rejected_idempotently() -> None:
    case = Investigation()
    records = [process("proc", 1, 1.0)]
    case.import_source("same-report", records)

    with pytest.raises(DuplicateImportError):
        case.import_source("same-report", [process("proc", 1, 1.0)])

    assert case.trace("proc").event_ids == ("proc",)


def test_revoking_source_removes_its_edges_and_preserves_other_provenance() -> None:
    case = Investigation()
    case.import_source(
        "reliable",
        [
            Record(
                process("parent", 1, 1.0),
                [Relation("child", LinkKind.PARENT, "out", "fork observed")],
            ),
            process("child", 2, 2.0),
        ],
    )
    case.import_source(
        "extra",
        [
            Record(
                process("parent", 1, 1.0),
                [Relation("other", LinkKind.PARENT, "out", "second report fork")],
            )
        ],
    )

    case.revoke_source("extra")

    assert case.get_event("parent") is not None
    assert case.link_between("parent", "child", LinkKind.PARENT) is not None
    assert case.link_between("parent", "other", LinkKind.PARENT) is None
    assert case.unresolved_relations("other") == ()

    case.import_source("extra-v2", [process("other", 3, 3.0)])
    assert case.get_event("other") is not None
    assert case.link_between("parent", "other", LinkKind.PARENT) is None


def test_revoking_one_edge_witness_keeps_link_with_remaining_provenance() -> None:
    case = Investigation()
    case.import_source(
        "witness-a",
        [
            process("alpha", 1, 1.0),
            Record(
                process("beta", 2, 2.0),
                [Relation("alpha", LinkKind.PARENT, "in", "A observed fork")],
            ),
        ],
    )
    case.import_source(
        "witness-b",
        [
            Record(
                process("beta", 2, 2.0),
                [Relation("alpha", LinkKind.PARENT, "in", "B corroborated fork")],
            )
        ],
    )

    case.revoke_source("witness-b")

    link = case.link_between("alpha", "beta", LinkKind.PARENT)
    assert link is not None
    assert link.source_id == "witness-a"
    assert case.get_event("beta") is not None


def test_revoking_introducer_deletes_event_without_revived_relationship() -> None:
    case = Investigation()
    case.import_source(
        "source-a",
        [
            Record(
                process("alpha", 1, 1.0),
                [Relation("beta", LinkKind.PARENT, "out", "A says alpha forked beta")],
            )
        ],
    )
    case.import_source("source-b", [process("beta", 2, 2.0)])
    assert case.link_between("alpha", "beta", LinkKind.PARENT) is not None

    case.revoke_source("source-a")

    assert case.get_event("alpha") is None
    assert case.get_event("beta") is not None
    assert case.link_between("alpha", "beta", LinkKind.PARENT) is None
    assert case.unresolved_relations("alpha") == ()

    case.import_source("source-c", [process("alpha", 1, 1.0)])
    assert case.link_between("alpha", "beta", LinkKind.PARENT) is None


def test_snapshot_records_every_link_provenance_and_json_shape(tmp_path) -> None:
    case = Investigation()
    case.import_source(
        "s1",
        [
            Record(
                process("p", 1, 1.0),
                [Relation("f", LinkKind.SUBJECT, "out", "created file")],
            )
        ],
    )
    case.import_source("s2", [file_event("f", "/tmp/x", 2.0)])

    snapshot_path = case.save_snapshot(tmp_path / "snapshot.json")
    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))

    assert [event["event_id"] for event in payload["events"]] == ["f", "p"]
    link = payload["links"][0]
    assert link["source_event_id"] == "p"
    assert link["target_event_id"] == "f"
    assert link["provenance"] == [["s1", "record-0"]]
    assert link["rationale"] == "created file"


def test_conflicting_identity_for_same_event_id_is_rejected() -> None:
    case = Investigation()
    case.import_source("one", [process("same", 1, 1.0)])

    with pytest.raises(ValueError):
        case.import_source("two", [process("same", 2, 2.0)])
