import json

import pytest

from investigation import InvestigationStore
from investigation.snapshot import load_snapshot, save_snapshot


def proc(record_id, pid, parent_guid=None, ts=0.0, guid=None, event_id=None,
         extra_aliases=()):
    record = {
        "record_id": record_id,
        "kind": "process",
        "ts": ts,
        "pid": pid,
        "name": "susp.bin",
        "aliases": tuple(extra_aliases) + (("guid:" + guid,) if guid else ()),
        "refs": [],
    }
    if event_id:
        record["event_id"] = event_id
    if parent_guid is not None:
        record["refs"].append({"relation": "parent", "target": parent_guid})
    return record


def test_out_of_order_parent_arrives_later_then_connects():
    store = InvestigationStore()
    store.import_source("edr-a", [proc("c1", pid=4444, parent_guid="guid:parent", ts=100.0,
                                     guid="child")])
    child = store.get_event("guid:child")
    assert store.edges() == []
    pending = store.pending_refs()
    assert len(pending) == 1
    assert pending[0].target == "guid:parent"

    store.import_source("edr-b", [proc("p1", pid=1234, ts=90.0,
                                  guid="parent")])
    parent = store.get_event("guid:parent")
    edge, = store.edges()
    assert edge.cause_id == parent.event_id
    assert edge.effect_id == child.event_id
    assert edge.relation == "parent"
    assert store.pending_refs() == []

    result = store.trace("guid:child")
    assert result.origin_id == child.event_id
    assert [hop.cause_id for hop in result.upstream] == [parent.event_id]
    assert result.downstream == []
    claims = result.upstream[0].claims
    assert [(c.source_id, c.record_id) for c in claims] == [("edr-a", "c1")]


def test_close_in_time_but_unrelated_events_are_not_linked():
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("x", pid=100, ts=1000.000, guid="g-x"),
        proc("y", pid=101, ts=1000.001, guid="g-y"),
    ])
    assert store.edges() == []
    result = store.trace("guid:g-x")
    assert list(result.events) == [store.get_event("guid:g-x").event_id]


def test_reimport_is_idempotent_and_does_not_duplicate_evidence():
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("p1", pid=1234, ts=1.0, guid="parent"),
        proc("c1", pid=4444, parent_guid="guid:parent", ts=2.0, guid="child"),
    ])
    edge, = store.edges()
    assert len(edge.claims) == 1
    assert len(store.events) == 2

    store.import_source("edr-a", [
        proc("p1", pid=1234, ts=1.0, guid="parent"),
        proc("c1", pid=4444, parent_guid="guid:parent", ts=2.0, guid="child"),
    ])
    edge, = store.edges()
    assert len(edge.claims) == 1
    assert len(store.events) == 2
    assert len(store.get_event("guid:parent").claims) == 1


def test_revoke_source_removes_edges_and_events_alone_asserted():
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("p1", pid=1234, ts=1.0, guid="parent"),
        proc("c1", pid=4444, parent_guid="guid:parent", ts=2.0, guid="child"),
    ])
    assert len(store.edges()) == 1

    assert store.revoke_source("edr-a") is True
    assert store.events == {}
    assert store.edges() == []
    assert store.pending_refs() == []
    assert store.get_event("guid:child") is None


def test_revoke_keeps_links_still_asserted_by_other_sources():
    parent = proc("p1", pid=1234, ts=1.0, guid="parent")
    child_a = proc("c1", pid=4444, parent_guid="guid:parent", ts=2.0, guid="child")
    child_b = dict(child_a, record_id="c1-copy")
    store = InvestigationStore()
    store.import_source("edr-a", [parent, child_a])
    store.import_source("edr-b", [child_b])
    edge, = store.edges()
    assert len(edge.claims) == 2

    store.revoke_source("edr-a")
    assert store.get_event("guid:parent") is None
    assert store.edges() == []
    pending, = store.pending_refs()
    assert pending.target == "guid:parent"
    assert pending.claim.source_id == "edr-b"

    store.import_source("edr-c", [parent])
    edge, = store.edges()
    assert {(c.source_id, c.record_id) for c in edge.claims} == {
        ("edr-b", "c1-copy")
    }


def test_shared_alias_merges_identity_across_sources():
    store = InvestigationStore()
    record = {
        "record_id": "r1", "kind": "process", "ts": 5.0, "pid": 7,
        "aliases": ["guid:SAME"], "refs": []
    }
    store.import_source("edr-a", [dict(record)])
    store.import_source("edr-b", [dict(record, record_id="r2")])
    event, = store.events.values()
    assert {"edr-a", "edr-b"} <= {c.source_id for c in event.claims}


def test_file_and_network_chain_with_evidence_per_edge(tmp_path):
    store = InvestigationStore()
    parent = proc("p", pid=1234, ts=0.0, guid="parent")
    child = proc("c", pid=1235, parent_guid="guid:parent", ts=1.0, guid="child")
    write = {"record_id": "w", "kind": "file", "ts": 2.0,
             "path": "/tmp/payload", "aliases": ["file:/tmp/payload"],
             "refs": [{"relation": "wrote", "target": "guid:child",
                       "direction": "incoming"}]}
    conn = {"record_id": "n", "kind": "network", "ts": 3.0,
            "dst": "203.0.113.9:443",
            "refs": [{"relation": "opened", "target": "guid:child",
                      "direction": "incoming"}]}
    store.import_source("host1", [parent, child, write, conn])

    result = store.trace("guid:parent")
    relations = {hop.relation for hop in result.downstream}
    assert relations == {"parent", "wrote", "opened"}
    for hop in result.downstream:
        assert hop.claims, "every link must cite its source record"
        for claim in hop.claims:
            assert claim.source_id == "host1"

    path = save_snapshot(store, tmp_path / "case.json")
    reloaded = load_snapshot(path)
    assert len(reloaded.edges()) == 3
    assert reloaded.trace("guid:parent").downstream[0].claims
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["version"] == 2


def test_unknown_trace_seed_raises():
    store = InvestigationStore()
    with pytest.raises(KeyError):
        store.trace("guid:missing")
