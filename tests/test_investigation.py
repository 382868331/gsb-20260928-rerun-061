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


def test_recycled_pid_and_close_timestamps_do_not_merge_or_infer():
    store = InvestigationStore()
    store.import_source("edr", [
        proc("old", pid=4444, ts=10.0, guid="old-process"),
        proc("new", pid=4444, ts=1000.0, guid="new-process"),
        proc("nearby", pid=5555, ts=1000.001, guid="nearby"),
    ])
    assert len(store.events) == 3
    assert store.edges() == []
    assert store.trace("guid:new-process").events.keys() == {"edr:new"}


def test_conflicting_parents_keep_evidence_ranges_and_allow_selection():
    store = InvestigationStore()
    child = proc("child", pid=4444, ts=100.0, guid="child",
                 parent_guid="guid:parent-a")
    child["refs"][0].update({
        "confidence_low": 0.75,
        "confidence_high": 0.9,
        "note": "EDR parent PID lookup",
    })
    corrected_child = {
        "record_id": "child-correction",
        "kind": "process",
        "ts": 100.0,
        "aliases": ["guid:child"],
        "refs": [{
            "relation": "parent",
            "target": "guid:parent-b",
            "confidence_low": 0.2,
            "confidence_high": 0.45,
            "note": "later audit correction",
        }],
    }
    store.import_source("edr", [child])
    store.import_source("audit", [
        proc("a", pid=100, ts=90.0, guid="parent-a"),
        proc("b", pid=200, ts=90.0, guid="parent-b"),
        corrected_child,
    ])

    candidates = store.conflicting_hypotheses("guid:child", "parent")
    assert {item.cause_id for item in candidates} == {"audit:a", "audit:b"}
    by_cause = {item.cause_id: item for item in candidates}
    assert by_cause["audit:a"].confidence_range() == (0.75, 0.9)
    assert by_cause["audit:b"].confidence_range() == (0.2, 0.45)
    assert {(item.claim.source_id, item.claim.record_id)
            for item in by_cause["audit:a"].evidence} == {("edr", "child")}

    chosen = by_cause["audit:a"].hypothesis_id
    trace = store.trace("guid:child", hypothesis_ids=[chosen])
    assert [hop.cause_id for hop in trace.upstream] == ["audit:a"]
    assert trace.hypothesis_ids == (chosen,)


def test_revoking_manual_or_source_refreshes_only_affected_saved_paths(tmp_path):
    store = InvestigationStore()
    store.import_source("edr", [
        proc("p", pid=100, ts=1.0, guid="parent"),
        proc("c", pid=200, parent_guid="guid:parent", ts=2.0, guid="child"),
        proc("other", pid=300, ts=3.0, guid="other"),
    ])
    store.import_source("filefeed", [
        {"record_id": "f", "kind": "file", "ts": 4.0,
         "aliases": ["file:x"],
         "refs": [{"relation": "wrote", "target": "guid:other",
                   "direction": "incoming"}]}
    ])
    store.import_source("netfeed", [
        proc("independent", pid=900, ts=5.0, guid="independent"),
        {"record_id": "conn", "kind": "network", "ts": 6.0,
         "aliases": ["net:independent"],
         "refs": [{"relation": "opened", "target": "guid:independent",
                   "direction": "incoming"}]},
    ])
    manual_record = store.add_manual_link(
        "guid:child", "file:x", "wrote",
        confidence_low=0.6, confidence_high=0.8,
    )
    selected = [
        h.hypothesis_id for h in store.causal_hypotheses()
        if h.effect_id in {"edr:c", "filefeed:f"}
        and (
            h.relation == "parent"
            or (h.relation == "wrote" and h.cause_id == "edr:c")
        )
    ]
    affected = store.close_investigation(
        "case-child", "guid:child", "follow EDR parent",
        hypothesis_ids=selected,
    )
    other_selected = [
        h.hypothesis_id for h in store.causal_hypotheses()
        if h.effect_id == "netfeed:conn" and h.relation == "opened"
    ]
    unaffected = store.close_investigation(
        "case-other", "guid:independent", "independent network path",
        hypothesis_ids=other_selected,
    )

    snapshot_path = save_snapshot(store, tmp_path / "before.json")
    reopened = load_snapshot(snapshot_path)
    reopened_trace = reopened.reopen_investigation("case-child")
    assert [hop.cause_id for hop in reopened_trace.upstream] == ["edr:p"]
    assert reopened.get_investigation("case-child").judgment == "follow EDR parent"

    assert store.revoke_manual_link(manual_record) is True
    assert store.get_investigation("case-child").status == "path_changed"
    assert store.get_investigation("case-child").trace_keys == affected.trace_keys
    assert store.get_investigation("case-other").status == "current"
    assert store.get_investigation("case-other").trace_keys == unaffected.trace_keys

    store.revoke_source("edr")
    assert store.get_investigation("case-child").status == "missing"
    assert store.get_investigation("case-other").status == "current"
    assert store.get_investigation("case-child").hypotheses[0].evidence


def test_saved_judgment_can_be_compared_with_latest_evidence(tmp_path):
    store = InvestigationStore()
    store.import_source("edr", [
        proc("a", pid=100, ts=1.0, guid="parent-a"),
        proc("c", pid=200, ts=2.0, guid="child",
             parent_guid="guid:parent-a"),
    ])
    original_id = [
        h.hypothesis_id for h in store.conflicting_hypotheses(
            "guid:child", "parent"
        )
    ]
    assert original_id == []
    original_id = [
        h.hypothesis_id for h in store.hypotheses_for_effect("guid:child", "parent")
    ]
    saved = store.close_investigation(
        "case-1", "guid:child", "parent A caused child",
        hypothesis_ids=original_id,
    )
    path = save_snapshot(store, tmp_path / "closed.json")

    store.import_source("audit", [
        proc("b", pid=101, ts=0.9, guid="parent-b"),
        {"record_id": "correction", "kind": "process", "ts": 2.0,
         "aliases": ["guid:child"],
         "refs": [{"relation": "parent", "target": "guid:parent-b"}]},
    ])
    comparison = store.compare_investigation("case-1")
    assert comparison.still_current == tuple(saved.selected_hypothesis_ids)
    assert comparison.new_alternatives

    corrected_child = proc("c", pid=200, ts=2.0, guid="child",
                           parent_guid="guid:parent-b")
    store.import_source("edr", [
        proc("a", pid=100, ts=1.0, guid="parent-a"),
        corrected_child,
    ])
    comparison = store.compare_investigation("case-1")
    assert comparison.missing == tuple(saved.selected_hypothesis_ids)
    assert comparison.new_alternatives
    assert store.get_investigation("case-1").judgment == "parent A caused child"
    assert store.get_investigation("case-1").hypotheses[0].cause_id == "edr:a"

    reloaded = load_snapshot(path)
    assert reloaded.get_investigation("case-1").judgment == "parent A caused child"
    assert reloaded.reopen_investigation("case-1") is not None
