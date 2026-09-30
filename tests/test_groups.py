"""Third-turn scenarios: group path comparison, time-ranged judgments,
independent reopening of saved hypothesis groups."""
import pytest

from investigation import Hypothesis, InvestigationStore, RecordRef
from investigation.snapshot import load_snapshot, save_snapshot


def proc(record_id, pid, *, guid=None, parent=None, ts=0.0, **extra):
    record = {"record_id": record_id, "kind": "process", "ts": ts,
              "pid": pid, "aliases": ([f"guid:{guid}"] if guid else []),
              "refs": ([{"relation": "parent", "target": f"guid:{parent}"}]
                       if parent else [])}
    record.update(extra)
    return record


def disputed_store():
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("c", pid=1, guid="child", parent="p-a", ts=100.0),
        proc("pa", pid=2, guid="p-a", ts=90.0),
        proc("ga", pid=3, guid="g-a", ts=80.0,
             refs=[{"relation": "parent", "target": "guid:p-a",
                    "direction": "outgoing"}]),
    ], trust=0.9, scopes=["host-a"])
    store.import_source("edr-b", [
        proc("c2", pid=1, guid="child", parent="p-b", ts=100.0),
        proc("pb", pid=2, guid="p-b", ts=95.0),
    ], trust=0.6, scopes=["host-b"])
    return store


def pick(store, cause_guid):
    return Hypothesis.make_id(store.get_event("guid:child").event_id,
                              "parent",
                              store.get_event(cause_guid).event_id)


def test_explain_set_reports_explained_conflicts_and_unexplained():
    store = disputed_store()
    store.create_hypothesis_set("work-a", [pick(store, "guid:p-a")])
    store.trace("guid:child", set_id="work-a", save=True)

    report = store.explain_set("work-a")
    child = store.get_event("guid:child").event_id
    assert child in report.explained_events
    assert store.get_event("guid:p-a").event_id in report.explained_events
    # The whole path is explained, not just the disputed slot.
    assert store.get_event("guid:g-a").event_id in report.explained_events
    # The rejected branch and its backing source are visible.
    assert report.rejected_hypotheses == (pick(store, "guid:p-b"),)
    assert report.conflicting_sources == ("edr-b",)
    assert report.unexplained_slots == ()

    # A pending reference on a reached event shows up as unexplained.
    store.import_source("edr-c", [
        {"record_id": "x", "kind": "process", "ts": 110.0,
         "aliases": ["guid:child"],
         "refs": [{"relation": "injected", "target": "guid:ghost"}]},
    ])
    report = store.explain_set("work-a")
    assert [(p.relation, p.target) for p in report.unresolved_refs] == [
        ("injected", "guid:ghost")]


def test_explain_set_flags_disputed_slot_without_selection():
    store = disputed_store()
    store.create_hypothesis_set("empty", [])
    store.trace("guid:child", set_id="empty", save=True)
    report = store.explain_set("empty")
    child = store.get_event("guid:child").event_id
    assert (child, "parent") in report.unexplained_slots


def test_compare_set_paths_shows_shared_and_unique_hops():
    store = disputed_store()
    store.create_hypothesis_set("work-a", [pick(store, "guid:p-a")])
    store.create_hypothesis_set("work-b", [pick(store, "guid:p-b")])

    comparison = store.compare_set_paths("guid:child",
                                         ["work-a", "work-b"])
    pa = store.get_event("guid:p-a").event_id
    pb = store.get_event("guid:p-b").event_id
    ga = store.get_event("guid:g-a").event_id
    child = store.get_event("guid:child").event_id
    # Each group walks its own full propagation path.
    assert {(h.cause_id, h.effect_id) for h in comparison.unique_hops["work-a"]} == {
        (pa, child), (ga, pa)}
    assert {(h.cause_id, h.effect_id) for h in comparison.unique_hops["work-b"]} == {
        (pb, child)}
    assert comparison.shared_hops == ()


def test_time_bounded_manual_link_is_not_generalized():
    store = InvestigationStore()
    store.import_source("edr", [
        proc("a", pid=1, guid="a", ts=10.0),
        proc("b", pid=2, guid="b", ts=500.0),
    ])
    link_id = store.add_manual_link(
        "guid:a", "guid:b", "controls", note="phase-1 only",
        valid_from=0.0, valid_to=100.0)
    # The effect event sits outside the window: no edge is created, but
    # the judgment itself is kept as evidence.
    assert store.edges() == []
    status, = store.manual_link_status()
    assert status.active is False and "window" in status.reason
    assert store.manual_links()[0].link_id == link_id

    # Widening the window activates the judgment for that phase only.
    assert store.adjust_manual_link_window(link_id, 0.0, 1000.0) is True
    status, = store.manual_link_status()
    assert status.active is True
    assert [e.relation for e in store.edges()] == ["controls"]


def test_same_object_has_different_relations_in_different_phases():
    store = InvestigationStore()
    store.import_source("edr", [
        {"record_id": "a", "kind": "process", "aliases": ["guid:a"]},
        {"record_id": "b", "kind": "process", "aliases": ["guid:b"]},
    ])
    store.add_manual_link("guid:a", "guid:b", "controls",
                          valid_from=0.0, valid_to=100.0)
    store.add_manual_link("guid:a", "guid:b", "exfiltrates",
                          valid_from=200.0, valid_to=300.0)
    early = store.trace("guid:b", at=50.0)
    late = store.trace("guid:b", at=250.0)
    assert [h.relation for h in early.upstream] == ["controls"]
    assert [h.relation for h in late.upstream] == ["exfiltrates"]
    # Without a moment, both bounded judgments remain visible as evidence.
    assert {h.relation for h in store.trace("guid:b").upstream} == {
        "controls", "exfiltrates"}


def test_window_adjustment_only_invalidates_affected_paths():
    store = InvestigationStore()
    store.import_source("edr", [
        proc("a", pid=1, guid="a", ts=10.0),
        proc("b", pid=2, guid="b", ts=500.0),
        proc("u", pid=3, guid="u", ts=1.0),
    ])
    link_id = store.add_manual_link("guid:a", "guid:b", "controls",
                                    valid_from=0.0, valid_to=1000.0)
    store.trace("guid:b", save=True)
    store.trace("guid:u", save=True)
    assert store.stale_paths() == []

    store.adjust_manual_link_window(link_id, 0.0, 100.0)
    stale = {p.seed for p in store.stale_paths()}
    assert store.get_event("guid:b").event_id in stale
    assert store.get_event("guid:u").event_id not in stale
    # The unrelated path keeps its original conclusion.
    untouched = next(p for p in store.saved_paths()
                     if p.seed == store.get_event("guid:u").event_id)
    assert untouched.valid and untouched.result.upstream == []


def test_saved_group_reopens_independently_and_keeps_exclusion_rationale():
    store = disputed_store()
    store.create_hypothesis_set("work-a", [pick(store, "guid:p-a")])
    rejected_id = pick(store, "guid:p-b")
    group_id = store.save_group(
        "work-a", note="phase-1 judgment",
        reasons={rejected_id: "edr-b trust too low"})

    # Evidence later disappears; the archive must not lose anything.
    store.revoke_source("edr-b")
    group = store.reopen_group(group_id)
    assert group.note == "phase-1 judgment"
    assert [h["hypothesis_id"] for h in group.selected] == [
        pick(store, "guid:p-a")]
    excluded, = group.excluded
    assert excluded["hypothesis_id"] == rejected_id
    assert excluded["exclusion_reason"] == "edr-b trust too low"
    assert excluded["claims"]  # original candidate evidence preserved

    # Reopening creates an independent working set from the archive.
    reopened = store.activate_saved_group(group_id, activate=True)
    assert reopened.set_id != "work-a"
    result = store.trace("guid:child")
    assert [h.cause_id for h in result.upstream] == [
        store.get_event("guid:p-a").event_id,
        store.get_event("guid:g-a").event_id]
    # The original live set is untouched by the reopen.
    assert {s.set_id for s in store.hypothesis_sets()} >= {
        "work-a", reopened.set_id}


def test_saved_groups_are_append_only_and_survive_snapshot(tmp_path):
    store = disputed_store()
    store.create_hypothesis_set("work-a", [pick(store, "guid:p-a")])
    gid = store.save_group("work-a")
    with pytest.raises(Exception):
        store.save_group("work-a", group_id=gid)

    path = save_snapshot(store, tmp_path / "case.json")
    reloaded = load_snapshot(path)
    group = reloaded.reopen_group(gid)
    assert [h["hypothesis_id"] for h in group.selected] == [
        pick(store, "guid:p-a")]
    assert [h["hypothesis_id"] for h in group.excluded] == [
        pick(store, "guid:p-b")]
    # Time-bounded manual judgments also survive the round trip.
    reloaded.add_manual_link("guid:p-a", "guid:child", "controls",
                             valid_from=0.0, valid_to=1000.0)
    again = load_snapshot(save_snapshot(reloaded, tmp_path / "case2.json"))
    link = again.manual_links()[0]
    assert (link.valid_from, link.valid_to) == (0.0, 1000.0)


def test_trace_at_moment_is_cached_and_invalidated_per_path():
    store = InvestigationStore()
    store.import_source("edr", [
        proc("a", pid=1, guid="a"),
        proc("b", pid=2, guid="b"),
    ])
    link_id = store.add_manual_link("guid:a", "guid:b", "controls",
                                    valid_from=0.0, valid_to=100.0)
    early = store.trace("guid:b", at=50.0, save=True)
    late = store.trace("guid:b", at=500.0, save=True)
    assert [h.relation for h in early.upstream] == ["controls"]
    assert late.upstream == []
    store.adjust_manual_link_window(link_id, 0.0, 1000.0)
    # Both saved moments observed this link, so both are stale.
    assert len(store.stale_paths()) == 2
    assert [h.relation for h in store.trace(
        "guid:b", at=500.0, save=True).upstream] == ["controls"]
