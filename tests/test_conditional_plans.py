"""Third-round scenarios: conditional verification plans under budget."""

from __future__ import annotations

import pytest

from investigation import InvestigationStore
from investigation.snapshot import save_snapshot, load_snapshot


def make_store():
    store = InvestigationStore()
    store.import_source("edr", [{
        "record_id": "c", "kind": "process", "ts": 1.0,
        "aliases": ["guid:child"],
        "refs": [{"relation": "parent", "target": "guid:a",
                  "direction": "incoming"}],
    }, {"record_id": "pa", "kind": "process", "ts": 0.9,
        "aliases": ["guid:a"]}])
    store.import_source("host2", [{
        "record_id": "c2", "kind": "process", "ts": 1.0,
        "aliases": ["guid:child"],
        "refs": [{"relation": "parent", "target": "guid:b",
                  "direction": "incoming"}],
    }, {"record_id": "pb", "kind": "process", "ts": 0.8,
        "aliases": ["guid:b"]}])
    store.import_source("forensics", [
        {"record_id": "f1", "kind": "file", "ts": 0.5},
    ])
    return store


def outcome_records(target):
    return [{
        "record_id": "result", "kind": "process", "ts": 1.0,
        "aliases": ["guid:child"],
        "refs": [{"relation": "parent", "target": target,
                  "direction": "incoming"}],
    }]


def make_plan(store, plan_id="round-a", budget=10.0):
    return store.create_verification_plan(plan_id, [
        {"check_id": "check-1", "label": "内存核查父进程",
         "source_id": "mem", "relation": "parent", "cost": 4.0,
         "outcomes": [
             {"outcome_id": "is-a", "records": outcome_records("guid:a"),
              "next_checks": ["check-2"]},
             {"outcome_id": "is-b", "records": outcome_records("guid:b"),
              "next_checks": ["check-3"]},
         ]},
        {"check_id": "check-2", "label": "磁盘侧核查",
         "source_id": "disk", "relation": "wrote", "cost": 3.0,
         "requires": ["forensics"],
         "available_start": 10.0, "available_end": 20.0,
         "outcomes": [
             {"outcome_id": "wrote", "records": []},
             {"outcome_id": "clean", "records": []},
         ]},
        {"check_id": "check-3", "label": "网络侧核查",
         "source_id": "net", "relation": "opened", "cost": 5.0,
         "outcomes": [
             {"outcome_id": "connected", "records": []},
             {"outcome_id": "quiet", "records": []},
         ]},
    ], seeds=["guid:child"], budget=budget)


def test_preview_charges_shared_prefix_once_and_splits_branches():
    store = make_store()
    make_plan(store)
    preview = store.preview_plan("round-a")
    assert preview.prospective
    costs = sorted(path.cost for path in preview.paths)
    assert costs == [7.0, 7.0, 9.0, 9.0]  # check-1 charged once per path
    for path in preview.paths:
        check_ids = [check_id for check_id, _ in path.steps]
        assert check_ids[0] == "check-1"
        assert len(set(check_ids)) == len(check_ids)
    assert preview.max_path_cost == 9.0


def test_preview_never_treats_outcomes_as_fact():
    store = make_store()
    make_plan(store)
    before = {h.hypothesis_id: h.active_claims
              for h in store.hypotheses()}
    preview = store.preview_plan("round-a")
    after = {h.hypothesis_id: h.active_claims
             for h in store.hypotheses()}
    assert before == after
    assert "mem" not in {source.source_id for source in store.sources()}
    assert preview.paths  # trial computation happened off to the side


def test_shared_source_across_branches_is_not_independent_evidence():
    store = make_store()
    store.create_verification_plan("shared", [
        {"check_id": "root", "source_id": "mem", "relation": "parent",
         "cost": 1.0,
         "outcomes": [
             {"outcome_id": "a", "records": [], "next_checks": ["x"]},
             {"outcome_id": "b", "records": [], "next_checks": ["y"]},
         ]},
        {"check_id": "x", "source_id": "mem", "relation": "wrote",
         "outcomes": [{"outcome_id": "o1", "records": []}]},
        {"check_id": "y", "source_id": "mem", "relation": "opened",
         "outcomes": [{"outcome_id": "o2", "records": []}]},
    ])
    preview = store.preview_plan("shared")
    assert preview.shared_sources == ("mem",)


def test_status_separates_startable_and_waiting():
    store = make_store()
    make_plan(store)
    status = store.plan_status("round-a")
    assert status.startable == ("check-1",)
    assert status.waiting == ("check-2", "check-3")
    assert status.spent == 0.0
    store.record_check_result("round-a", "check-1", "is-a")
    status = store.plan_status("round-a")
    assert status.startable == ("check-2",)
    assert status.waiting == ("check-3",)
    assert status.spent == 4.0
    assert status.remaining_budget == 6.0


def test_unexpected_result_keeps_spend_and_stops_dependents():
    store = make_store()
    make_plan(store)
    result = store.record_check_result(
        "round-a", "check-1", "something-unlisted")
    assert not result.expected
    status = store.plan_status("round-a")
    assert status.spent == 4.0  # spend stays on the books
    assert status.unexpected == ("check-1",)
    # dependents are stopped, not rerouted to the nearest preset branch
    assert "check-2" in status.invalidated
    assert "check-3" in status.invalidated
    assert status.startable == ()
    with pytest.raises(Exception):
        store.record_check_result("round-a", "check-2", "wrote")


def test_withdrawn_prerequisite_invalidates_but_keeps_history():
    store = make_store()
    make_plan(store)
    store.record_check_result("round-a", "check-1", "is-a")
    store.revoke_source("forensics")
    status = store.plan_status("round-a")
    assert "check-2" in status.invalidated
    assert status.spent == 4.0
    assert [r.check_id for r in status.results] == ["check-1"]


def test_withdrawn_outcome_basis_stops_dependents():
    store = make_store()
    make_plan(store)
    batch_id = store.receive_evidence(
        "mem", outcome_records("guid:a"),
        plan_id="round-a", check_id="check-1", outcome_id="is-a")
    store.accept_evidence(batch_id)
    store.record_check_result(
        "round-a", "check-1", "is-a", batch_id=batch_id)
    assert store.plan_status("round-a").startable == ("check-2",)
    store.withdraw_evidence(batch_id, reason="来源撤回")
    status = store.plan_status("round-a")
    assert "check-2" in status.invalidated
    assert status.spent == 4.0
    actions = [d.action for d in store.evidence_decisions()]
    assert actions == ["accepted", "withdrawn"]


def test_confirm_revise_and_terminate():
    store = make_store()
    make_plan(store)
    store.record_check_result("round-a", "check-1", "is-a")
    status = store.confirm_plan("round-a")
    assert status.confirmed
    # revising cannot drop the executed check
    with pytest.raises(Exception):
        store.revise_plan("round-a", [
            {"check_id": "check-9", "source_id": "x", "relation": "r",
             "outcomes": [{"outcome_id": "o", "records": []}]},
        ])
    plan = store.verification_plan("round-a")
    revised = store.revise_plan("round-a", [
        check.as_dict() for check in plan.checks
        if check.check_id != "check-3"
    ] + [{"check_id": "check-4", "source_id": "disk", "relation": "r",
          "cost": 1.0,
          "outcomes": [{"outcome_id": "o", "records": []}]}])
    assert "check-4" in {c.check_id for c in revised.checks}
    assert "check-3" not in {c.check_id for c in revised.checks}
    status = store.terminate_plan("round-a", ["check-4"])
    assert "check-4" in status.terminated
    status = store.terminate_plan("round-a")
    assert status.state == "terminated"
    with pytest.raises(Exception):
        store.record_check_result("round-a", "check-2", "wrote")


def test_compare_plans_reports_costs_and_worst_case_without_verdict():
    store = make_store()
    make_plan(store, plan_id="round-a", budget=10.0)
    store.create_verification_plan("round-b", [
        {"check_id": "only", "source_id": "mem", "relation": "parent",
         "cost": 2.0,
         "outcomes": [
             {"outcome_id": "a", "records": outcome_records("guid:a")},
             {"outcome_id": "b", "records": outcome_records("guid:b")},
         ]},
    ], seeds=["guid:child"], budget=6.0)
    store.record_check_result("round-a", "check-1", "is-a")
    comparison = store.compare_plans("round-a", "round-b")
    entries = {entry.plan_id: entry for entry in comparison.entries}
    assert entries["round-a"].committed_cost == 4.0
    assert entries["round-a"].uncommitted_cost == 5.0  # 9.0 worst path - 4.0
    assert entries["round-b"].committed_cost == 0.0
    assert entries["round-b"].uncommitted_cost == 2.0
    assert isinstance(entries["round-a"].worst_case_groups, tuple)
    assert "worst-case" in comparison.note


def test_over_budget_paths_are_flagged():
    store = make_store()
    make_plan(store, budget=8.0)
    preview = store.preview_plan("round-a")
    assert ("check-1", "is-b") in preview.over_budget_paths
    assert ("check-1", "is-a") not in preview.over_budget_paths


def test_snapshot_roundtrip_preserves_mid_plan_state(tmp_path):
    store = make_store()
    make_plan(store)
    batch_id = store.receive_evidence(
        "mem", outcome_records("guid:a"),
        plan_id="round-a", check_id="check-1", outcome_id="is-a")
    store.accept_evidence(batch_id)
    store.record_check_result(
        "round-a", "check-1", "is-a", batch_id=batch_id)
    store.terminate_plan("round-a", ["check-3"])
    path = save_snapshot(store, tmp_path / "case.json")
    reloaded = load_snapshot(path)
    status = reloaded.plan_status("round-a")
    assert status.spent == 4.0
    assert status.startable == ("check-2",)
    assert "check-3" in status.terminated
    actions = [d.action for d in reloaded.evidence_decisions()]
    assert actions == ["accepted"]
    reloaded.withdraw_evidence(batch_id, reason="撤回")
    assert "check-2" in reloaded.plan_status("round-a").invalidated


def test_outcome_branch_research_does_not_touch_real_investigation():
    store = make_store()
    make_plan(store)
    store.record_check_result("round-a", "check-1", "is-a")
    branch = store.open_plan_outcome("round-a", "check-1", "is-b")
    assert branch is not store
    # the alternative-outcome branch is a separate what-if study
    assert any(claim.source_id == "mem"
               for h in branch.hypotheses() for claim in h.claims)
    assert not any(claim.source_id == "mem"
                   for h in store.hypotheses() for claim in h.claims)
    assert store.plan_status("round-a").startable == ("check-2",)
