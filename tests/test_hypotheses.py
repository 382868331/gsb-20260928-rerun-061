"""Second-turn scenarios: disputed causality, corrections, frozen findings."""
import pytest

from investigation import Casebook, Hypothesis, InvestigationStore, RecordRef


def proc(record_id, pid, *, guid=None, parent=None, ts=0.0, **extra):
    parent_ref = (parent if isinstance(parent, dict) else
                  {"relation": "parent", "target": f"guid:{parent}"} if parent else None)
    record = {"record_id": record_id, "kind": "process", "ts": ts,
              "pid": pid, "aliases": ([f"guid:{guid}"] if guid else []),
              "refs": ([parent_ref] if parent_ref else [])}
    record.update(extra)
    return record


def test_conflicting_parentage_keeps_both_claims_with_trust_and_scope():
    store = InvestigationStore()
    # Child arrives first; both feeds later disagree about its parent.
    store.import_source("edr-a", [
        proc("c", pid=4444, guid="child", parent="p-a", ts=100.0),
    ], trust=0.9, scopes=["host-a"])
    assert len(store.pending_refs()) == 1

    # Late parent events: same recycled PID 1234, different GUIDs.  Equal
    # timestamps/PIDs must not merge or infer identity.
    store.import_source("edr-a", [
        proc("c", pid=4444, guid="child", parent="p-a", ts=100.0),
        proc("pa", pid=1234, guid="p-a", ts=90.0),
    ], trust=0.9, scopes=["host-a"])
    store.import_source("edr-b", [
        proc("c2", pid=4444, guid="child", parent="p-b", ts=100.0),
        proc("pb", pid=1234, guid="p-b", ts=99.9999),
    ], trust=0.6, scopes=["host-b"])

    groups = store.conflict_groups()
    assert len(groups) == 1
    group = groups[0]
    assert group.relation == "parent"
    assert {h.cause_id for h in group.hypotheses} == {
        store.get_event("guid:p-a").event_id,
        store.get_event("guid:p-b").event_id,
    }
    by_cause = {h.cause_id: h for h in group.hypotheses}
    ha = by_cause[store.get_event("guid:p-a").event_id]
    hb = by_cause[store.get_event("guid:p-b").event_id]
    assert ha.confidence == 0.9 and "host-a" in ha.scopes
    assert hb.confidence == 0.6 and "host-b" in hb.scopes
    assert {(c.source_id, c.record_id) for c in ha.claims} == {("edr-a", "c")}
    # Raw evidence graph still carries both; nothing was auto-merged.
    assert len(store.edges()) == 2


def test_hypothesis_set_pins_one_branch_for_tracking():
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("c", pid=1, guid="child", parent="p-a"),
        proc("pa", pid=2, guid="p-a"),
    ])
    store.import_source("edr-b", [
        proc("c2", pid=1, guid="child", parent="p-b"),
        proc("pb", pid=2, guid="p-b"),
    ])
    group = store.conflict_groups()[0]
    pick_a = next(h.hypothesis_id for h in group.hypotheses
                  if h.cause_id == store.get_event("guid:p-a").event_id)
    store.create_hypothesis_set("work", [pick_a], activate=True)

    result = store.trace("guid:child", save=True)
    assert [h.cause_id for h in result.upstream] == [
        store.get_event("guid:p-a").event_id]
    # The rejected alternative keeps its evidence for later review.
    rejected = store.hypothesis_evidence(
        Hypothesis.make_id(store.get_event("guid:child").event_id, "parent",
                           store.get_event("guid:p-b").event_id))
    assert rejected.active_claims


def test_source_correction_retracts_claim_but_keeps_history():
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("c", pid=1, guid="child", parent="p-a"),
        proc("pa", pid=2, guid="p-a"),
    ])
    store.import_source("edr-b", [
        proc("c2", pid=1, guid="child", parent="p-b"),
        proc("pb", pid=2, guid="p-b"),
    ])
    # A human-recorded correction from feed A withdraws its old claim.
    store.import_source("edr-a-correction", [{
        "record_id": "fix-1", "kind": "process", "ts": 200.0,
        "pid": 1, "aliases": ["guid:child"],
        "retracts": [{"source_id": "edr-a", "record_id": "c"}],
        "refs": [],
    }], trust=1.0, scopes=["correction"])

    groups = store.conflict_groups(include_retracted=True)
    a_hyp = next(h for g in groups for h in g.hypotheses
                 if h.cause_id == store.get_event("guid:p-a").event_id)
    assert a_hyp.is_retracted
    assert RecordRef("edr-a", "c") in a_hyp.retracted_claims
    # Retraction metadata still cites who withdrew what.
    assert store.retractions()[RecordRef("edr-a-correction", "fix-1")] == (
        RecordRef("edr-a", "c"),)
    # The live conflict now has one live explanation; the old one remains.
    live = store.conflict_groups()
    assert live == []
    all_hyps = store.hypotheses(include_retracted=True)
    assert len(all_hyps) == 2


def test_only_affected_saved_paths_are_recomputed_on_revoke():
    store = InvestigationStore()
    store.import_source("feed", [
        proc("root", pid=10, guid="root"),
        proc("kid", pid=11, guid="kid", parent="root"),
        proc("other", pid=12, guid="other"),
    ])
    touched = store.trace("guid:kid", save=True)
    untouched = store.trace("guid:other", save=True)
    assert all(p.valid for p in store.saved_paths())

    # Analyst links an unrelated event into the chain, then revokes it.
    link_id = store.add_manual_link("guid:other", "guid:kid", "injected",
                                   note="suspected loader")
    assert len(store.stale_paths()) == 2
    refreshed = store.trace("guid:kid", save=True)
    assert any(h.relation == "injected" for h in refreshed.upstream)

    # Recomputing the untouched path marks it valid again.
    store.trace("guid:other", save=True)
    assert store.stale_paths() == []

    assert store.retract_manual_link(link_id) is True
    states = {(p.seed, p.valid) for p in store.saved_paths()}
    # The other<->kid edge touched the 'kid' path (and 'other' as endpoint).
    assert (touched.origin_id, False) in states


def test_revoke_unrelated_source_keeps_path_valid():
    store = InvestigationStore()
    store.import_source("chain", [
        proc("p", pid=1, guid="p"),
        proc("c", pid=2, guid="c", parent="p"),
    ])
    store.import_source("side", [proc("s", pid=3, guid="s")])
    store.trace("guid:c", save=True)
    store.trace("guid:s", save=True)
    store.revoke_source("side")
    by_seed = {p.seed: p for p in store.saved_paths()}
    assert by_seed[store.get_event("guid:c").event_id].valid is True
    assert by_seed["side:s"].valid is False


def test_manual_link_is_independent_evidence_and_reopens(tmp_path):
    store = InvestigationStore()
    store.import_source("edr", [
        proc("a", pid=1, guid="a"), proc("b", pid=2, guid="b")])
    link_id = store.add_manual_link("guid:a", "guid:b", "parent",
                                   note="analyst correlation",
                                   confidence=0.75, scopes=["ir-team"])
    result = store.trace("guid:b")
    hop, = result.upstream
    assert hop.claims == (RecordRef("manual", link_id),)
    # Snapshot round trip keeps the manual association.
    from investigation.snapshot import save_snapshot, load_snapshot
    reloaded = load_snapshot(save_snapshot(store, tmp_path / "c.json"))
    assert reloaded.manual_links()[0].note == "analyst correlation"
    assert reloaded.trace("guid:b").upstream[0].claims[0].source_id == "manual"


def test_manual_link_visible_under_active_hypothesis_set():
    store = InvestigationStore()
    store.import_source("a", [
        proc("c", pid=1, guid="child", parent="p-a"),
        proc("pa", pid=2, guid="p-a"),
    ])
    store.import_source("b", [
        proc("c2", pid=1, guid="child", parent="p-b"),
        proc("pb", pid=2, guid="p-b"),
    ])
    store.import_source("x", [proc("x", pid=3, guid="x")])
    pick = Hypothesis.make_id(store.get_event("guid:child").event_id, "parent",
                              store.get_event("guid:p-a").event_id)
    store.create_hypothesis_set("work", [pick], activate=True)
    store.trace("guid:child", save=True)
    store.add_manual_link("guid:x", "guid:child", "injected",
                          note="analyst link")
    assert len(store.stale_paths()) == 1
    refreshed = store.trace("guid:child", save=True)
    relations = {h.relation for h in refreshed.upstream}
    assert relations == {"parent", "injected"}


def test_saved_finding_reopens_and_compares_with_later_evidence(tmp_path):
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("c", pid=1, guid="child", parent="p-a"),
        proc("pa", pid=2, guid="p-a"),
    ])
    store.import_source("edr-b", [
        proc("c2", pid=1, guid="child", parent="p-b"),
        proc("pb", pid=2, guid="p-b"),
    ])
    pick = Hypothesis.make_id(store.get_event("guid:child").event_id, "parent",
                              store.get_event("guid:p-a").event_id)
    store.create_hypothesis_set("work", [pick], activate=True)
    store.trace("guid:child", save=True)

    book = Casebook(case_id="case-1")
    finding_id = book.save_finding(store, title="initial judgment",
                                   note="A feed trusted")
    path = tmp_path / "casebook.json"
    book.save(path)

    # Later: feed A corrects itself; new evidence arrives downstream.
    store.import_source("edr-a-correction", [{
        "record_id": "fix", "kind": "process", "aliases": ["guid:child"],
        "retracts": [{"source_id": "edr-a", "record_id": "c"}],
        "refs": []}])
    store.import_source("edr-c", [{
        "record_id": "conn", "kind": "network", "ts": 300.0,
        "dst": "203.0.113.9:443",
        "refs": [{"relation": "opened", "target": "guid:child"}]}])

    book = Casebook.load(path)
    assert [f["title"] for f in book.findings] == ["initial judgment"]
    # Reopen the past exactly as decided then.
    past = book.reopen(finding_id)
    past_trace = book.frozen_trace(
        finding_id, past.get_event("guid:child").event_id)
    assert [h.cause_id for h in past_trace.upstream] == [
        past.get_event("guid:p-a").event_id]
    assert past.edges() and not past.get_event("conn:edr-c:conn")

    comparison = book.compare_with_latest(finding_id, store)
    diff, = comparison.path_diffs
    assert [h.relation for h in diff.added_downstream] == ["opened"]
    # The hypothesis originally chosen no longer has live evidence.
    assert pick in comparison.selected_hypotheses_missing

    # Saving again appends; the old judgment is never overwritten.
    book.save_finding(store, title="after correction")
    book.save(path)
    reloaded = Casebook.load(path)
    assert [f["title"] for f in reloaded.findings] == [
        "initial judgment", "after correction"]
    with pytest.raises(ValueError):
        reloaded.save_finding(store, finding_id=finding_id)


def test_time_ranged_manual_judgments_keep_phase_separate():
    store = InvestigationStore()
    store.import_source("base", [
        proc("c", 1, guid="child"),
        proc("a", 2, guid="parent-a"),
        proc("b", 3, guid="parent-b"),
    ])
    store.add_manual_link("guid:parent-a", "guid:child", "parent",
                          link_id="phase-a", valid_start=0, valid_end=10,
                          note="first stage")
    store.add_manual_link("guid:parent-b", "guid:child", "parent",
                          link_id="phase-b", valid_start=11, valid_end=20,
                          note="second stage")

    assert store.conflict_groups() == []
    assert [h.cause_id for h in store.trace("guid:child", at_time=5).upstream] == [
        store.get_event("guid:parent-a").event_id]
    assert [h.cause_id for h in store.trace("guid:child", at_time=15).upstream] == [
        store.get_event("guid:parent-b").event_id]
    assert len(store.trace("guid:child", at_time=25).upstream) == 0


def test_time_range_change_only_invalidates_overlapping_saved_path():
    store = InvestigationStore()
    store.import_source("base", [
        proc("c", 1, guid="child"), proc("a", 2, guid="parent-a")])
    store.add_manual_link("guid:parent-a", "guid:child", "parent",
                          link_id="phase", valid_start=0, valid_end=10)
    store.trace("guid:child", save=True, at_time=5)
    store.trace("guid:child", save=True, at_time=20)
    assert all(p.valid for p in store.saved_paths())

    store.add_manual_link("guid:parent-a", "guid:child", "parent",
                          link_id="phase", valid_start=0, valid_end=8)
    states = {state.at_time: state.valid for state in store.saved_paths()}
    assert states == {5.0: False, 20.0: True}


def test_revoked_source_keeps_original_candidates_and_exclusions(tmp_path):
    store = InvestigationStore()
    store.import_source("a", [
        proc("c", 1, guid="child", parent="pa"),
        proc("pa", 2, guid="pa"),
    ])
    store.import_source("b", [
        proc("c2", 1, guid="child", parent="pb"),
        proc("pb", 2, guid="pb"),
    ])
    store.import_source("b", [
        proc("c2", 1, guid="child", parent="pb"),
        proc("pb", 2, guid="pb"),
    ])
    group = store.conflict_groups()[0]
    selected, excluded = group.hypotheses
    store.create_hypothesis_set(
        "case", [selected.hypothesis_id],
        excluded_hypothesis_ids=[excluded.hypothesis_id],
        judgments={selected.hypothesis_id: "path fits memory timeline"},
        activate=True)
    store.trace("guid:child", save=True)
    store.revoke_source("a")

    historical = store.hypothesis_evidence(selected.hypothesis_id)
    assert RecordRef("a", "c") in historical.claims
    assert historical.is_retracted
    saved_set, = store.hypothesis_sets()
    assert selected.hypothesis_id in saved_set.hypothesis_ids
    assert excluded.hypothesis_id in saved_set.excluded_hypothesis_ids

    from investigation.snapshot import load_snapshot, save_snapshot
    reloaded = load_snapshot(save_snapshot(store, tmp_path / "case.json"))
    reopened_set, = reloaded.hypothesis_sets()
    assert selected.hypothesis_id in reopened_set.hypothesis_ids
    assert excluded.hypothesis_id in reopened_set.excluded_hypothesis_ids
    assert reloaded.hypothesis_evidence(selected.hypothesis_id).claims


def test_hypothesis_set_explains_path_conflicts_and_unresolved():
    store = InvestigationStore()
    store.import_source("a", [
        proc("c", 1, guid="child", parent="pa"),
        proc("pa", 2, guid="pa"),
    ])
    store.import_source("b", [
        proc("c2", 1, guid="child", parent="pb"),
        proc("pb", 2, guid="pb"),
    ])
    group = store.conflict_groups()[0]
    selected = next(h for h in group.hypotheses if h.cause_id.endswith(":pa"))
    excluded = next(h for h in group.hypotheses if h.cause_id.endswith(":pb"))
    store.create_hypothesis_set(
        "work", [selected.hypothesis_id],
        excluded_hypothesis_ids=[excluded.hypothesis_id], activate=True)

    explanation = store.explain_hypothesis_set("work")
    child_id = store.get_event("guid:child").event_id
    assert child_id in explanation.explained_events
    assert "b" in explanation.conflicting_sources
    assert excluded in explanation.excluded


def test_saved_hypothesis_sets_cannot_be_overwritten():
    store = InvestigationStore()
    store.import_source("a", [
        proc("c", 1, guid="child", parent="pa"),
        proc("pa", 2, guid="pa"),
    ])
    store.import_source("b", [
        proc("c2", 1, guid="child", parent="pb"),
        proc("pb", 2, guid="pb"),
    ])
    group = store.conflict_groups()[0]
    store.create_hypothesis_set("v1", [group.hypotheses[0].hypothesis_id])
    with pytest.raises(Exception):
        store.create_hypothesis_set("v1", [group.hypotheses[0].hypothesis_id])


def test_planned_outcomes_preview_exclusions_without_mutating_case():
    store = InvestigationStore()
    store.import_source("a", [
        proc("c", 1, guid="child", parent="pa"),
        proc("pa", 2, guid="pa"),
    ])
    store.import_source("b", [
        proc("c2", 1, guid="child", parent="pb"),
        proc("pb", 2, guid="pb"),
    ])
    group = store.conflict_groups()[0]
    a_hyp = next(h for h in group.hypotheses if h.cause_id.endswith(":pa"))
    b_hyp = next(h for h in group.hypotheses if h.cause_id.endswith(":pb"))

    def outcome(parent, retract):
        return {
            "outcome_id": f"says-{parent}",
            "label": f"parent is {parent}",
            "records": [{
                "record_id": "result",
                "kind": "process",
                "aliases": ["guid:child"],
                "retracts": [{"source_id": retract[0],
                              "record_id": retract[1]}],
                "refs": [{"relation": "parent",
                          "target": f"guid:{parent}"}],
            }],
        }

    plan = store.create_verification_plan("round-1", [{
        "check_id": "parent-check",
        "label": "verify parent",
        "source_id": "follow-up",
        "relation": "parent",
        "target": "guid:pa",
        "outcomes": [
            outcome("pa", ("b", "c2")),
            outcome("pb", ("a", "c")),
        ],
    }], seeds=["guid:child"], description="discriminating follow-up")

    says_a = store.assess_plan_outcome("round-1", "parent-check", "says-pa")
    assert says_a.retained_hypothesis_ids == (a_hyp.hypothesis_id,)
    assert says_a.excluded_hypothesis_ids == (b_hyp.hypothesis_id,)
    assert says_a.indistinguishable_groups == ()
    path, = says_a.retained_paths.values()
    assert [hop.cause_id for hop in path.upstream] == [a_hyp.cause_id]

    says_b = store.assess_plan_outcome("round-1", "parent-check", "says-pb")
    assert says_b.retained_hypothesis_ids == (b_hyp.hypothesis_id,)
    assert says_b.excluded_hypothesis_ids == (a_hyp.hypothesis_id,)

    # The live store remains a genuine conflict: plans are not evidence.
    assert len(store.conflict_groups()) == 1
    assert "follow-up" not in {source.source_id for source in store.sources()}
    independent = store.open_plan_outcome(
        "round-1", "parent-check", "says-pa")
    assert independent.get_event("guid:pb") is not None
    assert store.get_event("a:pa") is not None


def test_received_evidence_is_reviewed_then_accepted_and_withdrawn_with_audit(tmp_path):
    store = InvestigationStore()
    store.import_source("a", [
        proc("c", 1, guid="child", parent="pa"),
        proc("pa", 2, guid="pa"),
    ])
    store.import_source("b", [
        proc("c2", 1, guid="child", parent="pb"),
        proc("pb", 2, guid="pb"),
    ])
    group = store.conflict_groups()[0]
    b_hyp = next(h for h in group.hypotheses if h.cause_id.endswith(":pb"))
    plan_record = {
        "record_id": "result",
        "kind": "process",
        "aliases": ["guid:child"],
        "retracts": [{"source_id": "b", "record_id": "c2"}],
        "refs": [{"relation": "parent", "target": "guid:pa"}],
    }
    store.create_verification_plan("round-1", [{
        "check_id": "parent-check",
        "label": "verify parent",
        "source_id": "follow-up",
        "relation": "parent",
        "target": "guid:pa",
        "outcomes": [{
            "outcome_id": "says-pa",
            "label": "parent is pa",
            "records": [plan_record],
        }],
    }], seeds=["guid:child"])
    second = store.create_verification_plan("round-2", [{
        "check_id": "other-check",
        "label": "same feed",
        "source_id": "follow-up",
        "relation": "parent",
        "target": "guid:pa",
        "outcomes": [{"outcome_id": "repeat", "records": [plan_record]}],
    }])
    assert second.plan_id == "round-2"

    contradictory = dict(plan_record, record_id="actual")
    contradictory["refs"] = [{"relation": "parent", "target": "guid:pb"}]
    batch_id = store.receive_evidence(
        "follow-up", [contradictory], plan_id="round-1",
        check_id="parent-check", outcome_id="says-pa")
    review = store.review_received_evidence(batch_id)
    assert review["contradictions"]
    assert "round-2" in review["shared_planned_sources"]
    assert store.conflict_groups()

    matching = dict(plan_record, record_id="actual")
    duplicate_batch = store.receive_evidence("follow-up", [matching])
    matching_batch = store.receive_evidence("follow-up", [matching])
    store.accept_evidence(matching_batch, reason="memory correlation accepted")
    duplicate_review = store.review_received_evidence(duplicate_batch)
    assert duplicate_review["duplicate_claims"]
    assert store.hypothesis_evidence(b_hyp.hypothesis_id).is_retracted

    decision, = store.evidence_decisions()
    assert decision.excluded_hypotheses == frozenset({b_hyp.hypothesis_id})
    assert decision.reason == "memory correlation accepted"

    store.withdraw_evidence(matching_batch, reason="later found unreliable")
    assert not store.hypothesis_evidence(b_hyp.hypothesis_id).is_retracted
    actions = [(d.action, d.reason) for d in store.evidence_decisions()]
    assert actions[-1] == ("withdrawn", "later found unreliable")
    assert actions[0] == ("accepted", "memory correlation accepted")

    from investigation.snapshot import load_snapshot, save_snapshot
    reloaded = load_snapshot(save_snapshot(store, tmp_path / "case.json"))
    assert [d.action for d in reloaded.evidence_decisions()] == [
        "accepted", "withdrawn"]
    assert len(reloaded.verification_plans()) == 2


def test_conditional_plan_budget_preview_counts_shared_prefix_once():
    store = InvestigationStore()
    plan = store.create_verification_plan("conditional", [
        {
            "check_id": "prefix",
            "label": "common acquisition",
            "source_id": "same-team",
            "relation": "parent",
            "cost": 4,
            "required_materials": ["image"],
            "outcomes": [
                {"outcome_id": "need-a", "next_check_ids": ["branch-a"]},
                {"outcome_id": "need-b", "next_check_ids": ["branch-b"]},
            ],
        },
        {
            "check_id": "branch-a",
            "label": "a only",
            "source_id": "a-team",
            "relation": "parent",
            "cost": 3,
            "outcomes": [{"outcome_id": "done-a"}],
        },
        {
            "check_id": "branch-b",
            "label": "b only",
            "source_id": "same-team",
            "relation": "parent",
            "cost": 7,
            "outcomes": [{"outcome_id": "done-b"}],
        },
    ], budget=12, available_materials=["image"])

    preview = store.preview_conditional_plan("conditional")
    assert preview.available_now == ("prefix",)
    assert preview.common_check_ids == ("prefix",)
    assert preview.common_cost == 4
    assert preview.worst_case_cost == 11
    assert preview.budget_remaining_in_worst_case == 1
    assert [path["check_ids"] for path in preview.paths] == [
        ("prefix", "branch-a"), ("prefix", "branch-b")]
    assert preview.repeated_source_checks == (
        ("same-team", ("branch-b", "prefix")),)

    comparison = store.compare_verification_plans("conditional")
    assert comparison["plans"][0]["worst_case_total_cost"] == 11
    assert comparison["plans"][0]["uncommitted_cost"] == 11


def test_conditional_plan_run_waits_stops_out_of_range_and_restores(tmp_path):
    store = InvestigationStore()
    store.create_verification_plan("conditional", [
        {
            "check_id": "first",
            "label": "first",
            "source_id": "team",
            "relation": "parent",
            "cost": 2,
            "outcomes": [
                {"outcome_id": "continue", "next_check_ids": ["second"]},
                {"outcome_id": "stop", "next_check_ids": []},
            ],
        },
        {
            "check_id": "second",
            "label": "second",
            "source_id": "team",
            "relation": "parent",
            "cost": 3,
            "required_materials": ["deposition"],
            "outcomes": [{"outcome_id": "done"}],
        },
    ], budget=10)
    run = store.start_plan_run("conditional", "run-1")
    assert run.check_states["first"] == "available"
    assert run.check_states["second"] == "waiting"

    store.start_plan_check("run-1", "first")
    store.record_plan_check_result("run-1", "first", "continue",
                                   batch_id="batch-1")
    assert run.check_states["second"] == "blocked"
    assert store.preview_conditional_plan("conditional", "run-1").uncommitted_cost == 3

    store.add_plan_material("run-1", "deposition")
    assert run.check_states["second"] == "available"
    store.start_plan_check("run-1", "second")
    store.withdraw_plan_material("run-1", "deposition", note="source recalled")
    assert run.check_states["second"] == "blocked"
    store.add_plan_material("run-1", "deposition", note="replacement supplied")
    store.start_plan_check("run-1", "second")

    store.record_plan_check_result("run-1", "second", "unexpected")
    assert run.status == "active"
    assert run.check_states["second"] == "out_of_range"
    assert run.spent_cost == 5
    assert [(event.action, event.check_id, event.outcome_id) for event in run.events
            if event.action in {"result_recorded", "out_of_range"}][-1] == (
        "out_of_range", "second", "unexpected")

    store.pause_plan_run("run-1")
    from investigation.snapshot import load_snapshot, save_snapshot
    reloaded = load_snapshot(save_snapshot(store, tmp_path / "run.json"))
    restored = reloaded.plan_run("run-1")
    assert restored.status == "paused"
    assert restored.evidence_batches == {"first": "batch-1"}
    assert restored.actual_costs == {"first": 2.0, "second": 3.0}


def test_terminated_plan_keeps_costs_but_allows_replacing_unexecuted_plan():
    store = InvestigationStore()
    store.create_verification_plan("conditional", [
        {"check_id": "first", "label": "first", "source_id": "team",
         "relation": "parent", "cost": 2,
         "outcomes": [{"outcome_id": "continue",
                       "next_check_ids": ["second"]}]},
        {"check_id": "second", "label": "second", "source_id": "team",
         "relation": "parent", "cost": 3,
         "outcomes": [{"outcome_id": "done"}]},
    ])
    run = store.start_plan_run("conditional", "run-1")
    store.start_plan_check("run-1", "first")
    store.record_plan_check_result("run-1", "first", "continue")
    store.terminate_plan_run("run-1", note="user stopped")
    assert run.check_states["second"] == "uncommitted"
    assert run.spent_cost == 2

    replacement = store.revise_verification_plan("conditional", [
        {"check_id": "replacement", "label": "replacement",
         "source_id": "other", "relation": "parent", "cost": 1,
         "outcomes": [{"outcome_id": "done"}]},
    ])
    assert [check.check_id for check in replacement.checks] == ["replacement"]
    assert store.plan_run("run-1").events[-1].action == "terminated"


def _branching_plan(store, **kwargs):
    return store.create_verification_plan("branches", [
        {"check_id": "root", "label": "root", "source_id": "team",
         "relation": "parent", "cost": 2,
         "outcomes": [
             {"outcome_id": "go-left", "next_check_ids": ["left"]},
             {"outcome_id": "go-right", "next_check_ids": ["right"]},
         ]},
        {"check_id": "left", "label": "left", "source_id": "team",
         "relation": "parent", "cost": 3,
         "outcomes": [{"outcome_id": "left-done",
                       "next_check_ids": ["join"]}]},
        {"check_id": "right", "label": "right", "source_id": "team",
         "relation": "parent", "cost": 5,
         "outcomes": [{"outcome_id": "right-done",
                       "next_check_ids": ["join"]}]},
        {"check_id": "join", "label": "join", "source_id": "team",
         "relation": "parent", "cost": 1,
         "outcomes": [{"outcome_id": "join-done"}]},
    ], **kwargs)


def test_exclusive_branch_selection_controls_eligibility():
    store = InvestigationStore()
    _branching_plan(store, budget=20)
    run = store.start_plan_run("branches", "run-1")
    assert run.check_states["root"] == "available"
    assert run.check_states["left"] == "waiting"
    assert run.check_states["right"] == "waiting"

    store.start_plan_check("run-1", "root")
    store.record_plan_check_result("run-1", "root", "go-left")
    assert run.check_states["left"] == "available"
    assert run.check_states["right"] == "off_path"
    assert run.check_states["join"] == "waiting"
    with pytest.raises(ValueError):
        store.start_plan_check("run-1", "right")

    # Join only needs the applicable (selected) predecessors.
    store.start_plan_check("run-1", "left")
    store.record_plan_check_result("run-1", "left", "left-done")
    assert run.check_states["join"] == "available"


def test_choice_correction_out_of_range_and_snapshot_roundtrip(tmp_path):
    store = InvestigationStore()
    _branching_plan(store, budget=20)
    run = store.start_plan_run("branches", "run-1")
    store.start_plan_check("run-1", "root")
    store.record_plan_check_result("run-1", "root", "go-left")

    # Out-of-range result on the left branch: cost is spent, dependents block.
    store.start_plan_check("run-1", "left")
    store.record_plan_check_result("run-1", "left", "weird")
    assert run.check_states["left"] == "out_of_range"
    assert run.check_states["join"] == "blocked"
    assert run.spent_cost == 5

    # Correcting the out-of-range result to a planned outcome unblocks join.
    store.correct_plan_check_outcome("run-1", "left", "left-done",
                                     note="lab re-read the image")
    assert run.check_states["left"] == "completed"
    assert run.check_states["join"] == "available"

    # Researcher revises the root choice: left branch leaves the path, but
    # its spent cost stays on the books.
    store.correct_plan_check_outcome("run-1", "root", "go-right")
    assert run.check_states["right"] == "available"
    assert run.check_states["left"] == "completed"  # history is not erased
    assert run.check_states["join"] == "waiting"
    assert run.spent_cost == 5
    with pytest.raises(ValueError):
        store.start_plan_check("run-1", "left")

    off_path = store.off_path_plan_checks("run-1")
    assert [entry["check_id"] for entry in off_path] == ["left"]
    assert off_path[0]["sunk_cost"] == 3
    assert "root" in off_path[0]["reason"]
    assert "go-right" in off_path[0]["reason"]

    preview = store.preview_conditional_plan("branches", "run-1")
    assert preview.available_now == ("right",)
    assert preview.spent_cost == 5
    assert [entry["check_id"] for entry in preview.off_path_checks] == ["left"]
    # Remaining path is right + join; the sunk left cost is not double-counted
    # nor dropped from the budget view.
    assert preview.uncommitted_cost == 6
    assert preview.budget_remaining_in_worst_case == 9

    from investigation.snapshot import load_snapshot, save_snapshot
    reloaded = load_snapshot(save_snapshot(store, tmp_path / "run.json"))
    restored = reloaded.plan_run("run-1")
    assert restored.check_states == run.check_states
    assert restored.observed_outcomes == {"root": "go-right",
                                          "left": "left-done"}
    assert restored.spent_cost == 5
    assert [entry["check_id"]
            for entry in reloaded.off_path_plan_checks("run-1")] == ["left"]
    repreview = reloaded.preview_conditional_plan("branches", "run-1")
    assert repreview.available_now == ("right",)
    assert repreview.budget_remaining_in_worst_case == 9

    # The corrected run can still finish on the new path.
    reloaded.start_plan_check("run-1", "right")
    reloaded.record_plan_check_result("run-1", "right", "right-done")
    assert reloaded.plan_run("run-1").check_states["join"] == "available"
    assert reloaded.plan_run("run-1").spent_cost == 10
    assert reloaded.off_path_plan_checks("run-1")[0]["sunk_cost"] == 3


def _run_with_left_completed(store):
    run = store.start_plan_run("branches", "run-1")
    store.start_plan_check("run-1", "root")
    store.record_plan_check_result("run-1", "root", "go-left",
                                   batch_id="batch-root")
    store.start_plan_check("run-1", "left")
    store.record_plan_check_result("run-1", "left", "left-done",
                                   batch_id="batch-left")
    return run


def test_correction_preview_does_not_mutate_and_confirm_applies():
    store = InvestigationStore()
    _branching_plan(store, budget=20)
    run = _run_with_left_completed(store)
    assert run.check_states["join"] == "available"
    before_states = dict(run.check_states)
    before_events = len(run.events)

    preview = store.preview_plan_correction("run-1", "root", "go-right")
    # Completed left branch falls off the selected path; the join re-waits.
    assert preview.invalidated_check_ids == ("left",)
    assert preview.rewaiting_check_ids == ("join",)
    # Only evidence attached to checks still on the path is retained.
    assert preview.retained_evidence == (("root", "batch-root"),)
    # Worst case after the switch: right (5) + join (1) still fit the budget.
    assert preview.budget_remaining_in_worst_case == 9
    assert preview.potential_budget_increase == 0
    assert preview.status == "pending"
    # The preview itself changed nothing.
    assert run.check_states == before_states
    assert len(run.events) == before_events
    assert run.observed_outcomes == {"root": "go-left", "left": "left-done"}

    confirmed = store.confirm_plan_correction(preview.preview_id)
    assert confirmed.check_states["right"] == "available"
    assert confirmed.check_states["join"] == "waiting"
    assert confirmed.observed_outcomes["root"] == "go-right"
    assert confirmed.spent_cost == 5  # sunk cost is preserved, not re-spent
    assert [entry["check_id"]
            for entry in store.off_path_plan_checks("run-1")] == ["left"]
    assert store.correction_previews("run-1")[0].status == "applied"
    with pytest.raises(ValueError):
        store.confirm_plan_correction(preview.preview_id)


def test_correction_preview_requires_fresh_preview_after_evidence_change():
    store = InvestigationStore()
    _branching_plan(store, budget=20)
    _run_with_left_completed(store)
    preview = store.preview_plan_correction("run-1", "root", "go-right")

    store.receive_evidence("team", [{"record_id": "late-1", "kind": "process",
                                     "ts": 1.0}])
    with pytest.raises(ValueError, match="fresh correction preview"):
        store.confirm_plan_correction(preview.preview_id)
    assert store.correction_previews("run-1")[0].status == "stale"

    # A fresh preview against the new evidence state can be confirmed.
    fresh = store.preview_plan_correction("run-1", "root", "go-right")
    store.confirm_plan_correction(fresh.preview_id)
    assert store.plan_run("run-1").observed_outcomes["root"] == "go-right"


def test_correction_preview_requires_fresh_preview_after_budget_change():
    store = InvestigationStore()
    _branching_plan(store, budget=20)
    _run_with_left_completed(store)
    preview = store.preview_plan_correction("run-1", "root", "go-right")

    store.verification_plan("branches").budget = 6
    with pytest.raises(ValueError, match="fresh correction preview"):
        store.confirm_plan_correction(preview.preview_id)

    tighter = store.preview_plan_correction("run-1", "root", "go-right")
    # spent 5 + worst-case remaining 6 exceeds the tightened budget of 6.
    assert tighter.potential_budget_increase == 5
    assert tighter.budget_remaining_in_worst_case == -5


def test_conflicting_correction_previews_and_snapshot_roundtrip(tmp_path):
    store = InvestigationStore()
    _branching_plan(store, budget=20)
    run = store.start_plan_run("branches", "run-1")
    store.start_plan_check("run-1", "root")
    store.record_plan_check_result("run-1", "root", "go-left")
    store.start_plan_check("run-1", "left")
    store.record_plan_check_result("run-1", "left", "weird")
    assert run.check_states["left"] == "out_of_range"

    # Two mutually exclusive corrections can be previewed side by side.
    switch = store.preview_plan_correction("run-1", "root", "go-right")
    fix_left = store.preview_plan_correction("run-1", "left", "left-done")
    # left is out_of_range (not completed), so nothing completed is lost;
    # the blocked join goes back to waiting for the right branch instead.
    assert switch.invalidated_check_ids == ()
    assert switch.rewaiting_check_ids == ("join",)
    assert fix_left.invalidated_check_ids == ()
    assert fix_left.rewaiting_check_ids == ()
    assert {p.status for p in store.correction_previews("run-1")} == {"pending"}

    from investigation.snapshot import load_snapshot, save_snapshot
    reloaded = load_snapshot(save_snapshot(store, tmp_path / "previews.json"))
    restored = {p.preview_id: p for p in reloaded.correction_previews("run-1")}
    assert restored[switch.preview_id].status == "pending"
    assert restored[switch.preview_id].rewaiting_check_ids == ("join",)
    assert restored[fix_left.preview_id].retained_evidence == ()

    # Confirming one preview stales the conflicting one, even after reload.
    reloaded.confirm_plan_correction(switch.preview_id)
    statuses = {p.preview_id: p.status
                for p in reloaded.correction_previews("run-1")}
    assert statuses[switch.preview_id] == "applied"
    assert statuses[fix_left.preview_id] == "stale"
    with pytest.raises(ValueError):
        reloaded.confirm_plan_correction(fix_left.preview_id)
    assert reloaded.plan_run("run-1").observed_outcomes == {"root": "go-right"}
    assert reloaded.plan_run("run-1").check_states["left"] == "out_of_range"
