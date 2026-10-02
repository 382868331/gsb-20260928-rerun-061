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
