import pytest

from investigation import InvestigationStore


def _diamond_plan(store, **kwargs):
    return store.create_verification_plan("diamond", [
        {"check_id": "root", "label": "root", "source_id": "team",
         "relation": "parent", "cost": 2,
         "outcomes": [{"outcome_id": "split",
                       "next_check_ids": ["m1", "m2"]}]},
        {"check_id": "m1", "label": "m1", "source_id": "team",
         "relation": "parent", "cost": 3,
         "outcomes": [{"outcome_id": "m1-a", "next_check_ids": ["join"]},
                      {"outcome_id": "m1-b", "next_check_ids": ["alt1"]}]},
        {"check_id": "m2", "label": "m2", "source_id": "team",
         "relation": "parent", "cost": 4,
         "outcomes": [{"outcome_id": "m2-a", "next_check_ids": ["join"]},
                      {"outcome_id": "m2-b", "next_check_ids": ["alt2"]}]},
        {"check_id": "join", "label": "join", "source_id": "team",
         "relation": "parent", "cost": 1,
         "outcomes": [{"outcome_id": "j-done"}]},
        {"check_id": "alt1", "label": "alt1", "source_id": "team",
         "relation": "parent", "cost": 1,
         "outcomes": [{"outcome_id": "a1-done"}]},
        {"check_id": "alt2", "label": "alt2", "source_id": "team",
         "relation": "parent", "cost": 1,
         "outcomes": [{"outcome_id": "a2-done"}]},
    ], **kwargs)


def _completed_diamond_run(store):
    store.start_plan_run("diamond", "run-1")
    store.start_plan_check("run-1", "root")
    store.record_plan_check_result("run-1", "root", "split")
    store.start_plan_check("run-1", "m1")
    store.record_plan_check_result("run-1", "m1", "m1-a")
    store.start_plan_check("run-1", "m2")
    store.record_plan_check_result("run-1", "m2", "m2-a")
    store.start_plan_check("run-1", "join")
    store.record_plan_check_result("run-1", "join", "j-done")
    return store.plan_run("run-1")


def test_joint_study_splits_shared_and_independent_impact():
    store = InvestigationStore()
    _diamond_plan(store, budget=20)
    run = _completed_diamond_run(store)
    assert run.spent_cost == 10

    study = store.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])
    assert study.status == "pending"
    assert study.conflict_chains == ()
    # The diamond join is downstream of both corrections and is counted
    # once; alt1/alt2 are independent impacts of a single correction.
    assert study.affected_check_ids == ("alt1", "alt2", "join")
    assert study.shared_impact_check_ids == ("join",)
    assert dict(study.independent_impacts) == {
        "m1": ("alt1",), "m2": ("alt2",)}
    # The study itself did not touch the run.
    assert run.observed_outcomes == {"root": "split", "m1": "m1-a",
                                     "m2": "m2-a", "join": "j-done"}


def test_joint_study_budget_compares_two_strategies():
    store = InvestigationStore()
    _diamond_plan(store, budget=12)
    _completed_diamond_run(store)
    study = store.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])

    comparison = store.compare_joint_strategies(study.study_id)
    options = {option["strategy"]: option
               for option in comparison["options"]}
    # spent 10 of 12: the invalidated join (cost 1) always fits; only one
    # of the optional alt nodes can be funded on top.
    minimum = options["min_recompute"]
    assert minimum["recheck_check_ids"] == ("join",)
    assert minimum["recompute_cost"] == 1
    assert minimum["pending_check_ids"] == ()
    maximum = options["preserve_max"]
    assert maximum["recheck_check_ids"] == ("join", "alt1")
    assert maximum["recompute_cost"] == 2
    # The node that cannot be re-checked stays explicitly pending.
    assert maximum["pending_check_ids"] == ("alt2",)
    assert maximum["within_budget"]

    # Without a budget cap preserve_max re-checks everything, while
    # min_recompute still only re-checks the invalidated conclusion.
    store2 = InvestigationStore()
    _diamond_plan(store2)
    _completed_diamond_run(store2)
    study2 = store2.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])
    uncapped = store2.compare_joint_strategies(study2.study_id)
    uncapped_options = {option["strategy"]: option
                        for option in uncapped["options"]}
    assert uncapped_options["preserve_max"]["recheck_check_ids"] == \
        ("join", "alt1", "alt2")
    assert uncapped_options["min_recompute"]["recheck_check_ids"] == ("join",)
    for option in uncapped["options"]:
        assert option["pending_check_ids"] == ()


def test_confirm_joint_study_applies_and_is_idempotent():
    store = InvestigationStore()
    _diamond_plan(store, budget=20)
    _completed_diamond_run(store)
    study = store.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])

    run = store.confirm_joint_study(study.study_id, strategy="min_recompute")
    assert run.observed_outcomes["m1"] == "m1-b"
    assert run.observed_outcomes["m2"] == "m2-b"
    assert run.check_states["alt1"] == "available"
    assert run.check_states["alt2"] == "available"
    assert study.status == "applied"
    assert study.strategy == "min_recompute"
    assert study.applied_corrections == (("m1", "m1-b"), ("m2", "m2-b"))
    spent = run.spent_cost
    events = len(run.events)

    # A duplicate submission changes nothing and never charges twice.
    again = store.confirm_joint_study(study.study_id)
    assert again.spent_cost == spent
    assert len(again.events) == events

    explanation = store.explain_joint_study(study.study_id)
    assert explanation["status"] == "applied"
    assert [entry["status"] for entry in explanation["corrections"]] == [
        "adopted", "adopted"]
    nodes = {node["check_id"]: node
             for node in explanation["affected_nodes"]}
    assert nodes["join"]["impact"] == "shared"
    assert nodes["alt1"]["impact"] == "independent"


def test_joint_study_conflict_chains_are_explicit():
    store = InvestigationStore()
    _diamond_plan(store, budget=20)
    _completed_diamond_run(store)

    # Two corrections contesting the same original evidence.
    study = store.create_joint_study(
        "run-1", [("m1", "m1-a"), ("m1", "m1-b")])
    assert study.status == "conflicted"
    chain = study.conflict_chains[0]
    assert chain["kind"] == "same_original_evidence"
    assert chain["check_id"] == "m1"
    assert chain["outcome_ids"] == ["m1-a", "m1-b"]
    assert len(chain["chain"]) == 2
    with pytest.raises(ValueError, match="unresolved conflicts"):
        store.compare_joint_strategies(study.study_id)
    with pytest.raises(ValueError, match="conflicted"):
        store.confirm_joint_study(study.study_id)

    # One correction negating the record asserted by another.
    store2 = InvestigationStore()
    store2.create_verification_plan("neg", [
        {"check_id": "c1", "label": "c1", "source_id": "lab",
         "relation": "parent", "cost": 1,
         "outcomes": [
             {"outcome_id": "c1-old"},
             {"outcome_id": "c1-new",
              "records": [{"record_id": "rec-x", "kind": "process",
                           "ts": 1.0}]}]},
        {"check_id": "c2", "label": "c2", "source_id": "lab",
         "relation": "parent", "cost": 1,
         "outcomes": [
             {"outcome_id": "c2-old"},
             {"outcome_id": "c2-new",
              "records": [{"record_id": "rec-y", "kind": "process",
                           "ts": 2.0,
                           "retracts": [{"source_id": "lab",
                                         "record_id": "rec-x"}]}]}]},
    ])
    store2.start_plan_run("neg", "run-1")
    store2.start_plan_check("run-1", "c1")
    store2.record_plan_check_result("run-1", "c1", "c1-old")
    store2.start_plan_check("run-1", "c2")
    store2.record_plan_check_result("run-1", "c2", "c2-old")
    negated = store2.create_joint_study(
        "run-1", [("c1", "c1-new"), ("c2", "c2-new")])
    assert negated.status == "conflicted"
    kinds = {chain["kind"] for chain in negated.conflict_chains}
    assert kinds == {"mutual_negation"}
    chain = negated.conflict_chains[0]
    assert chain["check_ids"] == ["c1", "c2"]
    assert any("rec-x" in step for step in chain["chain"])
    # No winner was picked by application order.
    run = store2.plan_run("run-1")
    assert run.observed_outcomes == {"c1": "c1-old", "c2": "c2-old"}


def test_joint_study_requires_fresh_study_after_evidence_change():
    store = InvestigationStore()
    _diamond_plan(store, budget=20)
    _completed_diamond_run(store)
    study = store.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])

    store.receive_evidence("team", [{"record_id": "late-1",
                                     "kind": "process", "ts": 1.0}])
    with pytest.raises(ValueError, match="fresh study"):
        store.confirm_joint_study(study.study_id)
    # The outdated study is kept on file, marked stale.
    kept = store.joint_study(study.study_id)
    assert kept.status == "stale"
    explanation = store.explain_joint_study(study.study_id)
    assert [entry["status"] for entry in explanation["corrections"]] == [
        "stale", "stale"]

    fresh = store.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])
    store.confirm_joint_study(fresh.study_id)
    assert store.plan_run("run-1").observed_outcomes["m1"] == "m1-b"


def test_joint_study_snapshot_roundtrip_and_explain(tmp_path):
    from investigation.snapshot import load_snapshot, save_snapshot

    store = InvestigationStore()
    _diamond_plan(store, budget=20)
    _completed_diamond_run(store)
    pending = store.create_joint_study(
        "run-1", [("m1", "m1-b"), ("m2", "m2-b")])
    store.confirm_joint_study(pending.study_id)
    conflicted = store.create_joint_study(
        "run-1", [("m1", "m1-a"), ("m1", "m1-b")])

    reloaded = load_snapshot(save_snapshot(store, tmp_path / "studies.json"))
    studies = {study.study_id: study
               for study in reloaded.joint_studies("run-1")}
    assert studies[pending.study_id].status == "applied"
    assert studies[pending.study_id].applied_corrections == (
        ("m1", "m1-b"), ("m2", "m2-b"))
    assert studies[pending.study_id].shared_impact_check_ids == ("join",)
    assert studies[conflicted.study_id].status == "conflicted"
    assert studies[conflicted.study_id].conflict_chains[0]["kind"] == \
        "same_original_evidence"

    explanation = reloaded.explain_joint_study(pending.study_id)
    assert [entry["status"] for entry in explanation["corrections"]] == [
        "adopted", "adopted"]
    skipped = reloaded.explain_joint_study(conflicted.study_id)
    assert [entry["status"] for entry in skipped["corrections"]] == [
        "not_adopted", "not_adopted"]

    # A stale part shows up when the observed outcome moved on after
    # the study was applied.
    reloaded.correct_plan_check_outcome("run-1", "m1", "m1-a")
    moved = reloaded.explain_joint_study(pending.study_id)
    statuses = {entry["check_id"]: entry["status"]
                for entry in moved["corrections"]}
    assert statuses == {"m1": "stale", "m2": "adopted"}
