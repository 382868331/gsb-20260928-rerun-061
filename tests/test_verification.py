from investigation import InvestigationStore
from investigation.snapshot import load_snapshot, save_snapshot


def proc(record_id, guid, parent=None, ts=0.0):
    record = {
        "record_id": record_id,
        "kind": "process",
        "ts": ts,
        "aliases": [f"guid:{guid}"],
        "refs": [],
    }
    if parent is not None:
        record["refs"].append({
            "relation": "parent",
            "target": f"guid:{parent}",
            "direction": "incoming",
        })
    return record


def conflicting_store():
    store = InvestigationStore()
    store.import_source("a", [proc("c", "child", "pa"), proc("pa", "pa")])
    store.import_source("b", [proc("c2", "child", "pb"), proc("pb", "pb")])
    return store


def check(outcomes, source_id="follow", record_id="r1"):
    return {
        "check_id": "parent-check",
        "effect_id": "guid:child",
        "relation": "parent",
        "source_id": source_id,
        "record_id": record_id,
        "outcomes": outcomes,
    }


def test_planned_outcomes_preview_exclusions_paths_and_indistinguishable_groups():
    store = conflicting_store()
    pa = store.get_event("guid:pa").event_id
    pb = store.get_event("guid:pb").event_id
    before_edges = len(store.edges())

    plan = store.create_verification_plan("plan-1", [check([
        {"outcome_id": "pa", "cause_id": "guid:pa"},
        {"outcome_id": "pb", "cause_id": "guid:pb"},
    ])], seeds=["guid:child"])

    by_outcome = {preview.outcome_id: preview for preview in plan.previews}
    assert by_outcome["pa"].excluded_hypothesis_ids == (
        f"h:{store.get_event('guid:child').event_id}#parent<-{pb}",)
    assert [hop.cause_id for hop
            in by_outcome["pa"].retained_paths[0].upstream] == [pa]
    assert by_outcome["pa"].indistinguishable_groups == ()
    assert by_outcome["pb"].supported_hypothesis_ids == (
        f"h:{store.get_event('guid:child').event_id}#parent<-{pb}",)
    assert len(by_outcome["pb"].retained_paths[0].upstream) == 1
    # Planned evidence is never represented as established fact.
    assert len(store.edges()) == before_edges
    assert "follow" not in {source.source_id for source in store.sources()}


def test_shared_source_is_visible_and_repeated_confirmation_is_not_independent():
    store = conflicting_store()
    planned_check = check([{"outcome_id": "pa", "cause_id": "guid:pa"}])
    first = store.create_verification_plan("plan-1", [planned_check])
    second = store.create_verification_plan("plan-2", [dict(planned_check)])

    assert second.previews[0].shared_source_plan_ids == ("plan-1",)
    first_material = store.record_verification_result(
        "plan-1", "parent-check",
        proc("r1", "child", "pa"), claimed_outcome_id="pa")
    second_material = store.record_verification_result(
        "plan-2", "parent-check",
        proc("r1", "child", "pa"), claimed_outcome_id="pa")
    repeated = next(m for m in store.surprising_materials()
                    if m.material_id == second_material)
    assert repeated.duplicate_material_ids == (first_material,)
    assert repeated.shared_source_plan_ids == ("plan-1",)

    store.accept_verification_materials([first_material, second_material])
    hypothesis = next(h for h in store.hypotheses()
                      if h.cause_id == store.get_event("guid:pa").event_id)
    assert {(claim.source_id, claim.record_id) for claim in hypothesis.active_claims} == {
        ("a", "c"), ("follow", "r1")}


def test_accepted_material_retraction_keeps_original_exclusion_and_reason():
    store = conflicting_store()
    store.create_verification_plan("plan-1", [check([
        {"outcome_id": "pa", "cause_id": "guid:pa"},
    ])])

    material_id = store.record_verification_result(
        "plan-1", "parent-check",
        proc("r1", "child", "pa"), claimed_outcome_id="pa")
    assert store.surprising_materials() == []

    decisions = store.accept_verification_materials(
        [material_id], reason="memory image accepted")
    first_decision = store.verification_decisions()[0]
    assert first_decision.reason == "memory image accepted"
    excluded, = first_decision.excluded_hypothesis_ids
    assert excluded.endswith("#parent<-" + store.get_event("guid:pb").event_id)

    assert store.retract_accepted_material(material_id, reason="source withdrawn")
    actions = [(decision.action, decision.reason)
               for decision in store.verification_decisions()]
    assert actions == [
        ("accepted", "memory image accepted"),
        ("retracted", "source withdrawn"),
    ]
    assert store.verification_decisions()[0].material_id == material_id


def test_contradictory_material_has_no_automatic_exclusion_until_user_decides_scope():
    store = conflicting_store()
    store.create_verification_plan("plan-1", [check([
        {"outcome_id": "pa", "cause_id": "guid:pa"},
    ])])

    material_id = store.record_verification_result(
        "plan-1", "parent-check",
        proc("r1", "child"), claimed_outcome_id="pa")
    surprising, = store.surprising_materials()
    assert "observed_relation_differs_from_claimed_outcome" in surprising.contradictions
    decision, = store.accept_verification_materials(
        [material_id], reason="user accepts raw material without automatic exclusion")
    assert decision.excluded_hypothesis_ids == ()


def test_alternative_outcome_study_is_independent_of_live_investigation(tmp_path):
    store = conflicting_store()
    store.create_verification_plan("plan-1", [check([
        {"outcome_id": "pa", "cause_id": "guid:pa"},
        {"outcome_id": "pb", "cause_id": "guid:pb"},
    ])])

    study = store.study_alternative_outcome("plan-1", "parent-check", "pa")
    assert study.active_set == "trial:plan-1:parent-check:pa"
    assert [hop.cause_id for hop
            in study.trace("guid:child").upstream] == [
        study.get_event("guid:pa").event_id]
    # The hypothetical source is absent from the real investigation.
    assert not store.get_event("follow:r1")

    reloaded = load_snapshot(save_snapshot(store, tmp_path / "case.json"))
    saved_plan, = reloaded.verification_plans()
    assert saved_plan.hypothesis_snapshot
    assert [preview.outcome_id for preview in saved_plan.previews] == ["pa", "pb"]
    assert reloaded.verification_decisions() == []
