"""Group path comparison, time-ranged judgments, independent reopening."""
from investigation import Hypothesis, InvestigationStore


def proc(record_id, pid, guid=None, parent=None, ts=0.0, **extra):
    record = {"record_id": record_id, "kind": "process", "ts": ts, "pid": pid,
              "aliases": ([f"guid:{guid}"] if guid else []),
              "refs": ([{"relation": "parent", "target": f"guid:{parent}"}]
                       if parent else [])}
    record.update(extra)
    return record


def main() -> None:
    store = InvestigationStore()
    store.import_source("edr-a", [
        proc("c", 1, "child", "p-a", ts=100.0),
        proc("pa", 2, "p-a", ts=90.0),
        proc("ga", 3, "g-a", ts=80.0,
             refs=[{"relation": "parent", "target": "guid:p-a",
                    "direction": "outgoing"}]),
    ], trust=0.9, scopes=["host-a"])
    store.import_source("edr-b", [
        proc("c2", 1, "child", "p-b", ts=100.0),
        proc("pb", 2, "p-b", ts=95.0),
    ], trust=0.6, scopes=["host-b"])

    def pick(guid):
        return Hypothesis.make_id(store.get_event("guid:child").event_id,
                                  "parent",
                                  store.get_event(guid).event_id)

    # 1) Two competing groups, each pinning a different explanation.
    store.create_hypothesis_set("theory-a", [pick("guid:p-a")])
    store.create_hypothesis_set("theory-b", [pick("guid:p-b")])
    comparison = store.compare_set_paths("guid:child",
                                         ["theory-a", "theory-b"])
    for set_id in comparison.set_ids:
        hops = comparison.unique_hops[set_id]
        print(f"path unique to {set_id}:",
              [(h.cause_id, h.relation, h.effect_id) for h in hops])

    # 2) What does one group explain, conflict with, and leave open?
    store.trace("guid:child", set_id="theory-a", save=True)
    report = store.explain_set("theory-a")
    print("explained:", report.explained_events)
    print("conflicting sources:", report.conflicting_sources)
    print("unexplained slots:", report.unexplained_slots)

    # 3) Time-ranged manual judgments: local, never generalized.
    link_id = store.add_manual_link(
        "guid:g-a", "guid:child", "controls", note="phase-1 only",
        valid_from=0.0, valid_to=100.0)
    print("at t=50:", [h.relation for h in store.trace(
        "guid:child", at=50.0, use_set=False).upstream])
    print("at t=500:", [h.relation for h in store.trace(
        "guid:child", at=500.0, use_set=False).upstream])
    store.adjust_manual_link_window(link_id, 0.0, 1000.0)
    print("stale after window adjust:",
          [p.seed for p in store.stale_paths()])

    # 4) Save each group; reopen independently; rationale is never lost.
    gid = store.save_group("theory-a", note="phase-1 judgment",
                           reasons={pick("guid:p-b"): "edr-b trust too low"})
    store.revoke_source("edr-b")
    group = store.reopen_group(gid)
    print("archived selection:", [h["hypothesis_id"] for h in group.selected])
    print("archived exclusions:",
          [(h["hypothesis_id"], h["exclusion_reason"])
           for h in group.excluded])
    reopened = store.activate_saved_group(gid, activate=True)
    print("reopened set:", reopened.set_id,
          [h.cause_id for h in store.trace("guid:child").upstream])


if __name__ == "__main__":
    main()
