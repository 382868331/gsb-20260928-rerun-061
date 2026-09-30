"""Disputed parentage, pinned hypotheses, correction, frozen findings."""
from investigation import Casebook, Hypothesis, InvestigationStore


def proc(record_id, pid, guid=None, parent=None, ts=0.0):
    return {
        "record_id": record_id, "kind": "process", "ts": ts, "pid": pid,
        "aliases": [f"guid:{guid}"] if guid else [],
        "refs": ([{"relation": "parent", "target": f"guid:{parent}"}]
                 if parent else []),
    }


def main() -> None:
    store = InvestigationStore()

    # 1) Child arrives before either candidate parent.
    store.import_source("edr-a", [
        proc("c", 4444, "child", "p-a", ts=100.0),
    ], trust=0.9, scopes=["host-a"], description="EDR feed A")
    print("pending before parents arrive:", len(store.pending_refs()))

    # 2) Late parents: recycled PID 1234, distinct GUIDs, two feeds disagree.
    store.import_source("edr-a", [
        proc("c", 4444, "child", "p-a", 100.0),
        proc("pa", 1234, "p-a", ts=90.0),
    ], trust=0.9, scopes=["host-a"])
    store.import_source("edr-b", [
        proc("c2", 4444, "child", "p-b", 100.0),
        proc("pb", 1234, "p-b", 99.999),
    ], trust=0.6, scopes=["host-b"])

    for group in store.conflict_groups():
        print(f"\ndisputed {group.relation} of {group.effect_id}:")
        for h in group.hypotheses:
            evidence = ", ".join(f"{c.source_id}/{c.record_id}"
                                  for c in h.active_claims)
            print(f"  <- {h.cause_id}  confidence={h.confidence:.2f} "
                  f"scopes={sorted(h.scopes)} evidence=[{evidence}]")

    # 3) Analyst keeps one hypothesis for continued tracking.
    group = store.conflict_groups()[0]
    pick_a = next(h.hypothesis_id for h in group.hypotheses
                  if h.cause_id.endswith(":pa"))
    store.create_hypothesis_set("working", [pick_a], activate=True)
    store.trace("guid:child", save=True)
    print("\nupsream under working set:",
          [h.cause_id for h in store.trace("guid:child").upstream])

    # 4) Save the judgment; later feed A corrects and withdraws its claim.
    book = Casebook(case_id="INC-42")
    finding_id = book.save_finding(store, title="initial: parent A")
    store.import_source("edr-a-correction", [{
        "record_id": "fix-1", "kind": "process",
        "aliases": ["guid:child"],
        "retracts": [{"source_id": "edr-a", "record_id": "c"}],
        "refs": [],
    }], trust=1.0, scopes=["correction"])

    comparison = book.compare_with_latest(finding_id, store)
    print("picked hypotheses no longer supported:",
          comparison.selected_hypotheses_missing)

    # 5) The old finding reopens exactly as decided; it is never overwritten.
    past = book.reopen(finding_id)
    print("past conflict groups:", len(past.conflict_groups()))
    book.save("/tmp/investigation_casebook.json")
    print("casebook saved: /tmp/investigation_casebook.json")


if __name__ == "__main__":
    main()
