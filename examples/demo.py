"""End-to-end walkthrough: out-of-order ingestion + causal tracing."""
from investigation import InvestigationStore
from investigation.snapshot import load_snapshot, save_snapshot


def main() -> None:
    store = InvestigationStore()

    # 1) A suspicious child process arrives BEFORE its parent record.
    store.import_source("edr", [
        {"record_id": "evt-2", "kind": "process", "ts": 102.0,
         "pid": 4444, "aliases": ["guid:evil-child"],
         "refs": [{"relation": "parent", "target": "guid:evil-parent"}]},
    ], description="EDR collector")
    print("after child only: edges=%d pending=%d"
          % (len(store.edges()), len(store.pending_refs())))

    # 2) Remaining evidence arrives, including the late parent, a file write
    #    and a network connection - all out of timestamp order.
    store.import_source("oslogs", [
        {"record_id": "evt-1", "kind": "process", "ts": 100.0,
         "pid": 1234, "aliases": ["guid:evil-parent"], "refs": []},
        {"record_id": "evt-3", "kind": "file", "ts": 104.0,
         "path": "/tmp/payload", "aliases": ["file:/tmp/payload"],
         "refs": [{"relation": "wrote", "target": "guid:evil-child"}]},
        {"record_id": "evt-4", "kind": "network", "ts": 105.0,
         "dst": "203.0.113.9:443",
         "refs": [{"relation": "opened", "target": "guid:evil-child"}]},
    ], description="OS audit logs")

    # 3) Trace outward from the suspicious process.
    trace = store.trace("guid:evil-child")
    print("\nupstream (causes):")
    for hop in trace.upstream:
        print("  %s --%s--> %s  [evidence: %s]" % (
            hop.cause_id, hop.relation, hop.effect_id,
            ", ".join(f"{c.source_id}/{c.record_id}" for c in hop.claims)))
    print("downstream (effects):")
    for hop in trace.downstream:
        print("  %s --%s--> %s  [evidence: %s]" % (
            hop.cause_id, hop.relation, hop.effect_id,
            ", ".join(f"{c.source_id}/{c.record_id}" for c in hop.claims)))

    # 4) A later correction can disagree without overwriting the first claim.
    store.import_source("analyst-review", [
        {"record_id": "evt-2-review", "kind": "process", "ts": 102.0,
         "aliases": ["guid:evil-child"],
         "refs": [{"relation": "parent",
                   "target": "guid:review-parent",
                   "confidence_low": 0.3,
                   "confidence_high": 0.55}]},
        {"record_id": "review-parent", "kind": "process", "ts": 99.0,
         "aliases": ["guid:review-parent"]},
    ], description="Later analyst correction")
    conflicts = store.conflicting_hypotheses("guid:evil-child", "parent")
    print("\ncompeting parent hypotheses:", len(conflicts))
    for hypothesis in conflicts:
        print("  parent=%s range=%s claims=%s" % (
            hypothesis.cause_id,
            hypothesis.confidence_range(),
            ", ".join(f"{e.claim.source_id}/{e.claim.record_id}"
                       for e in hypothesis.evidence),
        ))

    store.close_investigation("demo-case", "guid:evil-child",
                              "initial EDR/OS causal judgment")

    # 5) Snapshot + restore preserves the frozen judgment and current graph.
    path = save_snapshot(store, "/tmp/investigation_snapshot.json")
    reloaded = load_snapshot(path)
    assert len(reloaded.edges()) == 4
    print("\nsnapshot saved to", path, "- edges after reload:",
          len(reloaded.edges()))


if __name__ == "__main__":
    main()
