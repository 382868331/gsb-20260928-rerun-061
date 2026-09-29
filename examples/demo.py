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

    # 4) Snapshot + restore.
    path = save_snapshot(store, "/tmp/investigation_snapshot.json")
    reloaded = load_snapshot(path)
    assert len(reloaded.edges()) == 3
    print("\nsnapshot saved to", path, "- edges after reload:",
          len(reloaded.edges()))


if __name__ == "__main__":
    main()
