"""Conditional verification plans under a limited budget."""

from investigation import InvestigationStore

store = InvestigationStore()
store.import_source("edr", [{
    "record_id": "c", "kind": "process", "ts": 1.0, "aliases": ["guid:child"],
    "refs": [{"relation": "parent", "target": "guid:a", "direction": "incoming"}],
}, {"record_id": "pa", "kind": "process", "ts": 0.9, "aliases": ["guid:a"]}])
store.import_source("host2", [{
    "record_id": "c2", "kind": "process", "ts": 1.0, "aliases": ["guid:child"],
    "refs": [{"relation": "parent", "target": "guid:b", "direction": "incoming"}],
}, {"record_id": "pb", "kind": "process", "ts": 0.8, "aliases": ["guid:b"]}])
store.import_source("forensics", [{"record_id": "f1", "kind": "file", "ts": 0.5}])

store.create_verification_plan("round-1", [
    {"check_id": "mem-check", "source_id": "mem", "relation": "parent",
     "cost": 4.0,
     "outcomes": [
         {"outcome_id": "is-a", "next_checks": ["disk-check"], "records": [{
             "record_id": "r", "kind": "process", "ts": 1.0,
             "aliases": ["guid:child"],
             "refs": [{"relation": "parent", "target": "guid:a",
                       "direction": "incoming"}]}]},
         {"outcome_id": "is-b", "next_checks": ["net-check"], "records": [{
             "record_id": "r", "kind": "process", "ts": 1.0,
             "aliases": ["guid:child"],
             "refs": [{"relation": "parent", "target": "guid:b",
                       "direction": "incoming"}]}]},
     ]},
    {"check_id": "disk-check", "source_id": "disk", "relation": "wrote",
     "cost": 3.0, "requires": ["forensics"],
     "outcomes": [{"outcome_id": "wrote", "records": []},
                  {"outcome_id": "clean", "records": []}]},
    {"check_id": "net-check", "source_id": "net", "relation": "opened",
     "cost": 5.0,
     "outcomes": [{"outcome_id": "connected", "records": []},
                  {"outcome_id": "quiet", "records": []}]},
], seeds=["guid:child"], budget=10.0)

preview = store.preview_plan("round-1")
for path in preview.paths:
    print("path", path.steps, "cost", path.cost,
          "worst-case groups", path.indistinguishable_groups)
print("worst case:", preview.worst_case_groups,
      "max cost:", preview.max_path_cost)

status = store.plan_status("round-1")
print("startable:", status.startable, "waiting:", status.waiting)

store.record_check_result("round-1", "mem-check", "is-a")
status = store.confirm_plan("round-1")
print("spent:", status.spent, "remaining:", status.remaining_budget,
      "startable:", status.startable, "waiting:", status.waiting)

store.revoke_source("forensics")
status = store.plan_status("round-1")
print("after prerequisite withdrawal, invalidated:", status.invalidated)

comparison = store.compare_plans("round-1", "round-1")
for entry in comparison.entries:
    print(entry.plan_id, "committed:", entry.committed_cost,
          "uncommitted:", entry.uncommitted_cost)

