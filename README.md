# 安全事件调查系统

第一阶段只做证据整理与因果关系追踪，不提供日志展示页，也不基于时间邻近性自动推断因果。

## 模型

- `Event`：人工录入的进程、文件或网络事件，使用稳定的 `event_id` 建立身份。
- `Source`：一份人工记录或导入批次，用 `source_id` 标识。
- `Record`：一条记录，包含一个事件及该记录明确陈述的若干 `Relation`。
- `Relation`：有向关系。`direction="in"` 表示对端指向当前事件，`direction="out"` 表示当前事件指向对端。
- `Link`：两个已知事件之间已接通的因果联系，保留来源记录和解释。

## 追踪规则

关系只来自记录中的显式陈述；时间戳仅作为事件属性。导入时若关系的一端尚未出现，会保留为 `unresolved_relations`。缺失事件后来补到时，系统自动接线。

重复导入相同 `source_id` 会被拒绝。撤销来源时：

1. 仅由该来源引用的事件被删除。
2. 该来源陈述的关系和边全部删除。
3. 其他存活来源仍引用的事件和边保留。
4. 被删事件导致存活来源的关系无法连接时，重新登记为未接关系。

因此撤销不会留下无法解释来源的幽灵关系；被撤销来源的陈述不会在以后事件补到时“复活”。

## 用法

```python
from investigation import Event, EventKind, Investigation, LinkKind, Record, Relation, Source

case = Investigation()
case.import_source(
    Source("ir-note-1", "analyst"),
    [
        Record(
            Event("child", EventKind.PROCESS, {"pid": 4242}, 10.1),
            [Relation("parent", LinkKind.PARENT, "in", "父进程派生了该进程")],
        )
    ],
)

case.import_source("ir-note-2", [
    Event("parent", EventKind.PROCESS, {"pid": 100}, 9.8),
])

result = case.trace("parent")
snapshot = case.save_snapshot("snapshots/case.json")
```

`TraceResult.hops` 中的每个 `Hop` 都带有 `source_id`、`record_id` 和 `rationale`，可回溯到具体记录。快照为 JSON，包含事件、边、边的全部来源引用及未接关系。

## 测试

```bash
.venv/bin/python -m pytest
```
