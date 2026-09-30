# 安全事件调查系统（首轮：证据整理与关系追踪）

这不是日志展示页。系统接收人工导入的**进程 / 文件 / 连接**事件，先解决
“这个活动是谁、来自哪份记录、和谁有明确因果”，再谈检测规则（后续轮次）。

## 核心原则

- **记录（record）是唯一事实来源**：每个事件和每条因果边都带有
  `(source_id, record_id)` 形式的来源声明（claim），每条联系都能解释
  “来自哪份来源的哪条记录”。
- **时间相近不等于因果**：系统只沿记录中**显式声明**的引用建边，
  绝不根据时间戳接近、同名进程等伪相似特征推断关系。
- **稳定身份优先**：跨采集器的同一活动通过 GUID 等稳定别名归并；
  PID 这类会被回收的标识不自动当作身份。
- **乱序安全**：父/目标事件尚未导入时，引用进入 `pending`（未接上），
  目标补录后自动连接，不会产生悬空边。
- **重复导入幂等**：同一 `source_id` 再次导入是整批替换；完全相同的
  批次不会产生重复事件或重复来源声明。
- **撤销无幽灵**：撤销一个来源后，图从剩余记录整体重放重建；只被该
  来源声明的事件与边全部消失，仍被其他来源声明的关系保留。
- **分歧是假设，不是覆盖**：不同来源给出不同父事件时，分别保存为
  `CausalHypothesis`，各自保留证据记录和可信范围；分析人员可选择一组
  假设继续追踪。
- **调查结论不可变**：关闭调查会冻结当时选择、路径和判断。后续导入、
  来源更正或撤销只标记受影响路径，可重开旧结论并与最新证据比较。

## 记录格式

```python
{
    "record_id": "evt-2",          # 来源内唯一；缺省事件 id = source_id:record_id
    "kind": "process",             # process | file | network
    "ts": 102.0,
    "aliases": ["guid:evil-child"], # 稳定身份别名，用于跨来源归并与引用
    "refs": [
        {"relation": "parent",      # 关系名自定义：parent/wrote/opened ...
         "target": "guid:evil-parent",
         "direction": "incoming",  # incoming: target -> 本事件；outgoing 反向
         "confidence_low": 0.72,
         "confidence_high": 0.91}
    ]
}
```

## 用法

```python
from investigation import InvestigationStore
from investigation.snapshot import save_snapshot, load_snapshot

store = InvestigationStore()
store.import_source("edr", records, description="EDR 采集")

# 子事件先到、父事件后到：先 pending，补录后自动连边
store.pending_refs()
store.edges()

# 从一个可疑事件沿显式因果双向追踪
result = store.trace("guid:evil-child")
for hop in result.upstream:      # 谁导致了它
    ...
for hop in result.downstream:    # 它导致了什么
    hop.claims                   # 每条联系的来源记录

for hypothesis in store.conflicting_hypotheses("guid:evil-child", "parent"):
    hypothesis.evidence
    hypothesis.confidence_range()
store.select_hypotheses([hypothesis.hypothesis_id])

record_id = store.add_manual_link("guid:a", "guid:b", "influenced")
store.revoke_manual_link(record_id)
store.close_investigation("case-1", "guid:evil-child", "当时判断")
comparison = store.compare_investigation("case-1")
store.reopen_investigation("case-1")

store.revoke_source("edr")      # 撤销来源，整体重放，无残留
save_snapshot(store, "case.json")
store = load_snapshot("case.json")
```

## 文件

- `investigation/models.py`：事件、来源、边、证据、因果假设、未决引用模型
- `investigation/store.py`：导入/撤销、身份归并、分歧假设、假设选择、
  人工关联、受影响调查刷新、双向追踪、快照序列化
- `investigation/snapshot.py`：快照读写
- `tests/test_investigation.py`：乱序、伪相似、重复 PID、冲突父事件、
  来源更正、人工撤销、调查归档对比等场景测试

## 运行测试

```sh
python3 -m pytest tests/ -q
PYTHONPATH=. python3 examples/demo.py
```
