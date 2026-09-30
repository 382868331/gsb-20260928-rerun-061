# 安全事件调查系统（第二轮：带分歧的因果假设）

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

## 第二轮：分歧、假设选择、增量重算、归档对比

- **冲突不合并**：同一（子事件、关系）槽位出现不同原因时，生成多个
  `Hypothesis`。每条候选保留各自的来源声明、可信值（trust/confidence）
  与可信范围（scopes，如某主机、某采集域）；时间戳接近、PID 相同（PID
  可回收）都不会触发合并或建边。
- **声明可更正**：记录可用 `retracts` 撤销旧声明（来源更正或人工更正）。
  被撤回的假设标记为 retracted，证据与撤回者仍保留在历史里。
- **人工关联是一等证据**：`add_manual_link(...)` 产生 `manual:<id>` 来源
  声明，带分析人员备注、可信值与范围，可独立撤销；也可用 retracts 参数
  同时撤回机器声明。
- **假设集**：分析人员为每个有分歧的槽位选定一条解释组成
  `HypothesisSet`；`trace(..., set_id=...)` 只沿选定假设追踪，被否决候选
  的证据仍完整保留。
- **只重算受影响路径**：`trace(..., save=True)` 保存调查路径。来源重导/
  撤销或人工关联变更后，只有支撑证据（或锚点事件）发生变化的路径被
  标记失效（`stale_paths()`），无关路径保持有效。
- **归档不可覆盖**：`Casebook` 以 append-only 方式保存 finding，冻结当时
  的证据、假设选择与路径。`reopen()` 重开当时的判断；
  `compare_with_latest()` 在不改动旧归档的前提下，与最新证据下重放同一
  选择做差异对比（新增/消失的因果跳、未决引用、所选假设是否已失效）。

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
         "direction": "incoming"}  # incoming: target -> 本事件；outgoing 反向
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

store.revoke_source("edr")      # 撤销来源，整体重放，无残留
save_snapshot(store, "case.json")
store = load_snapshot("case.json")
```

### 分歧假设与归档

```python
from investigation import Casebook

for group in store.conflict_groups():
    for hypothesis in group.hypotheses:
        hypothesis.confidence          # 该候选的可信值
        hypothesis.scopes              # 可信范围
        hypothesis.active_claims       # 仍有效的来源声明
        hypothesis.retracted_claims    # 被更正撤回的声明

store.create_hypothesis_set(
    "working", [group.hypotheses[0].hypothesis_id], activate=True)
store.trace("guid:evil-child", save=True)

link_id = store.add_manual_link(
    "guid:loader", "guid:evil-child", "parent",
    note="分析人员核对内存镜像", confidence=0.8, scopes=["ir-team"],
    retracts=[("edr", "evt-2")],       # 可选：撤回一条旧声明
)
store.retract_manual_link(link_id)      # 只影响相关路径

book = Casebook(case_id="INC-42")
finding_id = book.save_finding(store, title="初步判断")
# ... 新证据到达 / 来源更正 ...
past = book.reopen(finding_id)          # 原样重开当时的假设
diff = book.compare_with_latest(finding_id, store)
book.save("casebook.json")              # append-only，永不覆盖旧判断
```

## 文件

- `investigation/models.py`：事件、来源、边、未决引用、人工关联、假设模型
- `investigation/store.py`：导入/撤销、身份归并、冲突分组、假设集、
  按假设追踪、路径增量失效、快照序列化
- `investigation/casebook.py`：append-only 归档、历史重开、最新证据对比
- `investigation/snapshot.py`：快照读写
- `tests/test_investigation.py`：乱序、伪相似、重复导入、撤销、跨源归并、
  快照等首轮场景测试
- `tests/test_hypotheses.py`：冲突父关系/重复 PID/迟到父事件、来源更正、
  人工关联撤销、增量路径失效、归档重开与对比

## 运行测试

```sh
python3 -m pytest tests/ -q
PYTHONPATH=. python3 examples/demo.py
PYTHONPATH=. python3 examples/demo_hypotheses.py
```
