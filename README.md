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

## 第三轮：假设组路径对比、时间范围判断、独立重开

- **整路径对比假设组**：`compare_set_paths(seed, [set-a, set-b])` 从同一
  锚点分别沿每组假设走完整条传播路径，给出各组共有与独有的因果跳，
  而不是只比较一个父子槽位。`explain_set(set_id)` 报告该组解释了哪些
  事件、与哪些来源冲突（被否决候选的来源），以及仍无法解释的部分
  （未决引用、组内未做选择的争议槽位）。
- **带时间范围的人工判断**：`add_manual_link(..., valid_from=, valid_to=)`
  把判断限定在时间窗内；`trace(..., at=t)` 只采纳在 t 时刻有效的判断，
  同一对象在不同阶段可以有不同关系。事件时间戳落在窗口外时判断保持
  不激活（`manual_link_status()`），绝不把局部决定推广到全部历史。
  `adjust_manual_link_window()` 调整窗口后，只有受影响的路径被标记失效。
- **假设组独立重开**：`save_group(set_id, reasons=...)` 把一组假设连同
  所有被排除的候选及排除依据一并冻结（append-only，永不删除）；
  `reopen_group()` 原样查看归档，`activate_saved_group()` 从归档独立
  重建工作集，不影响现有假设集与其他调查记录。

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

### 假设组对比与时间范围判断

```python
store.create_hypothesis_set("theory-a", [hyp_a])
store.create_hypothesis_set("theory-b", [hyp_b])

cmp = store.compare_set_paths("guid:child", ["theory-a", "theory-b"])
cmp.shared_hops                 # 各组共有的因果跳
cmp.unique_hops["theory-a"]     # 仅在该组路径上出现的跳

report = store.explain_set("theory-a")
report.explained_events         # 该组解释到的事件（整条路径）
report.conflicting_sources      # 被否决候选背后的来源
report.unresolved_refs          # 仍无法解释的未决引用

link_id = store.add_manual_link(
    "guid:a", "guid:b", "controls",
    valid_from=0.0, valid_to=100.0)   # 只在阶段内有效
store.trace("guid:b", at=50.0)        # t=50 看到 controls
store.trace("guid:b", at=500.0)       # t=500 不适用该判断
store.adjust_manual_link_window(link_id, 0.0, 1000.0)  # 只失效相关路径

gid = store.save_group("theory-a",
                       reasons={hyp_b: "edr-b trust too low"})
group = store.reopen_group(gid)       # 候选与排除依据原样保留
store.activate_saved_group(gid, activate=True)  # 独立重开为新工作集
```

## 文件

- `investigation/models.py`：事件、来源、边、未决引用、人工关联、假设模型
- `investigation/store.py`：导入/撤销、身份归并、冲突分组、假设集、
  按假设追踪、假设组路径对比与解释报告、时间窗人工判断、
  路径增量失效、假设组归档、快照序列化
- `investigation/casebook.py`：append-only 归档、历史重开、最新证据对比
- `investigation/snapshot.py`：快照读写
- `tests/test_investigation.py`：乱序、伪相似、重复导入、撤销、跨源归并、
  快照等首轮场景测试
- `tests/test_hypotheses.py`：冲突父关系/重复 PID/迟到父事件、来源更正、
  人工关联撤销、增量路径失效、归档重开与对比
- `tests/test_groups.py`：假设组整路径对比、解释报告、时间窗判断、
  窗口调整的增量失效、假设组独立重开与快照往返

## 运行测试

```sh
python3 -m pytest tests/ -q
PYTHONPATH=. python3 examples/demo.py
PYTHONPATH=. python3 examples/demo_hypotheses.py
PYTHONPATH=. python3 examples/demo_groups.py
```
