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
- **阶段化人工判断**：人工关联和机器引用都可带 `valid_start` /
  `valid_end`。同一对象在不同阶段可以有不同关系；时间不重叠的候选不
  冲突，局部判断不会被推广到全部历史。
- **假设集**：分析人员可保存多组完整判断组成独立 `HypothesisSet`；每组
  记录选中候选、显式排除候选及判断备注。`trace(..., set_id=...)` 只沿
  选定假设追踪，`explain_hypothesis_set(...)` 汇总路径解释了哪些事件、
  与哪些来源冲突，以及仍未解释的部分。
- **候选只增不改**：来源撤回、更正或时间调整后，原始候选关系、来源声明
  和排除依据继续保留，只把候选标记为失效/撤回；每个假设组保存后都可从
  快照独立重开。
- **只重算受影响路径**：`trace(..., save=True)` 保存调查路径。来源重导/
  撤销或人工关联变更后，只有支撑证据（或锚点事件）发生变化的路径被
  标记失效（`stale_paths()`），无关路径保持有效。
- **归档不可覆盖**：`Casebook` 以 append-only 方式保存 finding，冻结当时
  的证据、假设选择与路径。`reopen()` 重开当时的判断；
  `compare_with_latest()` 在不改动旧归档的前提下，与最新证据下重放同一
  选择做差异对比（新增/消失的因果跳、未决引用、所选假设是否已失效）。
- **计划不是事实**：`create_verification_plan(...)` 保存每轮待核查关系、
  可能结果和当时假设。`assess_plan_outcome(...)` 在私有快照中试算每种结果
  会排除/保留哪些候选、仍无法区分哪些组、路径如何变化；
  `open_plan_outcome(...)` 可基于另一种可能结果建立独立研究，主调查不被修改。
- **新材料先审后纳**：`receive_evidence(...)` 只把材料放入暂存区。
  `review_received_evidence(...)` 先返回与计划不一致、互相矛盾、共用来源和
  重复声明信息；重复确认只提示重复，不会被描述成新的独立来源。用户随后用
  `accept_evidence(..., record_ids=...)` 决定采纳范围，或 `reject_evidence(...)`。
- **撤回可追查**：`withdraw_evidence(...)` 会从当前事实图移除后来证据并重算，
  但接受、排除原因、撤回等 `evidence_decisions()` 审计记录继续保留。

## 第三轮：有限预算下的条件调查计划

- **计划随结果分支**：核查可声明 `cost`、`available_start`/`available_end`
  （可开展时段）与 `requires`（前置材料来源）；每个预设结果用
  `next_checks` 声明拿到该结果后继续哪项核查。`create_verification_plan(
  ..., budget=...)` 记录本轮预算，条件链必须无环。
- **预览不是事实**：`preview_plan(plan_id)` 在私有试算中枚举每条可发生
  路径：共同前缀的核查在每条路径内只计一次成本，互斥分支按各自路径
  展示费用；`shared_sources` 标出在多个分支重复询问的同一来源（不算
  独立证据）；`worst_case_groups` 给出最坏情况下仍无法区分的假设组，
  `over_budget_paths` 标出超预算路径。预览不改动真实调查。
- **等待与独立开始**：`plan_status(plan_id)` 区分 `startable`（现在可
  独立开始）、`waiting`（必须等待前置结果）、`invalidated`（前置材料
  被撤回或所依赖结果失效，已停止而非悄悄改道）。`spent` 与
  `remaining_budget` 实时反映已承诺成本。
- **结果如实记录**：`record_check_result(...)` 每项核查只记一次、只扣
  一次成本。实际结果不在预设范围内时记为 unexpected：支出保留、依赖
  该结果的后续核查停止，不会自动转到最接近的分支。结果所依据的批次
  被 `withdraw_evidence` 撤回后，依赖它的后续核查同样停止，已发生的
  核查记录与支出继续保留。
- **人工掌控**：`confirm_plan` 确认继续；`revise_plan` 只替换未执行的
  核查（已执行/已终止的保持原样，悬空的分支引用被剪除）；
  `terminate_plan` 终止全部或指定剩余核查，记录与支出不清零。
- **计划对比不下判词**：`compare_plans(a, b)` 并列展示各自最坏情况下
  尚不能区分的组、已用成本（committed）与未承诺成本（uncommitted），
  不凭预计排除数量判定哪个计划必然更好。
- **中途保存可恢复**：计划执行状态随快照（version 5）保存；恢复后证据
  的采纳/撤回审计仍可追溯。`open_plan_outcome(...)` 的另一种假设结果
  研究在独立副本上进行，不改变真实调查。

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
    valid_start=100.0, valid_end=200.0,
    retracts=[("edr", "evt-2")],
)
store.retract_manual_link(link_id)
store.trace("guid:evil-child", at_time=150.0, set_id="working")
store.explain_hypothesis_set("working")

book = Casebook(case_id="INC-42")
finding_id = book.save_finding(store, title="初步判断")
# ... 新证据到达 / 来源更正 ...
past = book.reopen(finding_id)          # 原样重开当时的假设
diff = book.compare_with_latest(finding_id, store)
book.save("casebook.json")              # append-only，永不覆盖旧判断
```

### 核查计划、试算与材料采纳

```python
plan = store.create_verification_plan("round-1", [{
    "check_id": "check-parent",
    "label": "核查 child 的父进程",
    "source_id": "memory-team",
    "relation": "parent",
    "target": "guid:parent-a",
    "outcomes": [
        {"outcome_id": "supports-a", "records": [...]},
        {"outcome_id": "supports-b", "records": [...]},
    ],
}], seeds=["guid:child"])

preview = store.assess_plan_outcome("round-1", "check-parent", "supports-a")
preview.excluded_hypothesis_ids
preview.retained_hypothesis_ids
preview.indistinguishable_groups
preview.retained_paths

# 另一个可能结果的独立研究；不影响当前 store
branch = store.open_plan_outcome("round-1", "check-parent", "supports-b")

batch_id = store.receive_evidence(
    "memory-team", incoming_records,
    plan_id="round-1", check_id="check-parent", outcome_id="supports-a")
review = store.review_received_evidence(batch_id)
if not review["contradictions"]:
    store.accept_evidence(batch_id, record_ids=["record-1"], reason="...")
store.withdraw_evidence(batch_id, reason="...")
store.evidence_decisions()
```

## 文件

- `investigation/models.py`：事件、来源、边、未决引用、人工关联、假设模型
- `investigation/store.py`：核查计划、结果试算、材料暂存/采纳/撤回审计，
  以及导入、假设集、追踪、路径失效和快照序列化
- `investigation/store.py`：导入/撤销、身份归并、冲突分组、假设集、
  按假设追踪、路径增量失效、快照序列化
- `investigation/casebook.py`：append-only 归档、历史重开、最新证据对比
- `investigation/snapshot.py`：快照读写
- `tests/test_investigation.py`：乱序、伪相似、重复导入、撤销、跨源归并、
  快照等首轮场景测试
- `tests/test_hypotheses.py`：冲突父关系/重复 PID/迟到父事件、来源更正、
  人工关联撤销、增量路径失效、归档重开与对比
- `tests/test_conditional_plans.py`：条件计划预览（前缀成本、互斥分支、
  共享来源）、等待/可开始/失效状态、预算与超支路径、意外结果止损、
  前置材料撤回、确认/修改/终止、计划对比、中途快照恢复、分支隔离

## 运行测试

```sh
python3 -m pytest tests/ -q
PYTHONPATH=. python3 examples/demo.py
PYTHONPATH=. python3 examples/demo_hypotheses.py
PYTHONPATH=. python3 examples/demo_conditional.py
```
