# jb_demo 项目阶段汇报（2026-03-24 ~ 2026-03-25）

## 1. 汇报摘要

本阶段围绕“可用、可信、可接入”完成了 11 次核心提交，覆盖：

- `EasyJailbreak` 真实攻击方法接入（12/12 完成）。
- 批量评估能力升级（攻击分类优先 + 固定条数评估）。
- 攻击分类索引升级到 `v2`（含质量报告、抽检样本、前端告警）。
- 第一周安全硬化（鉴权、统一错误协议、任务可取消、环境稳定性修复）。
- M2 质量治理（评估器版本化、关键词规则版本化、索引严格策略、人工复核回写工具）。
- M3 接口化推进（统一异步任务接口 + SQLite 结果持久化 + 联调通过）。

当前状态：

- 分支：`jb_demo-migration`
- 提交数（本阶段）：`11`
- 最新提交：`9299449 feat: add unified evaluation task api with sqlite persistence`
- 最新进展：`jb_demo` 虚拟环境依赖链已校准，统一接口已完成本地联调

---

## 2. 提交时间线（按时间）

1. `dddda15`（2026-03-24）
   - 主题：项目迁移与基础安全加固。

2. `4181ba4`（2026-03-24）
   - 主题：数据集攻击分类索引与批量筛选能力初版。

3. `1031697`（2026-03-24）
   - 主题：接入真实攻击方法第一批：`PAIR / TAP / GCG / AutoDAN`。

4. `606b15f`（2026-03-25）
   - 主题：接入真实攻击方法第二批：
     `Cipher / JailBroken / DeepInception / MultiLingual / CodeChameleon`。

5. `ad89dab`（2026-03-25）
   - 主题：接入真实攻击方法第三批：`GPTFuzz / ReNeLLM / ICA`。

6. `4dedd49`（2026-03-25）
   - 主题：文档更新（攻击方法现状 + 分类索引使用说明）。

7. `706f7c2`（2026-03-25）
   - 主题：批量评估流程改为“先分类再固定 N 条”。

8. `7e8cc96`（2026-03-25）
   - 主题：分类索引 v2 升级（质量检查、v1 回退、质量指标暴露）。

9. `a3eb4a2`（2026-03-25）
   - 主题：第一周硬化：
     鉴权、统一错误协议、批量任务可取消、环境稳定性修复。

10. `3ec60d0`（2026-03-25）
   - 主题：M2 质量治理：
     `llm_judge` 结构化协议、关键词规则版本化与回归校验、索引严格策略与人工复核回写。

11. `9299449`（2026-03-25）
   - 主题：M3 统一接口与联调：
     新增统一任务 API（创建/查询/分页结果/取消）、SQLite 持久化、环境依赖链校准、联调验证通过。

---

## 3. 关键成果

### 3.1 攻击方法真实性落地

- 方法总数：`17`
- 真实 EasyJailbreak 方法：`12`（全部接入真实 attacker 主链路）
- 基线模板方法：`5`（保留对照，不冒充论文算法）
- 当配置不足时返回结构化错误，不再“伪成功”。

### 3.2 批量评估能力升级

- 支持“按攻击分类评估”。
- 执行逻辑固定为：`分类过滤 -> 截取 N 条`。
- 前后端同步约束 `sample_count`，避免越界。
- 新增任务可取消能力：`POST /api/batch_cancel/{task_id}`。

### 3.3 分类索引质量升级（v2）

- 索引加载策略：默认强制 `v2`，未就绪时提示先构建。
- 可选兼容回退：设置 `ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK=true` 时允许回退 `v1`。
- 新增质量字段：`index_warning`、`index_quality`、`index_fallback_allowed`。
- 新增人工复核回写脚本：`scripts/apply_attack_category_review.py`。

### 3.4 评估器与规则版本化（M2 新增）

- `llm_judge` 升级为结构化 JSON 协议（含协议版本号）。
- 关键词评估升级为版本化规则：`keyword_v1_20260325`。
- 单条评估结果新增 `evaluator_version` 字段，便于审计溯源。
- 新增回归脚本：`scripts/check_keyword_regression.py`（配套测试集 `keyword_regression_cases_v1.json`）。

### 3.5 第一周安全与稳定性硬化

- 关键接口鉴权（Bearer Token，支持本地回环放行）。
- 统一错误响应：`status/code/message/details`。
- 批量评估任务化：`task_id`、并发上限、取消状态。
- 环境稳定性修复：
  - 启动改为 `python -m uvicorn`
  - 强制建议 `PYTHONNOUSERSITE=1`
  - 增加 `requirements.lock.txt` 与 `scripts/doctor_env.py`

### 3.6 统一任务接口（M3 已落地）

- 新增统一任务入口：`POST /api/evaluations`
- 新增任务状态查询：`GET /api/evaluations/{task_id}`
- 新增分页结果查询：`GET /api/evaluations/{task_id}/results`
- 新增统一取消接口：`POST /api/evaluations/{task_id}/cancel`
- 任务与结果持久化到 SQLite：默认 `runtime/evaluation_tasks.db`
- 支持 `red_team` 与 `guardrail` 双 phase 结果分离，便于前端统一呈现

### 3.7 联调与环境校准结果

- `jb_demo` 环境执行 `requirements.lock.txt` 校准后，无版本冲突。
- `scripts/doctor_env.py` 检查通过（`PYTHONNOUSERSITE=1`，依赖版本来自 `/data/ljc/jb_demo`）。
- 新接口联调通过：
  - `POST /api/evaluations` 创建任务
  - `GET /api/evaluations/{task_id}` 查询状态
  - `GET /api/evaluations/{task_id}/results` 分页取结果
  - `POST /api/evaluations/{task_id}/cancel` 取消任务
- 兼容回归通过：`/api/batch_evaluate` SSE 仍可正常返回 `init/progress` 事件

---

## 4. 对外接口变化（汇报重点）

- 新增接口：`POST /api/batch_cancel/{task_id}`。
- `POST /api/batch_evaluate`：返回 `task_id`（header + SSE init event）。
- `POST /api/evaluations`：创建统一异步任务（红队 + 可选护栏）。
- `GET /api/evaluations/{task_id}`：查询任务生命周期状态。
- `GET /api/evaluations/{task_id}/results`：分页获取评估结果。
- `POST /api/evaluations/{task_id}/cancel`：取消统一评估任务。
- 关键接口已受鉴权保护（config/test/attack/batch）。
- 错误协议统一，便于外部前端和网关稳定接入。
- `/api/datasets` 增加索引治理信号：`index_fallback_allowed`。

---

## 5. 里程碑完成度（对照 `OPTIMIZATION_PLAN.md`）

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1（安全与可用性兜底） | 已完成（主要项） | 鉴权、统一错误协议、批量任务取消、并发控制、环境锁定已落地。 |
| M2（评估可信度提升） | 已完成（能力项） | `llm_judge` JSON 协议、关键词版本化、`v2` 严格索引、人工复核回写已落地。 |
| M3（统一接口与任务化） | 已完成 | 统一异步任务 API + SQLite 持久化 + 联调通过。 |
| M4（工程化与交付） | 未完成 | 自动化测试、CI、部署文档、运行手册、回滚手册待补齐。 |

## 6. 后续优化清单（仅 `jb_demo`）

1. 增补 `tests/` 与接口契约测试（任务生命周期、分页结果、`llm_judge` 协议）。
2. 接入 CI（lint + test + build checks），并设置失败阻断合并。
3. 输出部署与回滚文档（含 `.env.example`，可选 Docker/Compose）。
4. 强化可靠性（重试/退避/熔断、细粒度限流与配额策略）。
5. 补齐报告能力（CSV/JSON/Markdown 导出与基线对比）。

---

## 7. 一句话结论（可直接口头汇报）

`jb_demo` 已从“可演示原型”推进到“可接入、可追溯”的阶段，M1/M2/M3 已落地，但距离工程化完备仍需完成 M4（测试、CI、部署与回滚交付）。

---

## 8. 文档一致性更新（2026-03-26）

- 已完成 README / 数据集说明 / 代理指引文档的一致性修订。
- 修正了索引策略描述、运行环境说明、接口总表与阶段完成度映射。
- 本节为文档维护记录，不计入上文“11 次核心功能提交”统计口径。
