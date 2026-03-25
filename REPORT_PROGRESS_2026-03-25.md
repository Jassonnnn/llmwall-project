# jb_demo 项目阶段汇报（2026-03-24 ~ 2026-03-25）

## 1. 汇报摘要

本阶段围绕“可用、可信、可接入”完成了 10 次核心提交，覆盖：

- `EasyJailbreak` 真实攻击方法接入（12/12 完成）。
- 批量评估能力升级（攻击分类优先 + 固定条数评估）。
- 攻击分类索引升级到 `v2`（含质量报告、抽检样本、前端告警）。
- 第一周安全硬化（鉴权、统一错误协议、任务可取消、环境稳定性修复）。
- M2 质量治理（评估器版本化、关键词规则版本化、索引严格策略、人工复核回写工具）。

当前状态：

- 分支：`jb_demo-migration`
- 提交数（本阶段）：`10`
- 最新提交：`（本次提交：M2 质量治理）`

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

10. `（本次提交）`（2026-03-25）
   - 主题：M2 质量治理：
     `llm_judge` 结构化协议、关键词规则版本化与回归校验、索引严格策略与人工复核回写。

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

---

## 4. 对外接口变化（汇报重点）

- 新增接口：`POST /api/batch_cancel/{task_id}`。
- `POST /api/batch_evaluate`：返回 `task_id`（header + SSE init event）。
- 关键接口已受鉴权保护（config/test/attack/batch）。
- 错误协议统一，便于外部前端和网关稳定接入。
- `/api/datasets` 增加索引治理信号：`index_fallback_allowed`。

---

## 5. 当前风险与待办

1. 目前本地提交已领先远端，需统一 push 节奏。
2. `SwordHolder` 侧已做对接改动但尚未统一收口提交。
3. 建议下阶段：
   - 完成 `SwordHolder -> jb_demo` 端到端联调并提交。
   - 增补评估协议契约测试（含 `llm_judge` JSON 协议校验）。
   - 引入人工复核抽检闭环（抽样 -> 回写 -> 重建质量报告）。

---

## 6. 一句话结论（可直接口头汇报）

`jb_demo` 已从“可演示原型”进一步推进到“可接入、可控风险、可审计溯源”的阶段，真实攻击能力与分类评估能力成型，M2 已完成治理基础设施，下一步重点是联调与回归收口。
