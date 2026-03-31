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

## 5. 里程碑完成度（对照 `../plans/OPTIMIZATION_PLAN.md`）

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

---

## 9. safetydash 适配增量（2026-03-26）

- 新增 JWT 兼容鉴权接口：
  - `POST /api/auth/login`
  - `GET /api/auth/me`
- 新增红队聚合兼容接口：
  - `GET /api/redteam/overview`
- 该接口将 `jb_demo` 的数据集、任务状态、结果统计映射为 `safetydash` 前端 `RedteamOverview` 结构。
- 补充适配说明文档：`../integration/SAFETYDASH_ADAPTER.md`（字段映射、状态映射、联调步骤、环境变量）。

---

## 10. 真实攻击链稳定性收尾（2026-03-30）

### 10.1 本轮目标

- 不再停留在“方法已经接入”，而是要求真实攻击链能稳定执行。
- 重点收口 `PAIR`、`TAP`、`GCG`、`AutoDAN` 四个最容易失败的方法。
- 清理运行时非阻塞 warning，降低联调和演示时的噪声。

### 10.2 本轮核心修复

- `PAIR`：
  - 修复真实攻击生成链在当前模型供应链上的不稳定问题。
  - 收敛为可稳定返回真实 adversarial prompt 的执行路径，不再退化成原始 seed prompt。
- `TAP`：
  - 修复空分支与剪枝阶段的越界问题。
  - 收敛为可稳定执行的真实树式攻击生成路径。
- `GCG`：
  - 修复白盒模型模板别名兼容问题（如 `llama2` / `llama-2`）。
  - 调整默认白盒参数，避免不必要的高开销与失败。
- `AutoDAN`：
  - 修复 `NLTK` 资源识别与降级逻辑。
  - 调整默认批量大小、步数与设备选择，提升真实执行稳定性。
- 白盒模型稳定性：
  - 默认优先选择更轻量的本地白盒模型候选，降低 `GCG/AutoDAN` 的显存压力。
  - 按当前 GPU 空闲显存动态选择运行设备，避免默认落到拥挤显卡导致 OOM。
- OpenAI 兼容链：
  - 修复 OpenAI message list 直传兼容问题，减少上游 `502` / timeout 对真实攻击流程的影响。

### 10.3 运行时清理

- FastAPI：
  - 用 `lifespan` 替换旧的 `@app.on_event("startup")`，消除弃用警告。
- Transformers：
  - 合并白盒模型生成参数，避免同时传 `generation_config` 与显式生成参数导致的 warning。
  - 清理 AutoDAN 自定义 `generate()` 中 `max_new_tokens/max_length` 与 `pad_token_id` 的重复设置告警。
  - 修复 `zero_shot` 对话模板兼容问题与 `bfloat16` 分数转 `numpy` 的类型报错。

### 10.4 验证结果

- 12 个真实攻击方法已全部返回成功：
  - `PAIR`
  - `TAP`
  - `GPTFuzz`
  - `ReNeLLM`
  - `ICA`
  - `Cipher`
  - `JailBroken`
  - `DeepInception`
  - `MultiLingual`
  - `CodeChameleon`
  - `GCG`
  - `AutoDAN`
- `compileall` 通过：
  - `python -m compileall app EasyJailbreak/easyjailbreak`
- 后端测试通过：
  - `pytest -q tests/test_evaluation_tasks.py`
  - 结果：`2 passed`

### 10.5 本轮汇报结论

`jb_demo` 当前不只是“接了很多真实攻击方法”，而是已经完成了一轮真实攻击链稳定性收口。  
也就是说，项目现在具备了“真实方法能跑、结果可验证、运行噪声更低”的状态，更适合做组会汇报、联调演示和下一步工程化整理。

---

## 11. safetydash 红队前端闭环接入（2026-03-31）

### 11.1 本轮目标

- 不再只让 `safetydash` 展示红队概览，而是让它真正能发起红队测试。
- 把红队页补成完整三类能力：
  - 单条测试（`api/local × keyword/llm_judge`）
  - 数据集批量评估任务
  - 独立攻击方法实验室
- 保持 `jb_demo` 仍然是后端主体，`safetydash` 通过 `dashboard-api` 做 BFF 接入，不把两个项目代码硬耦合在一起。

### 11.2 本轮实现

- `dashboard-api` 新增红队代理接口：
  - `POST /api/redteam/single-test/matrix`
  - `POST /api/redteam/attack-lab/generate`
  - `POST /api/redteam/attack-lab/run`
- 红队页前端补齐两块之前缺失的能力：
  - 单条 `2x2` 测试卡片
  - 攻击方法实验室卡片
- 为本地联调和演示补充了两个操作脚本：
  - `start_safetydash_stack.sh`
  - `stop_safetydash_stack.sh`
  - 可一键拉起 / 停止 `jb_demo + dashboard-api + safetydash frontend`
- 这样前端现在已经具备三种真实红队能力：
  - 单条 prompt 测试
  - 数据集批量任务创建/查询/分页结果/取消/导出
  - 独立攻击方法生成与即时评估
- 白盒方法治理同步补上：
  - 对 `GCG / AutoDAN` 这类白盒方法，前端显示明确提示
  - 当前端目标不是 `local` 时直接拦截，避免用户把白盒方法误投到 API 目标
- 单条矩阵接口增加了“局部失败不拖垮整体”的容错：
  - 即使 `api` 目标因为没配 Key 失败，`local` 两格仍然正常返回
  - 前端可以完整展示四格状态，而不是整个接口直接报错

### 11.3 联调验证结果

- 后端测试通过：
  - `pytest -q tests/test_auth.py tests/test_redteam.py`
  - 结果：`12 passed`
- 后端静态编译检查通过：
  - `python -m compileall app`
- 前端构建通过：
  - `npm run build`
- 真实 smoke test 已通过：
  - `dashboard-api` 登录成功
  - `single-test/matrix` 能返回 4 格结构化结果
  - `attack-lab/generate` 能生成真实攻击提示词
  - `attack-lab/run` 能完成“生成 + 评估”闭环
- 其中在未配置远程 API Key 的情况下：
  - `api` 目标会返回结构化错误
  - `local` 目标仍然可以正常执行并展示结果

### 11.4 本轮汇报结论

这次改动意味着 `safetydash` 不再只是看板式前端，而是已经可以作为 `jb_demo` 的真实红队前端使用。  
也就是说，现在可以从前端直接完成单条测试、数据集批量评估、攻击方法独立测试，并拿到结构化结果、任务状态和导出内容，项目的对外接入完整度明显提升。
