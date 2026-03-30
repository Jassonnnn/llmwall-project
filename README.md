# LLM 红队安全评估平台

一个用于测试大语言模型对对抗性攻击防御能力的安全评估平台。

## 功能特性

- **对话测试模式**：单条指令的实时安全评估
- **批量评估模式**：基于数据集的批量攻击成功率测试
- **按攻击分类评估**：支持“混合全部 / 角色扮演 / 编码混淆 / 上下文注入 / 多语言绕过 / 组合攻击”等分类筛选
- **多攻击方法横评**：同一批种子样本可一次性对比多种攻击方法，并输出方法级聚合指标
- **多种评估方式**：
  - 关键词匹配检测（快速）
  - LLM 裁判评估（准确）
- **支持多种模型**：远程 API（OpenRouter/OpenAI）和本地模型（Ollama）
- **任务化与报告导出**：统一异步任务、SQLite 持久化、`json/csv/markdown` 报告导出

## 文档导航

- `DOCS_INDEX.md`：文档入口与维护规则
- `SAFETYDASH_ADAPTER.md`：safetydash 前端适配说明（JWT + redteam 聚合接口）
- `README.md`：功能与使用总览（本文件）
- `REPORT_PROGRESS_2026-03-25.md`：阶段性成果与提交时间线
- `OPTIMIZATION_PLAN.md`：里程碑规划与后续优化路线
- `datasets/README.md`：数据集与分类索引说明
- `AGENTS.md` / `CLAUDE.md`：面向代码代理的工程约束与开发约定

## 当前完成度（对照 `OPTIMIZATION_PLAN.md`）

当前结论：`jb_demo` 已具备内部联调、真实攻击回归与试运行能力，但还不是“工程化完备”状态。

- `M1`（安全与可用性兜底）：已完成主要项（鉴权、错误协议、任务取消、并发控制、环境锁定）。
- `M2`（评估可信度）：已完成主要项（`llm_judge` 结构化协议、关键词版本化、`v2` 索引、人工复核回写）。
- `M3`（统一接口与任务化）：已完成（统一异步任务 API + SQLite 持久化）。
- `M4`（工程化与交付）：部分完成（已补核心评估测试，CI、部署/回滚手册待补齐）。

### 最近验证结果（`2026-03-30`）

- 12 个真实攻击方法已完成一次性全量回归，并全部返回成功：
  - `PAIR`、`TAP`、`GPTFuzz`、`ReNeLLM`、`ICA`
  - `Cipher`、`JailBroken`、`DeepInception`、`MultiLingual`、`CodeChameleon`
  - `GCG`、`AutoDAN`
- `python -m compileall app EasyJailbreak/easyjailbreak` 通过。
- `pytest -q tests/test_evaluation_tasks.py` 通过，结果为 `2 passed`。
- 已清理 FastAPI `startup` 弃用告警，并收敛白盒模型生成参数 warning。
- 白盒方法默认优先选择更轻量本地模型，并按当前 GPU 空闲显存动态选择运行设备，以降低 `GCG/AutoDAN` 的 OOM 风险。

仍需优化的重点：

1. CI 与自动化回归（已补 `tests/test_evaluation_tasks.py`，但 GitHub Actions 与更完整回归集仍待建设）。
2. 部署/运行/回滚文档与一键化部署（Docker/Compose、`.env.example`）。
3. 可靠性增强（重试/退避/熔断、细粒度限流与配额）。
4. 密钥治理增强（从“前端输入”进一步收敛到服务端密钥托管方案）。
5. 基线对比与结果看板能力（导出链路已具备，但跨版本基线回归与可视化看板仍待补齐）。

## 项目结构

```
jb_demo/
├── main.py                      # 应用入口（轻量启动）
├── README.md                    # 项目说明文档
├── app/                         # 后端应用（模块化架构）
│   ├── __init__.py              # FastAPI 应用实例、CORS、异常处理、lifespan 初始化
│   ├── auth.py                  # 服务鉴权（Bearer Token + 本地回环放行）
│   ├── config.py                # 全局配置（模型设置、数据集配置）
│   ├── errors.py                # 统一错误结构
│   ├── models.py                # Pydantic 数据模型
│   ├── services/                # 业务逻辑层
│   │   ├── __init__.py
│   │   ├── llm.py               # LLM 调用服务
│   │   ├── evaluator.py         # 评估服务（关键词/LLM裁判）
│   │   ├── keyword_rules.py     # 关键词规则版本化
│   │   ├── dataset.py           # 数据集加载与分类索引管理
│   │   ├── attack_generator.py  # 攻击方法生成与真实 attacker 接入
│   │   └── evaluation_tasks.py  # 统一任务编排与 SQLite 持久化
│   └── routes/                  # API 路由层
│       ├── __init__.py          # 路由注册
│       ├── config.py            # 配置相关 API (/api/config)
│       ├── test.py              # 单条测试 API (/api/test_scenario)
│       ├── batch.py             # 批量评估 API (/api/batch_evaluate)
│       ├── attack.py            # 攻击生成/评估 API
│       └── evaluations.py       # 统一异步任务 API
├── static/                      # 前端静态资源
│   ├── css/
│   │   └── style.css            # 全局样式
│   └── js/
│       ├── app.js               # Vue 应用主逻辑
│       └── components/          # 前端组件
├── templates/                   # Jinja2 模板
│   └── index.html               # 前端主页面模板
├── scripts/                     # 索引构建/质量回归/环境诊断脚本
├── tests/
│   └── test_evaluation_tasks.py # 统一评估任务的迁移/聚合/导出测试
├── runtime/                     # 运行时目录（SQLite、临时产物）
└── datasets/                    # 红队测试数据集
    ├── HarmBench/               # HarmBench 数据集
    ├── llm-attacks/             # AdvBench 数据集
    ├── toxicchat/               # ToxicChat 数据集
    └── saferlhf/                # SafeRLHF 数据集
```

### 架构说明

**后端（FastAPI）**：
- 采用模块化架构，分离配置、模型、服务和路由
- `app/services/` 包含所有业务逻辑
- `app/routes/` 包含所有 API 端点处理

**前端（Vue 3）**：
- 采用组件化架构，分离 HTML、CSS 和 JavaScript
- `static/css/` 包含所有样式文件
- `static/js/` 包含 Vue 应用和组件
- 使用 `[[` `]]` 作为 Vue 分隔符（避免与 Jinja2 冲突）

## 快速开始

### 1. 激活虚拟环境

```bash
conda activate jb_demo
```

### 2. 进入项目目录

```bash
cd /data/ljc/jb_demo
```

可选：用锁定依赖修正运行环境

```bash
PYTHONNOUSERSITE=1 python -m pip install -r requirements.lock.txt
```

### 3. 启动服务

```bash
# 开发模式（支持热重载）
PYTHONNOUSERSITE=1 python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 或者直接运行
python main.py
```

### 4. 访问 Web 界面

打开浏览器访问：`http://localhost:8000`

## API 端点

| 端点 | 方法 | 说明 | 鉴权 |
|------|------|------|------|
| `/` | GET | 主页面 | 否 |
| `/api/config` | GET | 获取当前模型配置 | 是 |
| `/api/config` | POST | 更新模型配置 | 是 |
| `/api/datasets` | GET | 获取可用数据集列表与攻击分类统计 | 否 |
| `/api/test_scenario` | POST | 单条指令测试 | 是 |
| `/api/batch_evaluate` | POST | 批量评估（SSE 流式返回） | 是 |
| `/api/batch_cancel/{task_id}` | POST | 取消运行中的批量评估任务 | 是 |
| `/api/attack_methods` | GET | 获取攻击方法列表与依赖状态 | 否 |
| `/api/generate_attacks` | POST | 生成对抗攻击提示词 | 是 |
| `/api/attack_and_evaluate` | POST | 生成攻击后立即评估 | 是 |
| `/api/batch_generate_attacks` | POST | 批量生成攻击提示词 | 是 |
| `/api/evaluations` | POST | 创建统一异步评估任务（红队 + 可选护栏） | 是 |
| `/api/evaluations/{task_id}` | GET | 查询统一评估任务状态与进度 | 是 |
| `/api/evaluations/{task_id}/results` | GET | 分页获取统一评估任务结果 | 是 |
| `/api/evaluations/{task_id}/export` | GET | 导出任务结果（`json/csv/markdown`） | 是 |
| `/api/evaluations/{task_id}/cancel` | POST | 取消统一评估任务 | 是 |
| `/api/auth/login` | POST | safetydash 兼容登录（JWT） | 否 |
| `/api/auth/me` | GET | safetydash 兼容当前用户信息 | JWT |
| `/api/redteam/overview` | GET | safetydash 红队页聚合数据 | JWT |

## 使用说明

### 对话测试模式

1. 在设置中配置 API Key（点击右上角 ⚙️ 按钮）
2. 选择目标模型（远程 API / 本地模型）
3. 选择评估方式（关键词 / LLM 裁判）
4. 输入测试指令，点击发送

### 批量评估模式

1. 切换到"批量评估"标签页
2. 选择测试数据集
3. 选择攻击分类（角色扮演 / 编码混淆 / 上下文注入等，或“混合全部”）
4. 设置固定测试条数 `N`（在当前分类内取前 `N` 条）
5. 选择目标模型和评估方式
6. 点击"开始评估"，实时查看进度

说明：
- 执行顺序为：先按攻击分类过滤，再按 `N` 截取。
- 若 `N` 大于该分类可用条数，会自动按该分类全部可用条数评测。
- 默认要求使用 `v2` 分类索引；如需临时回退 `v1`，设置 `ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK=true`。

## 统一任务接口（M3）

统一任务接口用于外部前端/网关集成，推荐流程：

1. `POST /api/evaluations` 创建任务
2. `GET /api/evaluations/{task_id}` 轮询状态
3. `GET /api/evaluations/{task_id}/results?offset=0&limit=50` 分页拉取结果
4. `GET /api/evaluations/{task_id}/export?format=json|csv|markdown` 导出报告
5. `POST /api/evaluations/{task_id}/cancel` 取消任务

创建任务示例：

```bash
curl -X POST http://localhost:8000/api/evaluations \
  -H "Authorization: Bearer $JB_DEMO_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_id": "harmbench_text_test",
    "attack_category": "roleplay_persona",
    "sample_count": 20,
    "target": "api",
    "evaluator": "llm_judge",
    "attack_methods": ["PAIR", "TAP"],
    "generated_prompt_count_per_seed": 2,
    "include_guardrail": true,
    "guardrail_target": "local",
    "guardrail_evaluator": "keyword"
  }'
```

说明：
- 不传 `attack_methods` 时，保持兼容旧行为：直接拿数据集原始提示词评估，结果中的 `attack_method` 会标记为 `direct_prompt`。
- 传入 `attack_methods` 后，会在同一批种子样本上对每种方法分别生成攻击提示词，并返回方法级/分类级聚合结果。
- `generated_prompt_count_per_seed` 控制每个种子样本、每种攻击方法生成多少条攻击提示词，默认 `1`，上限 `10`。
- `include_guardrail=true` 时，会额外执行护栏评估链路。
- 结果里的 `phase` 用于区分 `red_team` 和 `guardrail`。
- 结果明细会额外带上 `seed_prompt`、`source_attack_category`、`attack_method`、`generation_mode`，便于复盘和横向对比。
- 任务详情会返回 `summary_metrics`、`by_attack_method`、`by_attack_category`，可直接给前端做排行榜或分组对比。
- 任务与结果会持久化到 SQLite（默认：`runtime/evaluation_tasks.db`）。

联调自检（本地）：

```bash
# 1) 启动服务（建议固定环境）
conda activate jb_demo
export PYTHONNOUSERSITE=1
python -m uvicorn main:app --host 127.0.0.1 --port 18000
```

```bash
# 2) 创建任务
curl -X POST http://127.0.0.1:18000/api/evaluations \
  -H "Authorization: Bearer $JB_DEMO_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_id": "harmbench_text_test",
    "attack_category": "mixed_all",
    "sample_count": 2,
    "target": "api",
    "evaluator": "keyword",
    "include_guardrail": false
  }'
```

```bash
# 3) 查询状态与结果（替换 <task_id>）
curl http://127.0.0.1:18000/api/evaluations/<task_id>
curl 'http://127.0.0.1:18000/api/evaluations/<task_id>/results?offset=0&limit=10'
curl -OJ 'http://127.0.0.1:18000/api/evaluations/<task_id>/export?format=markdown'
curl -X POST http://127.0.0.1:18000/api/evaluations/<task_id>/cancel
```

返回结果补充字段：

- `summary_metrics`：红队主链路的总体攻击成功率、拒答率、错误率、平均时延、攻击方法数、攻击分类数。
- `by_attack_method`：按攻击方法聚合后的样本数、成功率、拒答率、错误率、平均时延与 `rank`。
- `by_attack_category`：按攻击分类聚合后的样本数、成功率、拒答率、错误率、平均时延与 `rank`。
- `results[*].attack_method / generation_mode / source_attack_category / seed_prompt`：用于前端详情页、导出报表和人工复核。

## SafetyDash 适配接口（MVP）

为支持 `safetydash` 前端无代码改动接入，`jb_demo` 新增兼容接口：

1. `POST /api/auth/login`
2. `GET /api/auth/me`
3. `GET /api/redteam/overview`

鉴权说明：
- 兼容接口使用 JWT Bearer（与 `safetydash` 现有前端一致）。
- 原有 `jb_demo` 关键接口继续沿用服务令牌鉴权（`JB_DEMO_SERVICE_TOKEN`），互不影响。

环境变量（兼容接口）：

```bash
export JB_DEMO_JWT_SECRET=change-me
export JB_DEMO_JWT_ALG=HS256
export JB_DEMO_ACCESS_TOKEN_EXPIRE_MINUTES=60
export JB_DEMO_SEED_USERNAME=admin
export JB_DEMO_SEED_PASSWORD=admin
```

联调步骤（safetydash 前端）：

```bash
# safetydash frontend .env
VITE_USE_MOCK=false
VITE_API_BASE_URL=http://127.0.0.1:8000
```

跨域（如前后端分端口）：

```bash
export APP_CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

## 攻击分类索引（离线构建）

批量评估中的“攻击分类”依赖 sidecar 索引文件（不修改原始 CSV）。

默认索引路径：
`datasets/index/attack_category_index_v2.jsonl`

兼容策略：
- 默认强制使用 `v2` 索引；
- 仅当显式设置 `ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK=true` 时，才允许回退 `v1`；
- 建议定期重建 `v2` 以获得更高分类质量。

构建命令示例：

```bash
conda run -n jb_demo python scripts/build_attack_category_index.py \
  --api-key <YOUR_API_KEY> \
  --model gpt-5.4 \
  --reasoning-effort xhigh \
  --max-concurrency 8 \
  --confidence-threshold 0.72
```

调试少量样本：

```bash
conda run -n jb_demo python scripts/build_attack_category_index.py \
  --dataset-id harmbench_text_test \
  --limit 20 \
  --api-key <YOUR_API_KEY>
```

可选参数（常用）：
- `--disable-review`：关闭低置信度/规则冲突样本的二次复核。
- `--quality-report-output <path>`：指定质量报告 JSON 输出路径。
- `--audit-sample-per-category <N>`：每个分类抽检样本数（默认 `20`）。
- `--audit-sample-seed <seed>`：抽检采样随机种子。

构建产物：
- `datasets/index/attack_category_index_v2.jsonl`：分类索引主文件。
- `datasets/index/attack_category_quality_report_v2.json`：分类质量汇总（覆盖率、冲突率、低置信度比例等）。
- `datasets/index/attack_category_audit_samples_v2.jsonl`：分层抽检样本，便于人工复核。

人工复核回写（M2）：

```bash
conda run -n jb_demo python scripts/apply_attack_category_review.py \
  --review-file /path/to/review_result.jsonl
```

`review_file` 每行 JSON 至少包含：
- `dataset_id`
- `row_id`
- `attack_category`（必须是有效分类）
- 可选：`review_note`、`reviewed_by`、`reviewed_at`

## 真实攻击方法（已接入）

- `PAIR`、`TAP`
- `GPTFuzz`、`ReNeLLM`、`ICA`
- `Cipher`、`JailBroken`、`DeepInception`、`MultiLingual`、`CodeChameleon`
- `GCG`、`AutoDAN`（依赖本地白盒模型）

## 攻击方法现状（2026-03）

- 总方法数：`17`
- EasyJailbreak 方法：`12`（全部接入真实 attacker 主流程）
- Baseline 模板方法：`5`（用于对照，不属于论文算法复现）

Baseline 模板方法列表：
- `basic_jailbreak`
- `encoding`
- `translation`
- `roleplay`
- `hypothetical`

说明：
- 所有 EasyJailbreak 方法都会优先走真实链路。
- 配置不满足时返回结构化错误（例如 `MISSING_ATTACK_MODEL_CONFIG`、`MISSING_WHITEBOX_MODEL_CONFIG`），不会静默伪装成“模拟成功”。
- 生成结果会返回 `generation_mode`：`real_attacker` / `mutation` / `simulated` / `local_template`。

回归测试：

```bash
conda run -n jb_demo python -m pytest -q tests/test_evaluation_tasks.py
```

白盒模型最小配置（用于 `GCG` / `AutoDAN`）：

```bash
export EASYJAILBREAK_WHITEBOX_MODEL_PATH=/path/to/your/hf-model
export EASYJAILBREAK_WHITEBOX_TOKENIZER_PATH=/path/to/your/hf-tokenizer   # 可选
export EASYJAILBREAK_WHITEBOX_MODEL_NAME=llama2
```

常用可调参数（可选）：

```bash
# PAIR
export EASYJAILBREAK_PAIR_STREAMS=1
export EASYJAILBREAK_PAIR_ITERATIONS=2

# TAP
export EASYJAILBREAK_TAP_TREE_WIDTH=4
export EASYJAILBREAK_TAP_TREE_DEPTH=2

# GPTFuzz / ReNeLLM / ICA
export EASYJAILBREAK_GPTFUZZ_ENERGY=1
export EASYJAILBREAK_RENELLM_EVO_MAX=3
export EASYJAILBREAK_ICA_PROMPT_NUM=5

# GCG / AutoDAN
export EASYJAILBREAK_GCG_MAX_ITER=30
export EASYJAILBREAK_AUTODAN_NUM_STEPS=12
```

AutoDAN 还需要 NLTK 资源：

```bash
python -m nltk.downloader punkt stopwords wordnet
```

## 依赖项

- fastapi
- uvicorn
- litellm
- pandas
- jinja2
- pydantic

## 注意事项

- 首次使用需要在设置中配置 API Key
- 本地模型需要先启动 Ollama 服务
- 批量评估会消耗大量 API 调用，请注意配额

## 环境一致性（防串包）

如果机器上有多个 Python/uvicorn，建议固定以下启动方式，避免误用 `~/.local` 里的旧版本：

```bash
conda activate jb_demo
export PYTHONNOUSERSITE=1
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

快速自检：

```bash
which python
python -m uvicorn --version
python -c "import litellm, openai; print(litellm.__version__, openai.__version__)"
python scripts/doctor_env.py
```

## 服务鉴权与任务控制（Week-1）

默认开启关键接口鉴权（`/api/config`、`/api/test_scenario`、攻击生成、批量评估/取消）：

```bash
export JB_DEMO_SERVICE_TOKEN=your_service_token
export JB_DEMO_REQUIRE_AUTH=true
export JB_DEMO_ALLOW_LOCAL_BYPASS=true
export JB_DEMO_MAX_CONCURRENT_BATCH_TASKS=1
export JB_DEMO_EVAL_DB_PATH=/data/ljc/jb_demo/runtime/evaluation_tasks.db
export JB_DEMO_EVAL_RESULTS_PAGE_LIMIT=200
```

说明：
- 生产环境建议 `JB_DEMO_ALLOW_LOCAL_BYPASS=false`。
- `batch_evaluate` 响应头会返回 `X-Batch-Task-Id`，SSE `init` 事件也会携带 `task_id`。
- 可通过 `POST /api/batch_cancel/{task_id}` 发起取消请求。

## 评估质量（M2）

LLM 裁判协议已升级为结构化 JSON 判题（`llm_judge_json_v1_20260325`），降低文本解析误判。

关键词评估规则已版本化（`keyword_v1_20260325`），并提供回归样本与检查脚本：

```bash
conda run -n jb_demo python scripts/check_keyword_regression.py
```
