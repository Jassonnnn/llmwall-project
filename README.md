# LLM 红队安全评估平台

一个用于测试大语言模型对对抗性攻击防御能力的安全评估平台。

## 功能特性

- **对话测试模式**：单条指令的实时安全评估
- **批量评估模式**：基于数据集的批量攻击成功率测试
- **多种评估方式**：
  - 关键词匹配检测（快速）
  - LLM 裁判评估（准确）
- **支持多种模型**：远程 API（OpenRouter/OpenAI）和本地模型（Ollama）

## 项目结构

```
jb_demo/
├── main.py                      # 应用入口（7 行）
├── README.md                    # 项目说明文档
├── app/                         # 后端应用（模块化架构）
│   ├── __init__.py              # FastAPI 应用实例、CORS、静态文件配置
│   ├── config.py                # 全局配置（模型设置、数据集配置）
│   ├── models.py                # Pydantic 数据模型
│   ├── services/                # 业务逻辑层
│   │   ├── __init__.py
│   │   ├── llm.py               # LLM 调用服务
│   │   ├── evaluator.py         # 评估服务（关键词/LLM裁判）
│   │   └── dataset.py           # 数据集加载服务
│   └── routes/                  # API 路由层
│       ├── __init__.py          # 路由注册
│       ├── config.py            # 配置相关 API (/api/config)
│       ├── test.py              # 单条测试 API (/api/test_scenario)
│       └── batch.py             # 批量评估 API (/api/batch_evaluate)
├── static/                      # 前端静态资源
│   ├── css/
│   │   └── style.css            # 全局样式（121 行）
│   └── js/
│       ├── app.js               # Vue 应用主逻辑（290 行）
│       └── components/
│           └── ChatCard.js      # ChatCard 组件（34 行）
├── templates/                   # Jinja2 模板
│   └── index.html               # HTML 模板（715 行，精简后）
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

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 主页面 |
| `/api/config` | GET | 获取当前模型配置 |
| `/api/config` | POST | 更新模型配置 |
| `/api/datasets` | GET | 获取可用数据集列表与攻击分类统计 |
| `/api/test_scenario` | POST | 单条指令测试 |
| `/api/batch_evaluate` | POST | 批量评估（SSE 流式返回） |
| `/api/batch_cancel/{task_id}` | POST | 取消运行中的批量评估任务 |

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

## 攻击分类索引（离线构建）

批量评估中的“攻击分类”依赖 sidecar 索引文件（不修改原始 CSV）。

默认索引路径：
`datasets/index/attack_category_index_v2.jsonl`

兼容策略：
- 后端优先加载 `v2` 索引；
- 若 `v2` 缺失或不可用，会自动回退到 `v1` 并在前端显示告警；
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
