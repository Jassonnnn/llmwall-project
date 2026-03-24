# AGENTS.md

Guidelines for AI agents working in this LLM Red Team Security Evaluation Platform repository.

## Project Overview

This is a **FastAPI + Vue 3** web application for evaluating LLM security against adversarial attacks (red teaming). Supports both single-prompt testing and batch evaluation against security datasets.

**Key Technologies:**
- Backend: FastAPI, Pydantic, litellm (LLM abstraction)
- Frontend: Vue 3, Tailwind CSS (via CDN)
- Datasets: HarmBench, AdvBench, ToxicChat, SafeRLHF

## Build & Run Commands

### Development
```bash
# Start dev server with hot reload (RECOMMENDED)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Or using Python directly
python main.py
```

### Production
```bash
python main.py
```

### Virtual Environment
```bash
# The project uses conda environment 'opa_acl'
conda activate opa_acl
```

### No Testing/Linting Infrastructure
- **No pytest configured** - No test runner setup for the main app
- **No linting tools** - No black, flake8, mypy, or pylint configured
- **No CI/CD** - No automated checks in place
- If adding tests, create a `tests/` directory and use `pytest`

## Project Structure

```
jb_demo/
├── main.py                 # Entry point (7 lines)
├── app/                    # Backend application
│   ├── __init__.py         # FastAPI app, CORS, static files
│   ├── config.py           # GLOBAL_SETTINGS, AVAILABLE_DATASETS
│   ├── models.py           # Pydantic request/response models
│   ├── services/           # Business logic
│   │   ├── llm.py          # LLM calling via litellm
│   │   ├── evaluator.py    # Keyword + LLM judge evaluation
│   │   └── dataset.py      # Dataset loading utilities
│   └── routes/             # API endpoints
│       ├── __init__.py     # Route registration
│       ├── config.py       # GET/POST /api/config
│       ├── test.py         # POST /api/test_scenario
│       ├── batch.py        # GET /api/datasets, POST /api/batch_evaluate
│       └── attack.py       # 攻击生成与评估相关 API
│   └── services/
│       └── attack_generator.py # EasyJailbreak 集成与提示词生成
├── static/                 # Frontend assets
│   ├── css/style.css       # Custom styles
│   └── js/                 # Vue app and components
├── templates/              # Jinja2 templates
│   └── index.html          # Main page (Vue 3 + Tailwind)
└── datasets/               # Security test datasets (CSV files)
```

## Code Style Guidelines

### Python (Backend)

**Imports:**
- Group imports: stdlib → third-party → local
- Use `from pathlib import Path` for paths
- Example:
```python
import json
import asyncio
from typing import Dict, Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.config import GLOBAL_SETTINGS
from app.services.llm import call_llm_model
```

**Type Hints:**
- Use type hints for function parameters and returns
- Use `Optional[T]` for nullable types
- Use `Dict[str, Any]` for flexible dicts
- Example:
```python
async def evaluate_single_prompt(prompt: str, target: str, evaluator: str) -> Dict:
    ...
```

**Naming Conventions:**
- `snake_case` for functions and variables
- `PascalCase` for classes (Pydantic models)
- `UPPER_CASE` for global constants
- Example: `GLOBAL_SETTINGS`, `AttackRequest`, `call_llm_model()`

**Error Handling:**
- Wrap external API calls in try-except
- Return user-friendly error messages in Chinese
- Example:
```python
try:
    response = await acompletion(...)
    return response.choices[0].message.content
except Exception as e:
    return f"模型调用失败: {str(e)}"
```

**Async/Await:**
- All I/O operations (LLM calls, file reads) use async
- FastAPI routes are async by default
- Example: `async def test_scenario(req: AttackRequest):`

**Pydantic Models:**
- Define request/response schemas in `app/models.py`
- Use descriptive field names
- Example:
```python
class AttackResponse(BaseModel):
    target_type: str
    eval_type: str
    response_content: str
    is_success: bool
    latency: float
```

### JavaScript/Vue (Frontend)

**Vue 3 Composition API:**
- Use `<script setup>` style composition API
- Reactive state with `ref()` and `reactive()`
- Example:
```javascript
const { createApp, ref, reactive, computed, onMounted } = Vue;

const app = createApp({
  setup() {
    const prompt = ref('');
    const config = reactive({ target: 'api', judge: 'all' });
    
    onMounted(() => {
      fetchSettings();
    });
    
    return { prompt, config };
  }
});
```

**Template Delimiters:**
- Use `[[ ]]` for Vue (NOT `{{ }}`) to avoid Jinja2 conflicts
- Configure: `app.config.compilerOptions.delimiters = ['[[', ']]'];`

**Naming:**
- `camelCase` for variables and functions
- Descriptive names in Chinese or English
- Event handlers: `handleClick`, `saveSettings`

**API Calls:**
- Use native `fetch()` API
- Always set `Content-Type: application/json` for POSTs
- Example:
```javascript
const response = await fetch('/api/test_scenario?target=api&evaluator=keyword', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ prompt: prompt.value })
});
const data = await response.json();
```

## Key Patterns

### Global Configuration
- Stored in `app.config.GLOBAL_SETTINGS`
- Updated via `/api/config` POST endpoint
- Two targets: `"api"` (remote) and `"local"` (Ollama)

### LLM Calling
- Use `litellm.acompletion()` in `app/services/llm.py`
- Always check for API key before calling
- Handle timeouts (default 60s)

### Evaluation Logic
- Two evaluators: `keyword` (fast) and `llm_judge` (accurate)
- Keyword: Check refusal words in response
- LLM Judge: Use separate LLM to classify safety

### SSE Streaming (Batch Evaluation)
- Use `StreamingResponse` with `text/event-stream`
- Format: `data: {json}\n\n`
- Send progress updates during long operations

### Attack Generation (EasyJailbreak)
- API: `GET /api/attack_methods`, `POST /api/generate_attacks`, `POST /api/attack_and_evaluate`
- 攻击方法列表与描述在 `app/services/attack_generator.py` 的 `ATTACK_METHODS`
- 部分方法需要攻击模型配置（API Key / Model），否则返回明确错误或降级为模拟模板

### Dataset Loading
- CSV files in `datasets/` directory
- Configure in `AVAILABLE_DATASETS` dict
- Specify `prompt_column` for each dataset

## 算法级升级路线（11 方法全量）

以下路线用于把当前“mutation/模板化生成”升级为真正算法级攻击流程，支持面试展示与后续实现落地。

### 总体规划（核心 4 方法先行）
- 把当前“mutation/模板化生成”升级为算法级攻击流程，优先落地 PAIR / TAP / GPTFuzz / GCG。
- 同时支持开源本地模型（可白盒或半白盒）与商用 API 模型（黑盒交互）。
- 保留现有 UI/接口习惯，新增“算法级执行”与“模拟执行”双模式，并记录全过程指标。

**关键改造方向**
- 新增“攻击执行器”抽象：`AttackEngine`（算法级实现 vs 模拟实现）。
- 输出统一 `AttackRunResult`：包含生成过程日志、迭代轨迹、成功率、成本与耗时。
- 模型与评估基础设施：
  - 本地模型：`transformers` 或 `vLLM` 作为攻击目标与 judge。
  - API 模型：现有 `litellm` 接口扩展为统一 adapter。
  - Judge 策略：默认 LLM Judge + 关键词规则双路输出。
- 接口/配置升级：
  - `AttackGenRequest` 新增 `execution_mode`（`algorithmic | simulated`）、`max_iters`、`beam_width`、`budget`、`seed`
  - 生成结果增加 `trace`、`score_history`、`cost_estimate`。
- 前端展示：
  - UI 增加“算法级模式”开关 + 进度状态显示。
  - 展示迭代过程摘要（最佳提示词 / 成功率 / 花费）。

**新增公共接口（规划）**
- `GET /api/attack_runs/{id}` 查询长流程任务状态与中间结果。

### 分阶段落地（11 方法）

#### 阶段 1（白盒/高算力依赖）
- **GCG**：接入可微模型与梯度优化，对抗后缀搜索；需要 GPU 与可微推理框架。
- **AutoDAN**：若走优化式生成，需实现“候选池 + 判别器评分 + 迭代优化”；否则保持模板级作为过渡。

#### 阶段 2（黑盒/半黑盒迭代搜索）
- **PAIR**：实现“提示词改写 → 目标模型反馈 → 评分 → 迭代优化”闭环；需 judge 或拒答检测信号。
- **TAP**：实现树搜索生成策略 + 剪枝规则（基于评分/拒答信号），记录搜索轨迹。
- **GPTFuzz**：构建 mutation 池 + 反馈驱动选优/增殖；支持预算与迭代上限。
- **ReNeLLM**：实现“重写/否定/约束消解”策略集 + 迭代选择机制。

#### 阶段 3（规则/编码/多语言 → 算法级）
- **Cipher**：编码/混淆策略从静态模板升级为“多策略组合 + 可学习选择”。
- **ICA**：上下文攻击升级为“示例池管理 + 动态检索 + 反事实上下文构造”。
- **JailBroken**：把多模板升级为“多策略搜索与评分”，形成可解释攻击路径。
- **CodeChameleon**：引入代码语义保持与攻击语义注入的双目标优化。
- **MultiLingual**：加入多语言检索与对齐检查（翻译质量与攻击保真度双评价）。

## Common Tasks

### Adding a New API Endpoint
1. Create handler in `app/routes/[name].py`
2. Use `APIRouter()` and define routes
3. Import and register in `app/routes/__init__.py`

### Adding a New Dataset
1. Add CSV to `datasets/` folder
2. Add entry to `AVAILABLE_DATASETS` in `app/config.py`
3. Specify correct `prompt_column` name

### Adding Frontend Components
1. Create component in `static/js/components/`
2. Register in `app.js`: `app.component('name', Component)`
3. Use in template with kebab-case: `<my-component>`

### Adding a New Attack Method
1. 在 `app/services/attack_generator.py` 的 `ATTACK_METHODS` 增加方法定义
2. 在 `generate_adversarial_prompts()` 中接入真实 mutation 或模板回退逻辑
3. 如需攻击模型，确保请求中或全局配置提供 API Key / Model / API Base

## Important Notes

- **Chinese UI**: All user-facing text should be in Chinese
- **No database**: Uses in-memory state only
- **CORS enabled**: Allows all origins in development
- **Static files**: Served from `/static` path
- **Templates**: Jinja2 with `{% raw %}` blocks for Vue compatibility
- **Port**: App runs on port 8000
