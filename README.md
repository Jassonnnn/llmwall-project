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
conda activate opa_acl
```

### 2. 进入项目目录

```bash
cd /data/ljc/llmwall-project/jb_demo
```

### 3. 启动服务

```bash
# 开发模式（支持热重载）
uvicorn main:app --reload --host 0.0.0.0 --port 8000

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
| `/api/datasets` | GET | 获取可用数据集列表 |
| `/api/test_scenario` | POST | 单条指令测试 |
| `/api/batch_evaluate` | POST | 批量评估（SSE 流式返回） |

## 使用说明

### 对话测试模式

1. 在设置中配置 API Key（点击右上角 ⚙️ 按钮）
2. 选择目标模型（远程 API / 本地模型）
3. 选择评估方式（关键词 / LLM 裁判）
4. 输入测试指令，点击发送

### 批量评估模式

1. 切换到"批量评估"标签页
2. 选择测试数据集
3. 设置采样数量（可选）
4. 选择目标模型和评估方式
5. 点击"开始评估"，实时查看进度

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
