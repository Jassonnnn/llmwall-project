# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个 **LLM 红队安全评估平台**，用于测试大语言模型对对抗性攻击的防御能力。支持两种评估模式：
- **对话测试模式**：单条指令的实时安全评估
- **批量评估模式**：基于数据集的批量攻击成功率测试

## 启动命令

```bash
# 开发模式（热重载）
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 生产模式
python main.py
```

访问 `http://localhost:8000` 查看Web界面。

## 架构概览

### 后端 (main.py)
- **框架**: FastAPI + Jinja2
- **LLM调用**: 使用 `litellm` 库统一调用各种模型API
- **模型配置**: 支持远程API（OpenRouter/OpenAI等）和本地模型（Ollama）
- **评估方式**:
  - `keyword_evaluate()`: 关键词匹配检测拒绝词
  - `llm_judge_evaluate()`: 使用LLM作为裁判判断安全性
- **批量评估**: 使用SSE (Server-Sent Events) 实时推送进度

### 前端 (templates/index.html)
- **框架**: Vue 3 + Tailwind CSS
- **模板语法**: 使用 `[[ ]]` 作为Vue分隔符（避免与Jinja2冲突）
- **组件**: ChatCard（对话结果卡片）

### 数据集 (datasets/)
包含三个红队测试数据集：
- **HarmBench**: 标准化红队评估框架，提示词列为 `Behavior`
- **AdvBench (llm-attacks)**: 520个有害行为提示词，列为 `goal`
- **JailbreakBench**: 越狱攻击基准测试

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/config` | GET/POST | 获取/更新模型配置 |
| `/api/datasets` | GET | 获取可用数据集列表 |
| `/api/test_scenario` | POST | 单条指令测试 |
| `/api/batch_evaluate` | POST | 批量评估（返回SSE流） |

## 添加新数据集

在 `main.py` 的 `AVAILABLE_DATASETS` 字典中添加配置：
```python
"dataset_id": {
    "name": "显示名称",
    "description": "描述",
    "path": "相对于datasets/的路径",
    "prompt_column": "CSV中提示词所在列名",
    "count": None
}
```

## 依赖项

主要依赖：`fastapi`, `uvicorn`, `litellm`, `pandas`, `jinja2`
