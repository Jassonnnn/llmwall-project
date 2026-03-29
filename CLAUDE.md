# CLAUDE.md

本文件用于给代码代理（含 Claude/Codex）提供 `jb_demo` 仓库的快速事实参考。

## 项目定位

`jb_demo` 是一个 LLM 红队安全评估后端（FastAPI）+ 内置前端（Vue 3）项目，支持：

- 单条提示词安全测试
- 批量数据集评估（攻击分类 + 固定条数）
- 越狱攻击提示词生成与联测
- 统一异步任务接口（red-team + 可选 guardrail）

## 启动方式（推荐）

```bash
conda activate jb_demo
export PYTHONNOUSERSITE=1
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

可用环境自检：

```bash
python -m pip install -r requirements.lock.txt
python scripts/doctor_env.py
```

## 当前后端结构

- 入口：`main.py`
- 应用初始化：`app/__init__.py`
  - CORS、静态文件、异常处理、启动初始化
- 路由：`app/routes/`
  - `config.py`
  - `test.py`
  - `batch.py`
  - `attack.py`
  - `evaluations.py`
- 服务：`app/services/`
  - `llm.py`
  - `evaluator.py`
  - `keyword_rules.py`
  - `dataset.py`
  - `attack_generator.py`
  - `evaluation_tasks.py`
- 鉴权：`app/auth.py`
- 统一错误：`app/errors.py`

## 关键接口

- 配置：`GET/POST /api/config`
- 单测：`POST /api/test_scenario`
- 数据集：`GET /api/datasets`
- 批量评估：`POST /api/batch_evaluate`
- 批量取消：`POST /api/batch_cancel/{task_id}`
- 攻击方法列表：`GET /api/attack_methods`
- 攻击生成：`POST /api/generate_attacks`
- 攻击并评估：`POST /api/attack_and_evaluate`
- 统一任务创建：`POST /api/evaluations`
- 统一任务查询：`GET /api/evaluations/{task_id}`
- 统一结果分页：`GET /api/evaluations/{task_id}/results`
- 统一任务取消：`POST /api/evaluations/{task_id}/cancel`
- safetydash 登录：`POST /api/auth/login`
- safetydash 用户态：`GET /api/auth/me`
- safetydash 红队概览：`GET /api/redteam/overview`

## 鉴权与安全约束

默认要求服务鉴权（Bearer Token）：

- `JB_DEMO_REQUIRE_AUTH=true`
- `JB_DEMO_SERVICE_TOKEN=<token>`
- `JB_DEMO_ALLOW_LOCAL_BYPASS=true`（本地开发可放行，生产建议设为 `false`）

密钥治理原则：
- 不回传明文 key
- 配置接口只暴露 `has_api_key` 与掩码值

## 数据集与分类索引

攻击分类索引默认使用 `v2`：
- `datasets/index/attack_category_index_v2.jsonl`

仅在显式开启时允许回退 `v1`：
- `ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK=true`

构建与复核脚本：
- `scripts/build_attack_category_index.py`
- `scripts/apply_attack_category_review.py`

## 已知现状

- M1/M2/M3 能力已落地（安全基线、评估可信度、统一任务 API）
- M4 工程化仍待完善（测试、CI、部署/回滚手册）

建议任何功能变更后同步更新：
- `README.md`
- `OPTIMIZATION_PLAN.md`
- `REPORT_PROGRESS_2026-03-25.md`
