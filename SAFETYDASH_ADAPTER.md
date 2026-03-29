# SafetyDash 适配说明（`jb_demo` 后端）

## 1. 目标

在不修改 `safetydash` 前端代码的前提下，让红队页切换到 `jb_demo` 真实数据。

## 2. 兼容接口

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/redteam/overview`

其中：
- `/api/auth/*` 使用 JWT Bearer。
- `jb_demo` 原生关键接口（如 `/api/evaluations`）继续使用服务令牌鉴权。

## 3. 字段映射（`/api/redteam/overview`）

返回结构对齐 safetydash `RedteamOverview`：

- `datasets`：
  - 来源：`jb_demo` 数据集配置与统计（`/api/datasets` 同源数据）
  - 字段：`id/name/description/count`
- `promptExamples`：
  - 来源：攻击分类索引 + 数据集样本抽样
  - 字段：`id/title/prompt/category`
- `runningTasks`：
  - 来源：`evaluation_tasks`（SQLite）
  - 状态映射：
    - `queued -> queued`
    - `running/cancelling -> running`
    - `completed -> done`
    - `failed/cancelled -> failed`
  - 进度：`progress = completed / total * 100`
- `recentResults`：
  - 来源：`evaluation_tasks` 聚合
  - `score = success_count / total`
  - `summary` 为任务统计摘要文本

## 4. 运行配置

`jb_demo`（建议）：

```bash
export JB_DEMO_JWT_SECRET=change-me
export JB_DEMO_JWT_ALG=HS256
export JB_DEMO_ACCESS_TOKEN_EXPIRE_MINUTES=60
export JB_DEMO_SEED_USERNAME=admin
export JB_DEMO_SEED_PASSWORD=admin
export APP_CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

`safetydash` 前端 `.env`：

```bash
VITE_USE_MOCK=false
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## 5. 注意事项

- 当前适配聚焦红队页数据真实化；前端“新建任务”按钮仍为占位逻辑。
- 若要接入全站（gateway/vuln）真实后端，需要继续补齐对应兼容接口。
