# SafetyDash 适配说明（`jb_demo` 红队后端）

## 1. 目标

让 `safetydash` 真正作为 `jb_demo` 的红队前端使用，而不是只展示一层概览数据。

当前推荐架构：

`safetydash frontend -> dashboard-api(BFF) -> jb_demo`

说明：

- `jb_demo` 继续作为真实红队后端。
- `safetydash` 负责前端交互。
- `dashboard-api` 负责 JWT 登录、前端鉴权、字段整形与对 `jb_demo` 的服务端转发。

## 2. 当前已接通的红队能力

前端现在已经具备三类真实能力：

1. 单条测试
   - 输入 1 条 prompt
   - 同时测试 `api/local × keyword/llm_judge`
   - 前端显示 4 格结果矩阵
2. 数据集批量评估
   - 选择数据集、攻击分类、样本条数、攻击方法
   - 支持任务创建、状态轮询、结果分页、取消、导出
3. 独立攻击方法实验室
   - 输入种子提示词
   - 选择攻击方法
   - 只生成攻击提示词，或直接“生成并测试”

## 3. dashboard-api 对前端暴露的接口

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/redteam/overview`
- `GET /api/redteam/datasets`
- `GET /api/redteam/attack-methods`
- `POST /api/redteam/single-test/matrix`
- `POST /api/redteam/attack-lab/generate`
- `POST /api/redteam/attack-lab/run`
- `POST /api/redteam/tasks`
- `GET /api/redteam/tasks/{task_id}`
- `GET /api/redteam/tasks/{task_id}/results`
- `POST /api/redteam/tasks/{task_id}/cancel`
- `GET /api/redteam/tasks/{task_id}/export`

其中：

- `/api/auth/*` 使用 JWT Bearer。
- 红队页面所有操作都先打到 `dashboard-api`。
- `dashboard-api` 再去调用 `jb_demo` 的原生接口。

## 4. jb_demo 侧被调用的真实接口

- `GET /api/datasets`
- `GET /api/attack_methods`
- `POST /api/test_scenario`
- `POST /api/generate_attacks`
- `POST /api/attack_and_evaluate`
- `POST /api/evaluations`
- `GET /api/evaluations/{task_id}`
- `GET /api/evaluations/{task_id}/results`
- `POST /api/evaluations/{task_id}/cancel`
- `GET /api/evaluations/{task_id}/export`

其中：

- `jb_demo` 原生关键接口继续使用服务令牌鉴权（`JB_DEMO_SERVICE_TOKEN`）。
- `dashboard-api` 负责在服务端带上该令牌。

## 5. `overview` 字段映射（`/api/redteam/overview`）

返回结构对齐 safetydash `RedteamOverview`：

- `datasets`
  - 来源：`jb_demo` 数据集配置与统计（与 `/api/datasets` 同源）
  - 字段：`id/name/description/count`
- `promptExamples`
  - 来源：攻击分类索引 + 数据集样本抽样
  - 字段：`id/title/prompt/category`
- `runningTasks`
  - 来源：`evaluation_tasks`（SQLite）
  - 状态映射：
    - `queued -> queued`
    - `running/cancelling -> running`
    - `completed -> done`
    - `failed/cancelled -> failed`
  - 进度：`progress = completed / total * 100`
- `recentResults`
  - 来源：`evaluation_tasks` 聚合
  - `score = success_count / total`
  - `summary` 为任务统计摘要文本

## 6. 白盒方法限制

- `GCG`
- `AutoDAN`

这两类方法属于白盒攻击：

- 前端会明确标注“白盒”
- 当前端目标不是 `local` 时，前端直接拦截
- 后端仍然保留强校验，避免前端绕过时误调用

## 7. 运行配置

`jb_demo`：

```bash
export JB_DEMO_SERVICE_TOKEN=change-me
export JB_DEMO_JWT_SECRET=change-me
export JB_DEMO_JWT_ALG=HS256
export JB_DEMO_ACCESS_TOKEN_EXPIRE_MINUTES=60
export JB_DEMO_SEED_USERNAME=admin
export JB_DEMO_SEED_PASSWORD=admin
export APP_CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

`dashboard-api`：

```bash
export JB_DEMO_BASE_URL=http://127.0.0.1:18013
export JB_DEMO_USERNAME=admin
export JB_DEMO_PASSWORD=admin
export JB_DEMO_SERVICE_TOKEN=change-me
export SEED_USERNAME=admin
export SEED_PASSWORD=admin
```

`safetydash` 前端 `.env`：

```bash
VITE_USE_MOCK=false
VITE_API_BASE_URL=http://127.0.0.1:18117
```

## 8. 联调结论

当前红队页已经不是“只看概览”：

- 单条 `2x2` 测试可走通
- 数据集批量任务可走通
- 攻击方法生成 / 生成并评估可走通
- 任务详情、分页结果、取消、导出可走通

如果后续要继续扩展 `gateway / vuln` 两个页面，再按同样方式补各自的 BFF 路由即可。
