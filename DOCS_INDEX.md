# 文档总览（`jb_demo`）

最后更新：`2026-03-26`

## 1. 你应该先看哪份文档

1. 新同学上手：先看 `README.md`
2. 做阶段汇报：看 `REPORT_PROGRESS_2026-03-25.md`
3. 做按周口头汇报：看 `WEEKLY_REPORT_SCRIPT.md`
4. 追踪路线图：看 `OPTIMIZATION_PLAN.md`
5. 数据集与分类：看 `datasets/README.md`
6. 代理协作规范：看 `AGENTS.md` / `CLAUDE.md`

## 2. 文档职责边界

| 文档 | 作用 | 目标读者 |
|---|---|---|
| `README.md` | 项目总览、接口清单、运行方式、当前完成度 | 开发/联调/演示 |
| `SAFETYDASH_ADAPTER.md` | safetydash 前端零改动接入说明与字段映射 | 前后端联调 |
| `REPORT_PROGRESS_2026-03-25.md` | 阶段成果、提交时间线、汇报口径 | 组会/周报汇报 |
| `WEEKLY_REPORT_SCRIPT.md` | 按周拆分的口头汇报话术（第 2 周 - 第 6 周） | 组会口头汇报 |
| `OPTIMIZATION_PLAN.md` | 里程碑计划与后续任务池 | 负责人/排期协作 |
| `datasets/README.md` | 数据来源与分类索引策略（v2 优先） | 数据治理/评估同学 |
| `AGENTS.md` | 代码代理工程约束与实现规则 | AI Coding Agent |
| `CLAUDE.md` | 面向代码代理的快速事实参考 | AI Coding Agent |

## 3. 维护原则

- 代码接口变更后，至少同步更新 `README.md` 的 API 表。
- 里程碑状态变更后，同步更新 `OPTIMIZATION_PLAN.md` 与阶段汇报。
- 索引策略或数据流程变更后，同步更新 `datasets/README.md`。
- 任何文档若出现与代码不一致，以代码行为为准并立即修订文档。
