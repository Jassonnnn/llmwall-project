# AGENTS.md

Guidelines for coding agents working in this `jb_demo` repository.

## 1. Project Snapshot

`jb_demo` is a FastAPI + Vue 3 red-team evaluation platform for LLM safety testing.

Core capabilities:
- Single-prompt interactive evaluation (`/api/test_scenario`)
- Batch dataset evaluation with attack-category filtering (`/api/batch_evaluate`)
- Attack generation and attack+evaluation flows (`/api/generate_attacks`, `/api/attack_and_evaluate`)
- Unified async task API for red-team + optional guardrail (`/api/evaluations`)

## 2. Environment and Startup

Use the repository conda env:

```bash
conda activate jb_demo
export PYTHONNOUSERSITE=1
```

Recommended startup:

```bash
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Dependency alignment:

```bash
python -m pip install -r requirements.lock.txt
python scripts/doctor_env.py
```

## 3. High-Level Architecture

- Entry: `main.py` (thin launcher)
- App init: `app/__init__.py`
  - CORS setup (localhost defaults + `APP_CORS_ALLOW_ORIGINS` override)
  - unified error handlers (`AppError`, validation, unexpected errors)
  - startup hook initializes SQLite evaluation store
- Auth: `app/auth.py`
  - Bearer token auth via `JB_DEMO_SERVICE_TOKEN`
  - local bypass controlled by `JB_DEMO_ALLOW_LOCAL_BYPASS`
- Routes: `app/routes/`
  - `config.py`, `test.py`, `batch.py`, `attack.py`, `evaluations.py`
- Services: `app/services/`
  - `llm.py`, `evaluator.py`, `keyword_rules.py`, `dataset.py`, `attack_generator.py`, `evaluation_tasks.py`
- Runtime DB: default `runtime/evaluation_tasks.db`

## 4. API Surface (Current)

Public or low-risk read endpoints:
- `GET /`
- `GET /api/datasets`
- `GET /api/attack_methods`

Auth-protected endpoints (require `Authorization: Bearer <token>` unless local bypass enabled):
- `GET/POST /api/config`
- `POST /api/test_scenario`
- `POST /api/batch_evaluate`
- `POST /api/batch_cancel/{task_id}`
- `POST /api/generate_attacks`
- `POST /api/attack_and_evaluate`
- `POST /api/batch_generate_attacks`
- `POST /api/evaluations`
- `GET /api/evaluations/{task_id}`
- `GET /api/evaluations/{task_id}/results`
- `POST /api/evaluations/{task_id}/cancel`

## 5. Data and Index Rules

Attack category index policy:
- preferred: `datasets/index/attack_category_index_v2.jsonl`
- fallback to v1 only when `ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK=true`

Do not mutate source CSVs for categorization. Use sidecar index + review writeback flow:
- build: `scripts/build_attack_category_index.py`
- apply review: `scripts/apply_attack_category_review.py`

## 6. Security and Reliability Baselines

- Never return plaintext API keys in API responses.
  - Config APIs expose `has_api_key` and masked values only.
- Use unified error payload (`status/code/message/details`) via `AppError`.
- Batch and unified task flows must support cancellation.
- Keep service-token auth enabled in production:
  - `JB_DEMO_REQUIRE_AUTH=true`
  - `JB_DEMO_ALLOW_LOCAL_BYPASS=false`

## 7. Coding Conventions

Python:
- Prefer type hints for function signatures.
- Raise `AppError` for business/contract errors.
- Keep route handlers thin; move logic to `app/services`.
- Reuse existing evaluator/dataset/task helpers; avoid duplicating flow logic.

Frontend:
- Vue delimiter is `[[ ]]` (avoid Jinja2 collision).
- Keep user-facing text in Chinese.

## 8. Common Change Patterns

Add a new endpoint:
1. implement route in `app/routes/*.py`
2. register router in `app/routes/__init__.py`
3. add/adjust request models in `app/models.py` if needed
4. update README API table and usage examples

Add a new dataset:
1. place CSV under `datasets/`
2. add config in `app/config.py` `AVAILABLE_DATASETS`
3. verify `prompt_column`
4. rebuild category index and quality report if used in batch mode

Add a new attack method:
1. update method registry in `app/services/attack_generator.py`
2. implement real attacker flow or explicit fallback mode
3. ensure structured errors when required dependencies/config are missing
4. expose generation mode in response for auditability

## 9. Current Engineering Gaps (M4)

Not fully complete yet:
- project-level automated tests (`tests/`)
- CI workflows (lint/test/build gates)
- deployment/rollback runbooks and containerized delivery

When implementing these, keep docs synchronized:
- `README.md`
- `OPTIMIZATION_PLAN.md`
- `REPORT_PROGRESS_2026-03-25.md`
