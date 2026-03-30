import asyncio
import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from app.config import (
    GLOBAL_SETTINGS,
    JB_DEMO_EVAL_DB_PATH,
    JB_DEMO_EVAL_RESULTS_PAGE_LIMIT,
    JB_DEMO_MAX_CONCURRENT_BATCH_TASKS,
)
from app.errors import AppError
from app.models import EvaluationCreateRequest
from app.services.attack_generator import (
    AttackConfigError,
    ensure_attack_method_target_supported,
    generate_adversarial_prompts,
)
from app.services.dataset import CategoryIndexMissingError, load_dataset_entries
from app.services.evaluator import evaluate_single_prompt

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
DIRECT_PROMPT_METHOD = "direct_prompt"

ACTIVE_TASKS: Dict[str, Dict[str, Any]] = {}
ACTIVE_TASKS_LOCK = asyncio.Lock()
DB_LOCK = asyncio.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _json_loads(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _connect() -> sqlite3.Connection:
    db_path = Path(JB_DEMO_EVAL_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, column_sql: str) -> None:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    existing = {str(row[1]) for row in rows}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_sql}")


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def _build_metric_block(total: int, success_count: int, fail_count: int, error_count: int, avg_latency: float) -> Dict[str, Any]:
    return {
        "samples_evaluated": total,
        "attack_success_count": success_count,
        "attack_failed_count": fail_count,
        "error_count": error_count,
        "attack_success_rate": _rate(success_count, total),
        "refusal_rate": _rate(fail_count, total),
        "error_rate": _rate(error_count, total),
        "avg_latency": round(avg_latency, 4),
    }


def _normalize_attack_methods(payload: Dict[str, Any]) -> List[str]:
    raw_methods = payload.get("attack_methods", [])
    if not isinstance(raw_methods, list):
        return []

    methods: List[str] = []
    seen = set()
    for item in raw_methods:
        method = str(item).strip()
        if not method or method in seen:
            continue
        methods.append(method)
        seen.add(method)
    return methods


def _build_config_snapshot(
    target: str,
    include_guardrail: bool,
    guardrail_target: str,
    attack_methods: List[str],
    generated_prompt_count_per_seed: int,
) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {}
    for item in ("api", "local"):
        cfg = GLOBAL_SETTINGS.get(item, {})
        snapshot[item] = {
            "name": cfg.get("name", ""),
            "model": cfg.get("model", ""),
            "api_base": cfg.get("api_base", ""),
            "has_api_key": bool(cfg.get("api_key", "")),
        }
    return {
        "target": target,
        "include_guardrail": include_guardrail,
        "guardrail_target": guardrail_target,
        "attack_methods": attack_methods,
        "generated_prompt_count_per_seed": generated_prompt_count_per_seed,
        "models": snapshot,
    }


def _resolve_guardrail_target(req: EvaluationCreateRequest) -> str:
    if req.guardrail_target:
        return req.guardrail_target
    if req.target != "local":
        return "local"
    return "api"


def _resolve_guardrail_evaluator(req: EvaluationCreateRequest) -> str:
    if req.guardrail_evaluator:
        return req.guardrail_evaluator
    if req.evaluator in {"keyword", "llm_judge"}:
        return req.evaluator
    return "keyword"


def _task_row_to_payload(row: sqlite3.Row) -> Dict[str, Any]:
    total = int(row["total"] or 0)
    completed = int(row["completed"] or 0)
    success_count = int(row["success_count"] or 0)
    fail_count = int(row["fail_count"] or 0)
    error_count = int(row["error_count"] or 0)
    progress_percent = round((completed / total) * 100, 2) if total > 0 else 0.0

    return {
        "task_id": row["task_id"],
        "status": row["status"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "cancel_requested_at": row["cancel_requested_at"],
        "dataset_id": row["dataset_id"],
        "attack_category": row["attack_category"],
        "requested_sample_count": row["requested_sample_count"],
        "category_total_count": row["category_total_count"],
        "prompts_count": row["prompts_count"],
        "summary": {
            "total": total,
            "completed": completed,
            "success_count": success_count,
            "fail_count": fail_count,
            "error_count": error_count,
            "success_rate": round((success_count / total) * 100, 2) if total > 0 else 0.0,
            "progress_percent": progress_percent,
        },
        "request_payload": _json_loads(row["request_payload"]),
        "config_snapshot": _json_loads(row["config_snapshot"]),
        "error": {
            "code": row["error_code"] or "",
            "message": row["error_message"] or "",
        },
    }


def _resolve_execution_plan(payload: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    target = str(payload.get("target", "api"))
    evaluator = str(payload.get("evaluator", "keyword"))

    targets = ["api", "local"] if target == "all" else [target]
    evaluators = ["keyword", "llm_judge"] if evaluator == "all" else [evaluator]

    plan: List[Tuple[str, str, str]] = []
    for item_target in targets:
        for item_eval in evaluators:
            plan.append(("red_team", item_target, item_eval))

    if payload.get("include_guardrail"):
        guardrail_target = str(payload.get("guardrail_target", "")).strip()
        guardrail_evaluator = str(payload.get("guardrail_evaluator", "")).strip()
        if guardrail_target and guardrail_evaluator:
            plan.append(("guardrail", guardrail_target, guardrail_evaluator))

    return plan


async def _fetch_task_row(task_id: str) -> Optional[sqlite3.Row]:
    async with DB_LOCK:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM evaluation_tasks WHERE task_id = ?", (task_id,)).fetchone()
        finally:
            conn.close()
    return row


async def _update_task(task_id: str, **fields: Any) -> None:
    if not fields:
        return
    assignments = ", ".join([f"{key} = ?" for key in fields.keys()])
    values = list(fields.values()) + [task_id]
    sql = f"UPDATE evaluation_tasks SET {assignments} WHERE task_id = ?"

    async with DB_LOCK:
        conn = _connect()
        try:
            conn.execute(sql, values)
            conn.commit()
        finally:
            conn.close()


async def _insert_result(
    task_id: str,
    result_index: int,
    phase: str,
    prompt: str,
    target: str,
    evaluator: str,
    result: Dict[str, Any],
    *,
    seed_prompt: str,
    source_attack_category: str,
    attack_method: str,
    generation_mode: str,
) -> None:
    async with DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO evaluation_results (
                    task_id, result_index, phase, seed_prompt, source_attack_category, attack_method,
                    generation_mode, prompt, target_type, eval_type, response_content, is_success,
                    latency, reasoning_trace, evaluator_version, model_name, status,
                    error_code, error_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    result_index,
                    phase,
                    seed_prompt,
                    source_attack_category,
                    attack_method,
                    generation_mode,
                    prompt,
                    target,
                    evaluator,
                    str(result.get("response_content", "")),
                    1 if bool(result.get("is_success", False)) else 0,
                    float(result.get("latency", 0.0) or 0.0),
                    str(result.get("reasoning_trace", "")),
                    str(result.get("evaluator_version", "")),
                    str(result.get("model_name", "")),
                    str(result.get("status", "ok")),
                    str(result.get("error_code", "") or ""),
                    str(result.get("error_message", "") or ""),
                    _now_iso(),
                ),
            )
            conn.commit()
        finally:
            conn.close()


async def _load_phase_summary(task_id: str) -> Dict[str, Dict[str, int]]:
    async with DB_LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT
                    phase,
                    COUNT(1) AS total,
                    SUM(CASE WHEN is_success = 1 AND status = 'ok' THEN 1 ELSE 0 END) AS success_count,
                    SUM(CASE WHEN is_success = 0 AND status = 'ok' THEN 1 ELSE 0 END) AS fail_count,
                    SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END) AS error_count
                FROM evaluation_results
                WHERE task_id = ?
                GROUP BY phase
                """,
                (task_id,),
            ).fetchall()
        finally:
            conn.close()

    summary: Dict[str, Dict[str, int]] = {}
    for row in rows:
        phase = str(row["phase"])
        success_count = int(row["success_count"] or 0)
        fail_count = int(row["fail_count"] or 0)
        if phase == "guardrail":
            summary[phase] = {
                "total": int(row["total"] or 0),
                "bypass_count": success_count,
                "blocked_count": fail_count,
                "error_count": int(row["error_count"] or 0),
            }
        else:
            summary[phase] = {
                "total": int(row["total"] or 0),
                "attack_success_count": success_count,
                "attack_failed_count": fail_count,
                "error_count": int(row["error_count"] or 0),
            }
    return summary


async def _load_group_summary(task_id: str, group_field: str) -> List[Dict[str, Any]]:
    if group_field not in {"attack_method", "source_attack_category"}:
        return []

    async with DB_LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                f"""
                SELECT
                    {group_field} AS group_key,
                    COUNT(1) AS total,
                    SUM(CASE WHEN is_success = 1 AND status = 'ok' THEN 1 ELSE 0 END) AS success_count,
                    SUM(CASE WHEN is_success = 0 AND status = 'ok' THEN 1 ELSE 0 END) AS fail_count,
                    SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END) AS error_count,
                    AVG(latency) AS avg_latency
                FROM evaluation_results
                WHERE task_id = ? AND phase = 'red_team'
                GROUP BY {group_field}
                ORDER BY total DESC, group_key ASC
                """,
                (task_id,),
            ).fetchall()
        finally:
            conn.close()

    grouped: List[Dict[str, Any]] = []
    for row in rows:
        key = str(row["group_key"] or "").strip() or "unknown"
        total = int(row["total"] or 0)
        success_count = int(row["success_count"] or 0)
        fail_count = int(row["fail_count"] or 0)
        error_count = int(row["error_count"] or 0)
        avg_latency = float(row["avg_latency"] or 0.0)
        grouped.append(
            {
                "key": key,
                **_build_metric_block(total, success_count, fail_count, error_count, avg_latency),
            }
        )
    grouped.sort(
        key=lambda item: (
            -float(item.get("attack_success_rate", 0.0)),
            -int(item.get("samples_evaluated", 0)),
            str(item.get("key", "")),
        )
    )
    for index, item in enumerate(grouped, start=1):
        item["rank"] = index
    return grouped


async def _load_summary_metrics(task_id: str) -> Dict[str, Any]:
    async with DB_LOCK:
        conn = _connect()
        try:
            row = conn.execute(
                """
                SELECT
                    COUNT(1) AS total,
                    SUM(CASE WHEN is_success = 1 AND status = 'ok' THEN 1 ELSE 0 END) AS success_count,
                    SUM(CASE WHEN is_success = 0 AND status = 'ok' THEN 1 ELSE 0 END) AS fail_count,
                    SUM(CASE WHEN status != 'ok' THEN 1 ELSE 0 END) AS error_count,
                    AVG(latency) AS avg_latency,
                    COUNT(DISTINCT attack_method) AS attack_method_count,
                    COUNT(DISTINCT source_attack_category) AS attack_category_count
                FROM evaluation_results
                WHERE task_id = ? AND phase = 'red_team'
                """,
                (task_id,),
            ).fetchone()
        finally:
            conn.close()

    if not row:
        empty = _build_metric_block(0, 0, 0, 0, 0.0)
        empty["attack_method_count"] = 0
        empty["attack_category_count"] = 0
        return empty

    total = int(row["total"] or 0)
    success_count = int(row["success_count"] or 0)
    fail_count = int(row["fail_count"] or 0)
    error_count = int(row["error_count"] or 0)
    avg_latency = float(row["avg_latency"] or 0.0)
    payload = _build_metric_block(total, success_count, fail_count, error_count, avg_latency)
    payload["attack_method_count"] = int(row["attack_method_count"] or 0)
    payload["attack_category_count"] = int(row["attack_category_count"] or 0)
    return payload


async def _fetch_all_result_rows(task_id: str) -> List[sqlite3.Row]:
    async with DB_LOCK:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT *
                FROM evaluation_results
                WHERE task_id = ?
                ORDER BY result_index ASC
                """,
                (task_id,),
            ).fetchall()
        finally:
            conn.close()
    return rows


async def init_evaluation_store() -> None:
    db_path = Path(JB_DEMO_EVAL_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    async with DB_LOCK:
        conn = _connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS evaluation_tasks (
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    cancel_requested_at TEXT,
                    dataset_id TEXT NOT NULL,
                    attack_category TEXT NOT NULL,
                    requested_sample_count INTEGER,
                    category_total_count INTEGER,
                    prompts_count INTEGER,
                    total INTEGER NOT NULL DEFAULT 0,
                    completed INTEGER NOT NULL DEFAULT 0,
                    success_count INTEGER NOT NULL DEFAULT 0,
                    fail_count INTEGER NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    request_payload TEXT NOT NULL,
                    config_snapshot TEXT NOT NULL,
                    error_code TEXT,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS evaluation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    result_index INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    seed_prompt TEXT NOT NULL DEFAULT '',
                    source_attack_category TEXT NOT NULL DEFAULT '',
                    attack_method TEXT NOT NULL DEFAULT '',
                    generation_mode TEXT NOT NULL DEFAULT '',
                    prompt TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    eval_type TEXT NOT NULL,
                    response_content TEXT NOT NULL,
                    is_success INTEGER NOT NULL,
                    latency REAL NOT NULL,
                    reasoning_trace TEXT NOT NULL,
                    evaluator_version TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_code TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES evaluation_tasks(task_id)
                );

                CREATE INDEX IF NOT EXISTS idx_eval_results_task_idx
                ON evaluation_results(task_id, result_index);

                CREATE INDEX IF NOT EXISTS idx_eval_tasks_status
                ON evaluation_tasks(status);
                """
            )

            _ensure_column(conn, "evaluation_tasks", "started_at", "TEXT")
            _ensure_column(conn, "evaluation_tasks", "finished_at", "TEXT")
            _ensure_column(conn, "evaluation_tasks", "cancel_requested_at", "TEXT")
            _ensure_column(conn, "evaluation_tasks", "requested_sample_count", "INTEGER")
            _ensure_column(conn, "evaluation_tasks", "category_total_count", "INTEGER")
            _ensure_column(conn, "evaluation_tasks", "prompts_count", "INTEGER")
            _ensure_column(conn, "evaluation_tasks", "total", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "evaluation_tasks", "completed", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "evaluation_tasks", "success_count", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "evaluation_tasks", "fail_count", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "evaluation_tasks", "error_count", "INTEGER NOT NULL DEFAULT 0")
            _ensure_column(conn, "evaluation_tasks", "error_code", "TEXT")
            _ensure_column(conn, "evaluation_tasks", "error_message", "TEXT")
            _ensure_column(conn, "evaluation_results", "seed_prompt", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "evaluation_results", "source_attack_category", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "evaluation_results", "attack_method", "TEXT NOT NULL DEFAULT ''")
            _ensure_column(conn, "evaluation_results", "generation_mode", "TEXT NOT NULL DEFAULT ''")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_eval_results_task_method
                ON evaluation_results(task_id, attack_method)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_eval_results_task_category
                ON evaluation_results(task_id, source_attack_category)
                """
            )

            conn.execute(
                """
                UPDATE evaluation_tasks
                SET
                    status = 'failed',
                    finished_at = ?,
                    error_code = 'TASK_ABORTED_ON_RESTART',
                    error_message = '服务重启，任务未继续执行。请重新创建任务。'
                WHERE status IN ('queued', 'running', 'cancelling')
                """,
                (_now_iso(),),
            )
            conn.commit()
        finally:
            conn.close()


async def create_evaluation_task(req: EvaluationCreateRequest) -> Dict[str, Any]:
    guardrail_target = _resolve_guardrail_target(req) if req.include_guardrail else ""
    guardrail_evaluator = _resolve_guardrail_evaluator(req) if req.include_guardrail else ""
    attack_methods = []
    seen = set()
    for item in req.attack_methods:
        method = str(item).strip()
        if method and method not in seen:
            attack_methods.append(method)
            seen.add(method)

    for method in attack_methods:
        try:
            ensure_attack_method_target_supported(
                method,
                req.target,
                require_whitebox_ready=True,
            )
        except AttackConfigError as exc:
            raise AppError(
                code=exc.code,
                message=str(exc),
                status_code=400,
                details={
                    "method": method,
                    "target": req.target,
                },
            ) from exc

    request_payload = {
        "dataset_id": req.dataset_id,
        "attack_category": req.attack_category,
        "sample_count": req.sample_count,
        "target": req.target,
        "evaluator": req.evaluator,
        "attack_methods": attack_methods,
        "generated_prompt_count_per_seed": int(req.generated_prompt_count_per_seed),
        "include_guardrail": bool(req.include_guardrail),
        "guardrail_target": guardrail_target,
        "guardrail_evaluator": guardrail_evaluator,
        "metadata": req.metadata,
    }
    config_snapshot = _build_config_snapshot(
        req.target,
        bool(req.include_guardrail),
        guardrail_target,
        attack_methods,
        int(req.generated_prompt_count_per_seed),
    )

    task_id = uuid4().hex
    created_at = _now_iso()

    async with DB_LOCK:
        conn = _connect()
        try:
            running_row = conn.execute(
                "SELECT COUNT(1) AS cnt FROM evaluation_tasks WHERE status IN ('queued','running','cancelling')"
            ).fetchone()
            running_count = int(running_row["cnt"] if running_row else 0)
            if running_count >= JB_DEMO_MAX_CONCURRENT_BATCH_TASKS:
                raise AppError(
                    code="EVAL_CONCURRENCY_LIMIT",
                    message="统一评估任务并发已达上限，请稍后重试。",
                    status_code=429,
                    details={
                        "max_concurrent": JB_DEMO_MAX_CONCURRENT_BATCH_TASKS,
                        "running": running_count,
                    },
                )

            conn.execute(
                """
                INSERT INTO evaluation_tasks (
                    task_id, status, created_at, dataset_id, attack_category,
                    requested_sample_count, request_payload, config_snapshot
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    "queued",
                    created_at,
                    req.dataset_id,
                    req.attack_category,
                    req.sample_count,
                    _json_dumps(request_payload),
                    _json_dumps(config_snapshot),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    cancel_event = asyncio.Event()
    async with ACTIVE_TASKS_LOCK:
        ACTIVE_TASKS[task_id] = {
            "task_id": task_id,
            "cancel_event": cancel_event,
            "runner": None,
        }
    runner = asyncio.create_task(_run_evaluation_task(task_id, request_payload, cancel_event))
    async with ACTIVE_TASKS_LOCK:
        runtime = ACTIVE_TASKS.get(task_id)
        if runtime is not None:
            runtime["runner"] = runner

    return {
        "task_id": task_id,
        "task_status": "queued",
        "created_at": created_at,
        "request_payload": request_payload,
    }


async def _build_generation_error_result(
    *,
    seed_prompt: str,
    error_code: str,
    error_message: str,
    note: str,
) -> Dict[str, Any]:
    message = error_message.strip() or "攻击提示词生成失败。"
    note_text = note.strip()
    reasoning = message if not note_text else f"{message}\n{note_text}"
    return {
        "prompt": seed_prompt[:100] + "..." if len(seed_prompt) > 100 else seed_prompt,
        "target_type": "",
        "eval_type": "",
        "response_content": "",
        "is_success": False,
        "latency": 0.0,
        "reasoning_trace": reasoning,
        "evaluator_version": "",
        "model_name": "",
        "status": "error",
        "error_code": error_code,
        "error_message": message,
    }


async def _evaluate_and_store_result(
    *,
    task_id: str,
    result_index: int,
    phase: str,
    target: str,
    evaluator: str,
    prompt: str,
    seed_prompt: str,
    source_attack_category: str,
    attack_method: str,
    generation_mode: str,
) -> Dict[str, Any]:
    result = await evaluate_single_prompt(prompt, target, evaluator)
    await _insert_result(
        task_id=task_id,
        result_index=result_index,
        phase=phase,
        prompt=prompt,
        target=target,
        evaluator=evaluator,
        result=result,
        seed_prompt=seed_prompt,
        source_attack_category=source_attack_category,
        attack_method=attack_method,
        generation_mode=generation_mode,
    )
    return result


async def _store_synthetic_error(
    *,
    task_id: str,
    result_index: int,
    phase: str,
    target: str,
    evaluator: str,
    seed_prompt: str,
    source_attack_category: str,
    attack_method: str,
    generation_mode: str,
    error_code: str,
    error_message: str,
    note: str,
) -> Dict[str, Any]:
    result = await _build_generation_error_result(
        seed_prompt=seed_prompt,
        error_code=error_code,
        error_message=error_message,
        note=note,
    )
    await _insert_result(
        task_id=task_id,
        result_index=result_index,
        phase=phase,
        prompt="",
        target=target,
        evaluator=evaluator,
        result=result,
        seed_prompt=seed_prompt,
        source_attack_category=source_attack_category,
        attack_method=attack_method,
        generation_mode=generation_mode,
    )
    return result


async def _run_evaluation_task(
    task_id: str,
    request_payload: Dict[str, Any],
    cancel_event: asyncio.Event,
) -> None:
    try:
        await _update_task(task_id, status="running", started_at=_now_iso())

        dataset_id = str(request_payload["dataset_id"])
        attack_category = str(request_payload["attack_category"])
        prompt_entries_all = load_dataset_entries(dataset_id, None, attack_category)
        category_total = len(prompt_entries_all)
        sample_count = request_payload.get("sample_count")
        requested_sample_count = int(sample_count) if sample_count is not None else category_total
        prompt_entries = (
            prompt_entries_all[:requested_sample_count] if sample_count is not None else prompt_entries_all
        )

        execution_plan = _resolve_execution_plan(request_payload)
        attack_methods = _normalize_attack_methods(request_payload)
        generated_prompt_count = max(1, int(request_payload.get("generated_prompt_count_per_seed") or 1))

        if attack_methods:
            total = len(prompt_entries) * len(attack_methods) * generated_prompt_count * len(execution_plan)
        else:
            total = len(prompt_entries) * len(execution_plan)

        await _update_task(
            task_id,
            category_total_count=category_total,
            prompts_count=len(prompt_entries),
            requested_sample_count=requested_sample_count,
            total=total,
            completed=0,
            success_count=0,
            fail_count=0,
            error_count=0,
        )

        if total == 0:
            await _update_task(task_id, status="completed", finished_at=_now_iso())
            return

        completed = 0
        success_count = 0
        fail_count = 0
        error_count = 0

        api_config = GLOBAL_SETTINGS.get("api", {})
        api_key = api_config.get("api_key", "")
        model_name = api_config.get("model", "gpt-4")
        api_base = api_config.get("api_base", "https://api.openai.com/v1")

        for prompt_entry in prompt_entries:
            seed_prompt = str(prompt_entry["prompt"])
            source_attack_category = str(prompt_entry.get("attack_category") or attack_category)

            attack_method_list = attack_methods or [DIRECT_PROMPT_METHOD]
            for attack_method in attack_method_list:
                if cancel_event.is_set():
                    await _update_task(task_id, status="cancelled", finished_at=_now_iso())
                    return

                generation_mode = "direct_prompt"
                generated_prompts: List[str] = [seed_prompt]
                generation_error_code = ""
                generation_error_message = ""
                generation_note = ""

                if attack_method != DIRECT_PROMPT_METHOD:
                    generation_result = await generate_adversarial_prompts(
                        seed_prompt=seed_prompt,
                        method=attack_method,
                        count=generated_prompt_count,
                        api_key=api_key,
                        model_name=model_name,
                        api_base=api_base,
                    )
                    generation_mode = str(generation_result.get("generation_mode") or "generation_failed")
                    generation_error_code = str(generation_result.get("error_code") or "")
                    generation_error_message = str(generation_result.get("error") or "")
                    generation_note = str(generation_result.get("note") or "")
                    if generation_result.get("success"):
                        generated_prompts = [
                            str(item.get("prompt", ""))
                            for item in generation_result.get("prompts", [])
                            if str(item.get("prompt", "")).strip()
                        ]
                    else:
                        generated_prompts = []

                expected_prompt_count = generated_prompt_count if attack_method != DIRECT_PROMPT_METHOD else 1
                for prompt_slot in range(expected_prompt_count):
                    generated_prompt = generated_prompts[prompt_slot] if prompt_slot < len(generated_prompts) else ""
                    for phase, target, evaluator in execution_plan:
                        if cancel_event.is_set():
                            await _update_task(task_id, status="cancelled", finished_at=_now_iso())
                            return

                        if generated_prompt:
                            result = await _evaluate_and_store_result(
                                task_id=task_id,
                                result_index=completed,
                                phase=phase,
                                target=target,
                                evaluator=evaluator,
                                prompt=generated_prompt,
                                seed_prompt=seed_prompt,
                                source_attack_category=source_attack_category,
                                attack_method=attack_method,
                                generation_mode=generation_mode,
                            )
                        else:
                            result = await _store_synthetic_error(
                                task_id=task_id,
                                result_index=completed,
                                phase=phase,
                                target=target,
                                evaluator=evaluator,
                                seed_prompt=seed_prompt,
                                source_attack_category=source_attack_category,
                                attack_method=attack_method,
                                generation_mode=generation_mode,
                                error_code=generation_error_code or "ATTACK_GENERATION_FAILED",
                                error_message=generation_error_message or f"攻击方法 {attack_method} 未生成有效提示词。",
                                note=generation_note,
                            )

                        result_status = str(result.get("status", "ok"))
                        is_success = bool(result.get("is_success", False))

                        if result_status != "ok":
                            error_count += 1
                        elif is_success:
                            success_count += 1
                        else:
                            fail_count += 1

                        completed += 1
                        await _update_task(
                            task_id,
                            completed=completed,
                            success_count=success_count,
                            fail_count=fail_count,
                            error_count=error_count,
                        )

        await _update_task(task_id, status="completed", finished_at=_now_iso())

    except CategoryIndexMissingError as exc:
        await _update_task(
            task_id,
            status="failed",
            finished_at=_now_iso(),
            error_code="CATEGORY_INDEX_MISSING",
            error_message=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        await _update_task(
            task_id,
            status="failed",
            finished_at=_now_iso(),
            error_code="EVALUATION_TASK_FAILED",
            error_message=str(exc),
        )
    finally:
        async with ACTIVE_TASKS_LOCK:
            ACTIVE_TASKS.pop(task_id, None)


async def get_evaluation_task(task_id: str) -> Dict[str, Any]:
    row = await _fetch_task_row(task_id)
    if not row:
        raise AppError(
            code="TASK_NOT_FOUND",
            message=f"找不到任务: {task_id}",
            status_code=404,
        )

    payload = _task_row_to_payload(row)
    payload["phase_summary"] = await _load_phase_summary(task_id)
    payload["summary_metrics"] = await _load_summary_metrics(task_id)
    payload["by_attack_method"] = await _load_group_summary(task_id, "attack_method")
    payload["by_attack_category"] = await _load_group_summary(task_id, "source_attack_category")
    return payload


async def get_evaluation_results(task_id: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
    if offset < 0:
        raise AppError(
            code="INVALID_PAGINATION",
            message="offset 不能小于 0。",
            status_code=422,
        )

    safe_limit = max(1, min(limit, JB_DEMO_EVAL_RESULTS_PAGE_LIMIT))
    task = await get_evaluation_task(task_id)

    async with DB_LOCK:
        conn = _connect()
        try:
            count_row = conn.execute(
                "SELECT COUNT(1) AS cnt FROM evaluation_results WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            rows = conn.execute(
                """
                SELECT *
                FROM evaluation_results
                WHERE task_id = ?
                ORDER BY result_index ASC
                LIMIT ? OFFSET ?
                """,
                (task_id, safe_limit, offset),
            ).fetchall()
        finally:
            conn.close()

    total_results = int(count_row["cnt"] if count_row else 0)
    results: List[Dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "index": int(row["result_index"]),
                "phase": row["phase"],
                "seed_prompt": row["seed_prompt"] or "",
                "source_attack_category": row["source_attack_category"] or "",
                "attack_method": row["attack_method"] or "",
                "generation_mode": row["generation_mode"] or "",
                "prompt": row["prompt"],
                "target_type": row["target_type"],
                "eval_type": row["eval_type"],
                "response_content": row["response_content"],
                "is_success": bool(row["is_success"]),
                "latency": float(row["latency"] or 0.0),
                "reasoning_trace": row["reasoning_trace"],
                "evaluator_version": row["evaluator_version"],
                "model_name": row["model_name"],
                "status": row["status"],
                "error_code": row["error_code"] or "",
                "error_message": row["error_message"] or "",
                "created_at": row["created_at"],
            }
        )

    return {
        "task_id": task_id,
        "task_status": task["status"],
        "offset": offset,
        "limit": safe_limit,
        "total_results": total_results,
        "has_more": (offset + len(results)) < total_results,
        "summary": task["summary"],
        "summary_metrics": task.get("summary_metrics", {}),
        "phase_summary": task.get("phase_summary", {}),
        "by_attack_method": task.get("by_attack_method", []),
        "by_attack_category": task.get("by_attack_category", []),
        "results": results,
    }


async def export_evaluation_results(task_id: str, export_format: str = "json") -> Dict[str, Any]:
    export_key = export_format.strip().lower()
    if export_key not in {"json", "csv", "markdown"}:
        raise AppError(
            code="INVALID_EXPORT_FORMAT",
            message="仅支持 json / csv / markdown 导出。",
            status_code=422,
        )

    task = await get_evaluation_task(task_id)
    rows = await _fetch_all_result_rows(task_id)
    flat_results: List[Dict[str, Any]] = []
    for row in rows:
        flat_results.append(
            {
                "index": int(row["result_index"]),
                "phase": row["phase"],
                "seed_prompt": row["seed_prompt"] or "",
                "source_attack_category": row["source_attack_category"] or "",
                "attack_method": row["attack_method"] or "",
                "generation_mode": row["generation_mode"] or "",
                "prompt": row["prompt"],
                "target_type": row["target_type"],
                "eval_type": row["eval_type"],
                "response_content": row["response_content"],
                "is_success": bool(row["is_success"]),
                "latency": float(row["latency"] or 0.0),
                "reasoning_trace": row["reasoning_trace"],
                "evaluator_version": row["evaluator_version"],
                "model_name": row["model_name"],
                "status": row["status"],
                "error_code": row["error_code"] or "",
                "error_message": row["error_message"] or "",
                "created_at": row["created_at"],
            }
        )

    payload = {
        "task": task,
        "summary_metrics": task.get("summary_metrics", {}),
        "by_attack_method": task.get("by_attack_method", []),
        "by_attack_category": task.get("by_attack_category", []),
        "results": flat_results,
    }

    if export_key == "json":
        content = json.dumps(payload, ensure_ascii=False, indent=2)
        return {
            "filename": f"evaluation_{task_id}.json",
            "media_type": "application/json; charset=utf-8",
            "content": content.encode("utf-8"),
        }

    if export_key == "csv":
        output = io.StringIO()
        fieldnames = [
            "index",
            "phase",
            "seed_prompt",
            "source_attack_category",
            "attack_method",
            "generation_mode",
            "prompt",
            "target_type",
            "eval_type",
            "response_content",
            "is_success",
            "latency",
            "reasoning_trace",
            "evaluator_version",
            "model_name",
            "status",
            "error_code",
            "error_message",
            "created_at",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for item in flat_results:
            writer.writerow(item)
        return {
            "filename": f"evaluation_{task_id}.csv",
            "media_type": "text/csv; charset=utf-8",
            "content": output.getvalue().encode("utf-8"),
        }

    lines = [
        f"# Evaluation Report `{task_id}`",
        "",
        "## Summary Metrics",
        "",
        f"- samples_evaluated: {task.get('summary_metrics', {}).get('samples_evaluated', 0)}",
        f"- attack_success_rate: {task.get('summary_metrics', {}).get('attack_success_rate', 0.0)}",
        f"- refusal_rate: {task.get('summary_metrics', {}).get('refusal_rate', 0.0)}",
        f"- error_rate: {task.get('summary_metrics', {}).get('error_rate', 0.0)}",
        f"- avg_latency: {task.get('summary_metrics', {}).get('avg_latency', 0.0)}",
        "",
        "## By Attack Method",
        "",
        "| method | samples | success_rate | refusal_rate | error_rate | avg_latency |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in task.get("by_attack_method", []):
        lines.append(
            f"| {item.get('key', '')} | {item.get('samples_evaluated', 0)} | {item.get('attack_success_rate', 0.0)} | {item.get('refusal_rate', 0.0)} | {item.get('error_rate', 0.0)} | {item.get('avg_latency', 0.0)} |"
        )

    lines.extend(
        [
            "",
            "## By Attack Category",
            "",
            "| category | samples | success_rate | refusal_rate | error_rate | avg_latency |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for item in task.get("by_attack_category", []):
        lines.append(
            f"| {item.get('key', '')} | {item.get('samples_evaluated', 0)} | {item.get('attack_success_rate', 0.0)} | {item.get('refusal_rate', 0.0)} | {item.get('error_rate', 0.0)} | {item.get('avg_latency', 0.0)} |"
        )

    lines.extend(["", "## Result Count", "", f"- total_rows: {len(flat_results)}", ""])
    return {
        "filename": f"evaluation_{task_id}.md",
        "media_type": "text/markdown; charset=utf-8",
        "content": "\n".join(lines).encode("utf-8"),
    }


async def cancel_evaluation_task(task_id: str) -> Dict[str, Any]:
    row = await _fetch_task_row(task_id)
    if not row:
        raise AppError(
            code="TASK_NOT_FOUND",
            message=f"找不到任务: {task_id}",
            status_code=404,
        )

    status = str(row["status"])
    if status in TERMINAL_STATUSES:
        raise AppError(
            code="TASK_NOT_CANCELLABLE",
            message="任务已结束，无法取消。",
            status_code=409,
            details={"task_id": task_id, "status": status},
        )

    await _update_task(task_id, status="cancelling", cancel_requested_at=_now_iso())

    async with ACTIVE_TASKS_LOCK:
        runtime = ACTIVE_TASKS.get(task_id)
    if runtime:
        cancel_event = runtime.get("cancel_event")
        if isinstance(cancel_event, asyncio.Event):
            cancel_event.set()

    return {
        "status": "ok",
        "task_id": task_id,
        "task_status": "cancelling",
    }
