import asyncio
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
from app.services.dataset import CategoryIndexMissingError, load_dataset
from app.services.evaluator import evaluate_single_prompt

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}

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


def _build_config_snapshot(target: str, include_guardrail: bool, guardrail_target: str) -> Dict[str, Any]:
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
            "fail_count": int(row["fail_count"] or 0),
            "error_count": int(row["error_count"] or 0),
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
) -> None:
    async with DB_LOCK:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO evaluation_results (
                    task_id, result_index, phase, prompt, target_type, eval_type, response_content,
                    is_success, latency, reasoning_trace, evaluator_version, model_name, status,
                    error_code, error_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    result_index,
                    phase,
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
                    SUM(CASE WHEN is_success = 1 THEN 1 ELSE 0 END) AS success_count,
                    SUM(CASE WHEN is_success = 0 THEN 1 ELSE 0 END) AS fail_count,
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

    request_payload = {
        "dataset_id": req.dataset_id,
        "attack_category": req.attack_category,
        "sample_count": req.sample_count,
        "target": req.target,
        "evaluator": req.evaluator,
        "include_guardrail": bool(req.include_guardrail),
        "guardrail_target": guardrail_target,
        "guardrail_evaluator": guardrail_evaluator,
        "metadata": req.metadata,
    }
    config_snapshot = _build_config_snapshot(
        req.target,
        bool(req.include_guardrail),
        guardrail_target,
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


async def _run_evaluation_task(
    task_id: str,
    request_payload: Dict[str, Any],
    cancel_event: asyncio.Event,
) -> None:
    try:
        await _update_task(task_id, status="running", started_at=_now_iso())

        prompts_all = load_dataset(
            str(request_payload["dataset_id"]),
            None,
            str(request_payload["attack_category"]),
        )
        category_total = len(prompts_all)
        sample_count = request_payload.get("sample_count")
        requested_sample_count = int(sample_count) if sample_count is not None else category_total
        prompts = prompts_all[:requested_sample_count] if sample_count is not None else prompts_all

        execution_plan = _resolve_execution_plan(request_payload)
        total = len(prompts) * len(execution_plan)

        await _update_task(
            task_id,
            category_total_count=category_total,
            prompts_count=len(prompts),
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

        for prompt in prompts:
            for phase, target, evaluator in execution_plan:
                if cancel_event.is_set():
                    await _update_task(task_id, status="cancelled", finished_at=_now_iso())
                    return

                result = await evaluate_single_prompt(prompt, target, evaluator)

                result_status = str(result.get("status", "ok"))
                is_success = bool(result.get("is_success", False))

                if result_status != "ok":
                    error_count += 1
                elif is_success:
                    success_count += 1
                else:
                    fail_count += 1

                await _insert_result(
                    task_id=task_id,
                    result_index=completed,
                    phase=phase,
                    prompt=prompt,
                    target=target,
                    evaluator=evaluator,
                    result=result,
                )

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
        "phase_summary": task.get("phase_summary", {}),
        "results": results,
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
