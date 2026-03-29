import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth_jwt import require_jwt_auth
from app.config import ATTACK_CATEGORIES, JB_DEMO_EVAL_DB_PATH
from app.services.dataset import get_dataset_info, load_dataset

router = APIRouter()


class RedteamDataset(BaseModel):
    id: str
    name: str
    description: str
    count: int


class RedteamPromptExample(BaseModel):
    id: str
    title: str
    prompt: str
    category: str


class RedteamRunningTask(BaseModel):
    id: str
    datasetId: str
    status: Literal["queued", "running", "done", "failed"]
    progress: int
    startedAt: str


class RedteamResult(BaseModel):
    id: str
    taskId: str
    score: float
    summary: str
    createdAt: str


class RedteamOverview(BaseModel):
    datasets: List[RedteamDataset]
    promptExamples: List[RedteamPromptExample]
    runningTasks: List[RedteamRunningTask]
    recentResults: List[RedteamResult]


STATUS_MAP = {
    "queued": "queued",
    "running": "running",
    "cancelling": "running",
    "completed": "done",
    "failed": "failed",
    "cancelled": "failed",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_iso(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        return value
    return _now_iso()


def _connect_eval_db() -> sqlite3.Connection | None:
    db_path = Path(JB_DEMO_EVAL_DB_PATH)
    if not db_path.exists():
        return None
    conn = sqlite3.connect(str(db_path), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _fetch_task_rows(limit: int = 80) -> List[Dict[str, Any]]:
    conn = _connect_eval_db()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            """
            SELECT
                task_id,
                dataset_id,
                status,
                created_at,
                started_at,
                finished_at,
                total,
                completed,
                success_count,
                fail_count,
                error_count
            FROM evaluation_tasks
            ORDER BY COALESCE(started_at, created_at) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(row) for row in rows]


def _build_prompt_examples(datasets: List[Dict[str, Any]], max_examples: int = 24) -> List[RedteamPromptExample]:
    category_name_map = {
        str(item["id"]): str(item["name"])
        for item in ATTACK_CATEGORIES
        if str(item["id"]) != "mixed_all"
    }
    examples: List[RedteamPromptExample] = []
    next_id = 1

    for ds in datasets:
        ds_id = str(ds.get("id", ""))
        category_counts = ds.get("category_counts", {}) if isinstance(ds, dict) else {}
        if not ds_id:
            continue

        for category_id, category_name in category_name_map.items():
            cnt = category_counts.get(category_id) if isinstance(category_counts, dict) else None
            if cnt in (None, 0):
                continue
            try:
                prompts = load_dataset(ds_id, sample_count=1, attack_category=category_id)
            except Exception:  # noqa: BLE001
                continue
            if not prompts:
                continue

            examples.append(
                RedteamPromptExample(
                    id=f"pe_{next_id:03d}",
                    title=f"{ds_id} · {category_name}",
                    prompt=str(prompts[0]),
                    category=category_name,
                )
            )
            next_id += 1
            if len(examples) >= max_examples:
                return examples

    if len(examples) >= max_examples:
        return examples

    for ds in datasets:
        ds_id = str(ds.get("id", ""))
        if not ds_id:
            continue
        try:
            prompts = load_dataset(ds_id, sample_count=3, attack_category="mixed_all")
        except Exception:  # noqa: BLE001
            continue
        for i, prompt in enumerate(prompts, start=1):
            examples.append(
                RedteamPromptExample(
                    id=f"pe_{next_id:03d}",
                    title=f"{ds_id} · mixed #{i}",
                    prompt=str(prompt),
                    category="mixed_all",
                )
            )
            next_id += 1
            if len(examples) >= max_examples:
                return examples
    return examples


def _build_running_tasks(rows: List[Dict[str, Any]], max_items: int = 40) -> List[RedteamRunningTask]:
    tasks: List[RedteamRunningTask] = []
    for row in rows:
        status_raw = str(row.get("status", "")).strip().lower()
        status = STATUS_MAP.get(status_raw, "failed")
        total = int(row.get("total") or 0)
        completed = int(row.get("completed") or 0)
        if status == "done":
            progress = 100
        elif total > 0:
            progress = max(0, min(100, int(round((completed / total) * 100))))
        else:
            progress = 0

        tasks.append(
            RedteamRunningTask(
                id=str(row.get("task_id", "")),
                datasetId=str(row.get("dataset_id", "")),
                status=status,
                progress=progress,
                startedAt=_safe_iso(row.get("started_at") or row.get("created_at")),
            )
        )
        if len(tasks) >= max_items:
            break
    return tasks


def _build_recent_results(rows: List[Dict[str, Any]], max_items: int = 24) -> List[RedteamResult]:
    results: List[RedteamResult] = []
    for row in rows:
        task_id = str(row.get("task_id", "")).strip()
        if not task_id:
            continue
        total = int(row.get("total") or 0)
        success = int(row.get("success_count") or 0)
        fail_count = int(row.get("fail_count") or 0)
        error_count = int(row.get("error_count") or 0)
        status_raw = str(row.get("status", "")).strip().lower()
        status = STATUS_MAP.get(status_raw, "failed")

        score = round((success / total), 4) if total > 0 else 0.0
        summary = (
            f"状态 {status}，总计 {total}，攻击成功 {success}，"
            f"攻击失败 {fail_count}，错误 {error_count}"
        )

        results.append(
            RedteamResult(
                id=f"rr_{task_id[:8]}",
                taskId=task_id,
                score=score,
                summary=summary,
                createdAt=_safe_iso(row.get("finished_at") or row.get("created_at")),
            )
        )
        if len(results) >= max_items:
            break
    return results


@router.get("/redteam/overview", response_model=RedteamOverview)
async def redteam_overview(_: Dict[str, Any] = Depends(require_jwt_auth)):
    dataset_payload = get_dataset_info()
    datasets_raw = dataset_payload.get("datasets", []) if isinstance(dataset_payload, dict) else []

    datasets: List[RedteamDataset] = []
    for item in datasets_raw:
        if not isinstance(item, dict):
            continue
        datasets.append(
            RedteamDataset(
                id=str(item.get("id", "")),
                name=str(item.get("name", "")),
                description=str(item.get("description", "")),
                count=int(item.get("count") or 0),
            )
        )

    task_rows = _fetch_task_rows(limit=80)
    return RedteamOverview(
        datasets=datasets,
        promptExamples=_build_prompt_examples(datasets_raw),
        runningTasks=_build_running_tasks(task_rows),
        recentResults=_build_recent_results(task_rows),
    )
