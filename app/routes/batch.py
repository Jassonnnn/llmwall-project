import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.auth import require_service_auth
from app.config import BATCH_TASKS, JB_DEMO_MAX_CONCURRENT_BATCH_TASKS
from app.errors import AppError, error_payload
from app.models import BatchEvalRequest
from app.services.dataset import CategoryIndexMissingError, get_dataset_info, load_dataset
from app.services.evaluator import evaluate_single_prompt

router = APIRouter()
TASK_LOCK = asyncio.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sse(data: Dict[str, Any]) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


async def _update_task(task_id: str, **fields: Any) -> None:
    async with TASK_LOCK:
        task = BATCH_TASKS.get(task_id)
        if not task:
            return
        task.update(fields)


async def _running_task_count() -> int:
    async with TASK_LOCK:
        return sum(
            1
            for task in BATCH_TASKS.values()
            if task.get("status") in {"queued", "running", "cancelling"}
        )


def _error_event(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = error_payload(code=code, message=message, details=details)
    payload["type"] = "error"
    return payload


@router.get("/datasets")
async def list_datasets():
    return get_dataset_info()


@router.post("/batch_evaluate", dependencies=[Depends(require_service_auth)])
async def batch_evaluate(req: BatchEvalRequest, request: Request):
    """启动批量评估，返回SSE流"""
    running_count = await _running_task_count()
    if running_count >= JB_DEMO_MAX_CONCURRENT_BATCH_TASKS:
        raise AppError(
            code="BATCH_CONCURRENCY_LIMIT",
            message="并发批量评估任务数已达上限，请稍后重试。",
            status_code=429,
            details={
                "max_concurrent": JB_DEMO_MAX_CONCURRENT_BATCH_TASKS,
                "running": running_count,
            },
        )

    task_id = uuid4().hex
    cancel_event = asyncio.Event()
    async with TASK_LOCK:
        BATCH_TASKS[task_id] = {
            "task_id": task_id,
            "status": "queued",
            "created_at": _now_iso(),
            "cancel_event": cancel_event,
            "dataset_id": req.dataset_id,
            "attack_category": req.attack_category,
            "target": req.target,
            "evaluator": req.evaluator,
        }

    async def generate():
        status_marked = False
        try:
            await _update_task(task_id, status="running", started_at=_now_iso())
            status_marked = True

            # 先按分类过滤，再按条数截取
            category_prompts = load_dataset(req.dataset_id, None, req.attack_category)
            category_total = len(category_prompts)
            requested_sample_count = req.sample_count if req.sample_count is not None else category_total
            prompts = category_prompts[:requested_sample_count] if req.sample_count is not None else category_prompts
            total = len(prompts)

            # 确定要运行的组合
            targets = ['api', 'local'] if req.target == 'all' else [req.target]
            evaluators = ['keyword', 'llm_judge'] if req.evaluator == 'all' else [req.evaluator]

            combinations = [(t, e) for t in targets for e in evaluators]
            total_tasks = total * len(combinations)

            # 初始化统计
            stats = {
                "total": total_tasks,
                "completed": 0,
                "success_count": 0,  # 攻击成功（拦截失败）
                "fail_count": 0,     # 攻击失败（拦截成功）
                "error_count": 0,
                "results": []
            }

            # 发送初始状态
            init_data = {
                'type': 'init',
                'task_id': task_id,
                'total': total_tasks,
                'prompts_count': total,
                'combinations': len(combinations),
                'requested_sample_count': requested_sample_count,
                'category_total_count': category_total,
            }
            yield _sse(init_data)

            if total_tasks == 0:
                final_data = {
                    "type": "complete",
                    "task_id": task_id,
                    "total": 0,
                    "success_count": 0,
                    "fail_count": 0,
                    "error_count": 0,
                    "success_rate": 0,
                    "results": []
                }
                yield _sse(final_data)
                await _update_task(task_id, status="completed", finished_at=_now_iso())
                return

            # 逐个评估
            for prompt in prompts:
                for target, evaluator in combinations:
                    if await request.is_disconnected():
                        cancel_event.set()

                    if cancel_event.is_set():
                        cancelled_data = {
                            "type": "cancelled",
                            "task_id": task_id,
                            "completed": stats["completed"],
                            "total": stats["total"],
                            "message": "批量评估已取消。",
                        }
                        yield _sse(cancelled_data)
                        await _update_task(task_id, status="cancelled", finished_at=_now_iso())
                        return

                    try:
                        result = await evaluate_single_prompt(prompt, target, evaluator)
                        result["index"] = stats["completed"]

                        if result["is_success"]:
                            stats["success_count"] += 1
                        else:
                            stats["fail_count"] += 1

                        stats["results"].append(result)

                    except Exception as e:
                        stats["error_count"] += 1
                        result = {
                            "index": stats["completed"],
                            "prompt": prompt[:100],
                            "target_type": target,
                            "eval_type": evaluator,
                            "error": str(e),
                            "is_success": False
                        }
                        stats["results"].append(result)

                    stats["completed"] += 1

                    # 发送进度更新
                    progress_data = {
                        "type": "progress",
                        "task_id": task_id,
                        "completed": stats["completed"],
                        "total": stats["total"],
                        "success_count": stats["success_count"],
                        "fail_count": stats["fail_count"],
                        "error_count": stats["error_count"],
                        "progress_percent": round(stats["completed"] / stats["total"] * 100, 1),
                        "current_result": result
                    }
                    yield _sse(progress_data)

                    # 小延迟避免过快
                    await asyncio.sleep(0.1)

            # 发送完成状态
            final_data = {
                "type": "complete",
                "task_id": task_id,
                "total": stats["total"],
                "success_count": stats["success_count"],
                "fail_count": stats["fail_count"],
                "error_count": stats["error_count"],
                "success_rate": round(stats["success_count"] / stats["total"] * 100, 2) if stats["total"] > 0 else 0,
                "results": stats["results"][-20:]  # 只返回最后20条详细结果
            }
            yield _sse(final_data)
            await _update_task(task_id, status="completed", finished_at=_now_iso())

        except CategoryIndexMissingError as e:
            yield _sse(_error_event("CATEGORY_INDEX_MISSING", str(e), {"task_id": task_id}))
            await _update_task(task_id, status="failed", finished_at=_now_iso())
        except Exception as e:
            yield _sse(_error_event("BATCH_EVAL_FAILED", str(e), {"task_id": task_id}))
            await _update_task(task_id, status="failed", finished_at=_now_iso())
        finally:
            if status_marked and cancel_event.is_set():
                async with TASK_LOCK:
                    task = BATCH_TASKS.get(task_id)
                    if task and task.get("status") == "running":
                        task["status"] = "cancelled"
                        task["finished_at"] = _now_iso()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "X-Batch-Task-Id": task_id,
        },
    )


@router.post("/batch_cancel/{task_id}", dependencies=[Depends(require_service_auth)])
async def cancel_batch_task(task_id: str):
    async with TASK_LOCK:
        task = BATCH_TASKS.get(task_id)
        if not task:
            raise AppError(
                code="TASK_NOT_FOUND",
                message=f"找不到任务: {task_id}",
                status_code=404,
            )

        status = str(task.get("status", ""))
        if status in {"completed", "failed", "cancelled"}:
            raise AppError(
                code="TASK_NOT_CANCELLABLE",
                message="任务已结束，无法取消。",
                status_code=409,
                details={"task_id": task_id, "status": status},
            )

        cancel_event = task.get("cancel_event")
        if isinstance(cancel_event, asyncio.Event):
            cancel_event.set()
        task["status"] = "cancelling"
        task["cancel_requested_at"] = _now_iso()

    return {
        "status": "ok",
        "task_id": task_id,
        "task_status": "cancelling",
    }
