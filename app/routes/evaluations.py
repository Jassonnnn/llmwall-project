from fastapi import APIRouter, Depends, Query, Response

from app.auth import require_service_auth
from app.models import EvaluationCreateRequest
from app.services.evaluation_tasks import (
    cancel_evaluation_task,
    create_evaluation_task,
    export_evaluation_results,
    get_evaluation_results,
    get_evaluation_task,
)

router = APIRouter()


@router.post("/evaluations", dependencies=[Depends(require_service_auth)])
async def create_evaluation(req: EvaluationCreateRequest):
    created = await create_evaluation_task(req)
    return {
        "status": "ok",
        "task_id": created["task_id"],
        "task_status": created["task_status"],
        "created_at": created["created_at"],
        "request_payload": created["request_payload"],
    }


@router.get("/evaluations/{task_id}", dependencies=[Depends(require_service_auth)])
async def get_evaluation(task_id: str):
    task = await get_evaluation_task(task_id)
    return {
        "status": "ok",
        "task": task,
    }


@router.get("/evaluations/{task_id}/results", dependencies=[Depends(require_service_auth)])
async def get_evaluation_task_results(
    task_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1),
):
    payload = await get_evaluation_results(task_id=task_id, offset=offset, limit=limit)
    return {
        "status": "ok",
        **payload,
    }


@router.get("/evaluations/{task_id}/export", dependencies=[Depends(require_service_auth)])
async def export_evaluation_task_results(
    task_id: str,
    format: str = Query(default="json"),
):
    exported = await export_evaluation_results(task_id=task_id, export_format=format)
    return Response(
        content=exported["content"],
        media_type=exported["media_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{exported["filename"]}"',
        },
    )


@router.post("/evaluations/{task_id}/cancel", dependencies=[Depends(require_service_auth)])
async def cancel_evaluation(task_id: str):
    return await cancel_evaluation_task(task_id)
