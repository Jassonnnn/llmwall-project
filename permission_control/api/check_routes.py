"""权限校验相关路由"""

from fastapi import APIRouter, Depends, HTTPException

from data.permission_controller import PermissionController
from main import get_permission_controller

from .schemas import ChatQueryRequest, ChatQueryResponse


router = APIRouter()


@router.post("/check_query", response_model=ChatQueryResponse, summary="执行权限检查")
async def check_query(
    request: ChatQueryRequest,
    controller: PermissionController = Depends(get_permission_controller),
):
    """调用 PermissionController 执行权限判断"""

    try:
        result = await controller.check_query(
            tenant_id=request.tenant_id,
            user_id=request.user_id,
            query=request.query,
            conversation_history=request.conversation_history,
        )
    except Exception as exc:  # pragma: no cover - FastAPI 会记录日志
        raise HTTPException(status_code=500, detail=f"权限检查失败: {exc}") from exc

    return ChatQueryResponse(
        decision=result.get("decision", "DENY"),
        rewritten_query=result.get("rewritten_query"),
        reason=result.get("reason"),
        opa_result=result.get("opa_result"),
    )
