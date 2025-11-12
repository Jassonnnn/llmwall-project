"""权限校验相关路由"""

import httpx
from fastapi import APIRouter, Depends, HTTPException

from data.permission_controller import PermissionController
from main import get_permission_controller

from .schemas import ChatQueryRequest, ChatQueryResponse


router = APIRouter()

_JAILBREAK_ENDPOINT = "http://127.0.0.1:11514/check_input"
_JAILBREAK_PARAMS = {"detect_jailbreak": {"on_fail": "exception"}}


async def _run_jailbreak_guard(text: str) -> dict:
    """调用本地越狱检测服务并返回响应 JSON。"""

    payload = {
        "text": text,
        "checks": ["detect_jailbreak"],
        "params": _JAILBREAK_PARAMS,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(_JAILBREAK_ENDPOINT, json=payload)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"越狱检测服务调用失败: {exc}") from exc

    try:
        return response.json()
    except ValueError as exc:  # pragma: no cover - 守护服务异常
        raise HTTPException(status_code=502, detail="越狱检测服务返回非 JSON 响应") from exc


@router.post("/check_query", response_model=ChatQueryResponse, summary="执行权限检查")
async def check_query(
    request: ChatQueryRequest,
    controller: PermissionController = Depends(get_permission_controller),
):
    """调用越狱检测服务，再执行 PermissionController 权限判断"""

    guard_result = await _run_jailbreak_guard(request.query)
    if guard_result.get("status") != 200:
        return ChatQueryResponse(
            decision="DENY",
            reason="检测到越狱攻击/提示注入",
            opa_result={"jailbreak_guard": guard_result},
        )

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
