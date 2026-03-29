from typing import Any, Dict

from fastapi import Request

from app.errors import AppError
from app.jwt_auth import decode_access_token


async def require_jwt_auth(request: Request) -> Dict[str, Any]:
    authorization = request.headers.get("Authorization", "").strip()
    if not authorization.startswith("Bearer "):
        raise AppError(
            code="AUTH_REQUIRED",
            message="缺少 Bearer Token。",
            status_code=401,
        )

    token = authorization[7:].strip()
    if not token:
        raise AppError(
            code="AUTH_REQUIRED",
            message="Bearer Token 为空。",
            status_code=401,
        )

    payload = decode_access_token(token)
    username = str(payload.get("sub", "")).strip()
    if not username:
        raise AppError(
            code="AUTH_INVALID",
            message="Bearer Token 缺少 subject。",
            status_code=401,
        )

    uid_raw = payload.get("uid", 1)
    try:
        user_id = int(uid_raw)
    except Exception:  # noqa: BLE001
        user_id = 1

    return {
        "id": user_id,
        "username": username,
        "token_payload": payload,
    }
