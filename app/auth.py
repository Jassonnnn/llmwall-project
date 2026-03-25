from fastapi import Request

from app.config import (
    JB_DEMO_ALLOW_LOCAL_BYPASS,
    JB_DEMO_REQUIRE_AUTH,
    JB_DEMO_SERVICE_TOKEN,
)
from app.errors import AppError


LOCALHOST_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _is_local_request(request: Request) -> bool:
    client = request.client
    if client is None:
        return False
    host = (client.host or "").strip().lower()
    return host in LOCALHOST_HOSTS


async def require_service_auth(request: Request) -> None:
    if not JB_DEMO_REQUIRE_AUTH:
        return

    if JB_DEMO_ALLOW_LOCAL_BYPASS and _is_local_request(request):
        return

    if not JB_DEMO_SERVICE_TOKEN:
        raise AppError(
            code="AUTH_NOT_CONFIGURED",
            message="服务端鉴权已启用，但未配置 JB_DEMO_SERVICE_TOKEN。",
            status_code=503,
        )

    authorization = request.headers.get("Authorization", "").strip()
    if not authorization.startswith("Bearer "):
        raise AppError(
            code="AUTH_REQUIRED",
            message="缺少 Bearer Token。",
            status_code=401,
        )

    token = authorization[7:].strip()
    if token != JB_DEMO_SERVICE_TOKEN:
        raise AppError(
            code="AUTH_INVALID",
            message="Bearer Token 无效。",
            status_code=403,
        )
