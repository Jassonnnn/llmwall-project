import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict

from app.config import (
    JB_DEMO_ACCESS_TOKEN_EXPIRE_MINUTES,
    JB_DEMO_JWT_ALG,
    JB_DEMO_JWT_SECRET,
)
from app.errors import AppError


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))


def _validate_jwt_config() -> None:
    if not JB_DEMO_JWT_SECRET:
        raise AppError(
            code="JWT_NOT_CONFIGURED",
            message="未配置 JWT 密钥（JB_DEMO_JWT_SECRET）。",
            status_code=503,
        )
    if JB_DEMO_JWT_ALG != "HS256":
        raise AppError(
            code="JWT_ALG_UNSUPPORTED",
            message=f"当前仅支持 HS256，收到配置: {JB_DEMO_JWT_ALG}",
            status_code=503,
        )


def create_access_token(subject: str, user_id: int = 1, expires_in_minutes: int | None = None) -> str:
    _validate_jwt_config()
    if not subject.strip():
        raise AppError(
            code="JWT_SUBJECT_REQUIRED",
            message="创建 JWT 失败：subject 不能为空。",
            status_code=400,
        )

    now = int(time.time())
    ttl_minutes = expires_in_minutes or JB_DEMO_ACCESS_TOKEN_EXPIRE_MINUTES
    exp = now + int(ttl_minutes) * 60

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject.strip(),
        "uid": int(user_id),
        "iat": now,
        "exp": exp,
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(JB_DEMO_JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_access_token(token: str) -> Dict[str, Any]:
    _validate_jwt_config()

    parts = token.split(".")
    if len(parts) != 3:
        raise AppError(
            code="AUTH_INVALID",
            message="Bearer Token 格式无效。",
            status_code=401,
        )

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_sig = hmac.new(
        JB_DEMO_JWT_SECRET.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)

    if not hmac.compare_digest(signature_b64, expected_sig_b64):
        raise AppError(
            code="AUTH_INVALID",
            message="Bearer Token 签名无效。",
            status_code=401,
        )

    try:
        header_raw = _b64url_decode(header_b64).decode("utf-8")
        payload_raw = _b64url_decode(payload_b64).decode("utf-8")
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except Exception as exc:  # noqa: BLE001
        raise AppError(
            code="AUTH_INVALID",
            message=f"Bearer Token 解析失败: {exc}",
            status_code=401,
        ) from exc

    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise AppError(
            code="AUTH_INVALID",
            message="Bearer Token 算法头无效。",
            status_code=401,
        )
    if not isinstance(payload, dict):
        raise AppError(
            code="AUTH_INVALID",
            message="Bearer Token 载荷无效。",
            status_code=401,
        )

    exp_raw = payload.get("exp")
    try:
        exp = int(exp_raw)
    except Exception as exc:  # noqa: BLE001
        raise AppError(
            code="AUTH_INVALID",
            message=f"Bearer Token 过期时间无效: {exp_raw}",
            status_code=401,
        ) from exc

    now = int(time.time())
    if exp <= now:
        raise AppError(
            code="AUTH_EXPIRED",
            message="Bearer Token 已过期。",
            status_code=401,
        )

    return payload
