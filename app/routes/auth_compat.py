from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth_jwt import require_jwt_auth
from app.config import JB_DEMO_SEED_PASSWORD, JB_DEMO_SEED_USERNAME
from app.errors import AppError
from app.jwt_auth import create_access_token

router = APIRouter()


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserMeResponse(BaseModel):
    id: int
    username: str


@router.post("/auth/login", response_model=TokenResponse)
async def login(payload: AuthLoginRequest):
    username = payload.username.strip()
    password = payload.password

    if username != JB_DEMO_SEED_USERNAME or password != JB_DEMO_SEED_PASSWORD:
        raise AppError(
            code="AUTH_INVALID_CREDENTIALS",
            message="Invalid username/password",
            status_code=401,
        )

    access_token = create_access_token(subject=username, user_id=1)
    return TokenResponse(access_token=access_token)


@router.get("/auth/me", response_model=UserMeResponse)
async def me(current_user: Dict[str, Any] = Depends(require_jwt_auth)):
    return UserMeResponse(
        id=int(current_user["id"]),
        username=str(current_user["username"]),
    )
