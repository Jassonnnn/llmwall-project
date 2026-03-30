import os
from pathlib import Path
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.errors import AppError, error_payload
from app.routes import register_routes
from app.services.evaluation_tasks import init_evaluation_store


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_evaluation_store()
    yield


# 创建 FastAPI 应用实例
app = FastAPI(title="安全评估平台", lifespan=lifespan)

# 默认只开放本地开发来源；可通过 APP_CORS_ALLOW_ORIGINS 追加（逗号分隔）
cors_from_env = os.getenv("APP_CORS_ALLOW_ORIGINS", "")
allow_origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
if cors_from_env.strip():
    allow_origins = [o.strip() for o in cors_from_env.split(",") if o.strip()]

# 配置 CORS 中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 配置模板目录
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# 配置静态文件目录
static_dir = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# 注册所有 API 路由
register_routes(app)

logger = logging.getLogger(__name__)


@app.exception_handler(AppError)
async def handle_app_error(_: Request, exc: AppError):
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(code=exc.code, message=exc.message, details=exc.details),
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=error_payload(
            code="VALIDATION_ERROR",
            message="请求参数校验失败。",
            details={"errors": exc.errors()},
        ),
    )


@app.exception_handler(HTTPException)
async def handle_http_exception(_: Request, exc: HTTPException):
    if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
        code = str(exc.detail["code"])
        message = str(exc.detail["message"])
        details = exc.detail.get("details", {})
    else:
        code = "HTTP_ERROR"
        message = str(exc.detail) if exc.detail else "请求失败。"
        details = {}
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(code=code, message=message, details=details),
    )


@app.exception_handler(Exception)
async def handle_unexpected_exception(_: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content=error_payload(code="INTERNAL_ERROR", message="服务内部异常。"),
    )


# 根路由 - 返回主页
@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
