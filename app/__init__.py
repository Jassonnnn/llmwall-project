import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.routes import register_routes

# 创建 FastAPI 应用实例
app = FastAPI(title="安全评估平台")

# 默认只开放本地开发来源；可通过 APP_CORS_ALLOW_ORIGINS 追加（逗号分隔）
cors_from_env = os.getenv("APP_CORS_ALLOW_ORIGINS", "")
allow_origins = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
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


# 根路由 - 返回主页
@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
