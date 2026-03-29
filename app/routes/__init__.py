from fastapi import APIRouter

from app.routes.config import router as config_router
from app.routes.test import router as test_router
from app.routes.batch import router as batch_router
from app.routes.attack import router as attack_router
from app.routes.evaluations import router as evaluations_router
from app.routes.auth_compat import router as auth_compat_router
from app.routes.redteam_compat import router as redteam_compat_router


def register_routes(app):
    """注册所有路由到 FastAPI 应用"""
    app.include_router(config_router, prefix="/api")
    app.include_router(test_router, prefix="/api")
    app.include_router(batch_router, prefix="/api")
    app.include_router(attack_router, prefix="/api")
    app.include_router(evaluations_router, prefix="/api")
    app.include_router(auth_compat_router, prefix="/api")
    app.include_router(redteam_compat_router, prefix="/api")
