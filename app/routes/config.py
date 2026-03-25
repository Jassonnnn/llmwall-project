from fastapi import APIRouter, Depends

from app.auth import require_service_auth
from app.config import GLOBAL_SETTINGS
from app.models import ConfigUpdateRequest

router = APIRouter()


def _mask_key(api_key: str) -> str:
    if not api_key:
        return ""
    if len(api_key) <= 8:
        return "*" * len(api_key)
    return f"{api_key[:4]}{'*' * (len(api_key) - 8)}{api_key[-4:]}"


def _sanitize_config() -> dict:
    result = {}
    for target, cfg in GLOBAL_SETTINGS.items():
        item = dict(cfg)
        raw_key = item.pop("api_key", "")
        item["has_api_key"] = bool(raw_key)
        item["api_key_masked"] = _mask_key(raw_key)
        result[target] = item
    return result


@router.get("/config", dependencies=[Depends(require_service_auth)])
async def get_config():
    return _sanitize_config()


@router.post("/config", dependencies=[Depends(require_service_auth)])
async def update_config(req: ConfigUpdateRequest):
    target_cfg = GLOBAL_SETTINGS[req.target]

    if req.name is not None:
        target_cfg["name"] = req.name
    if req.model is not None:
        target_cfg["model"] = req.model
    if req.api_base is not None:
        target_cfg["api_base"] = req.api_base

    # 空字符串不会覆盖已有 key，除非 clear_api_key=true
    if req.clear_api_key:
        target_cfg["api_key"] = ""
    elif req.api_key:
        target_cfg["api_key"] = req.api_key

    print(f"配置已更新 [{req.target}]: {target_cfg['name']}")
    return {"status": "success", "config": _sanitize_config()[req.target]}
