from typing import Any, Dict, Optional

from litellm import acompletion
from app.config import GLOBAL_SETTINGS


def _build_result(
    ok: bool,
    content: str = "",
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "ok": ok,
        "content": content,
        "status": "ok" if ok else "error",
        "error_code": error_code,
        "error_message": error_message,
    }


def _model_basename(model_name: str) -> str:
    raw = (model_name or "").strip()
    if not raw:
        return ""
    return raw.split("/", 1)[-1].strip().lower()


def _should_use_openai_provider(model_name: str, api_base: str, target_type: str) -> bool:
    if target_type == "local":
        return True

    normalized_base = (api_base or "").strip().lower()
    basename = _model_basename(model_name)
    return (
        "gmncode.cn" in normalized_base
        or basename.startswith("gpt-")
        or model_name.strip().lower().startswith("openai/")
    )


def _normalize_temperature(model_name: str, requested_temperature: Any) -> Any:
    basename = _model_basename(model_name)
    if basename.startswith("gpt-5") and (basename.endswith("-codex") or basename in {"gpt-5.3", "gpt-5.4"}):
        return 1
    return requested_temperature


def build_completion_kwargs(
    config: Dict[str, Any],
    user_prompt: str,
    *,
    response_format: Optional[Dict[str, Any]] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    model_name = str(config.get("model", ""))
    api_base = str(config.get("api_base", ""))
    target_type = str(config.get("target_type", "api"))
    payload: Dict[str, Any] = {
        "model": model_name,
        "api_base": api_base,
        "api_key": config.get("api_key", ""),
        "messages": [{"role": "user", "content": user_prompt}],
        "timeout": timeout,
        "stream": False,
    }

    if _should_use_openai_provider(model_name, api_base, target_type):
        payload["custom_llm_provider"] = "openai"

    normalized_temperature = _normalize_temperature(model_name, config.get("temperature"))
    if normalized_temperature is not None:
        payload["temperature"] = normalized_temperature

    if response_format is not None:
        payload["response_format"] = response_format

    return payload


def extract_response_content(response: Any) -> str:
    return response.choices[0].message.content or ""


async def call_llm_model(target_type: str, user_prompt: str) -> Dict[str, Any]:
    try:
        if target_type not in GLOBAL_SETTINGS:
            return _build_result(
                ok=False,
                error_code="INVALID_TARGET",
                error_message=f"无效目标模型类型: {target_type}",
            )

        config = GLOBAL_SETTINGS[target_type]

        # 检查是否配置了 Key (针对 API 模型)
        if target_type == 'api' and not config["api_key"]:
            return _build_result(
                ok=False,
                error_code="CONFIG_MISSING_API_KEY",
                error_message="错误：未配置 API Key。请点击右上角⚙️设置按钮，填入 Key 并保存。",
            )

        response = await acompletion(
            **build_completion_kwargs(
                {
                    **config,
                    "target_type": target_type,
                },
                user_prompt,
            )
        )
        content = extract_response_content(response)
        return _build_result(ok=True, content=content)
    except Exception as e:
        return _build_result(
            ok=False,
            error_code="MODEL_CALL_FAILED",
            error_message=f"模型调用失败: {str(e)}",
        )
