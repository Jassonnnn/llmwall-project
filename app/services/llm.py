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

        provider = "openai" if target_type == 'local' else None

        response = await acompletion(
            model=config["model"],
            api_base=config["api_base"],
            api_key=config["api_key"],
            custom_llm_provider=provider,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=config["temperature"],
            timeout=60,
            stream=False
        )
        content = response.choices[0].message.content or ""
        return _build_result(ok=True, content=content)
    except Exception as e:
        return _build_result(
            ok=False,
            error_code="MODEL_CALL_FAILED",
            error_message=f"模型调用失败: {str(e)}",
        )
