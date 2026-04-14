from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional

from litellm import acompletion
from openai import AsyncOpenAI

from app.config import GLOBAL_SETTINGS


EMPTY_RESPONSE_ERROR = "MODEL_EMPTY_RESPONSE"
CALL_FAILED_ERROR = "MODEL_CALL_FAILED"
MISSING_API_KEY_ERROR = "CONFIG_MISSING_API_KEY"
INVALID_TARGET_ERROR = "INVALID_TARGET"


@dataclass(frozen=True)
class LLMTargetConfig:
    target_type: str
    name: str
    model: str
    api_base: str
    api_key: str
    temperature: Any


@dataclass(frozen=True)
class LLMCallOutcome:
    content: str
    source: str


@dataclass(frozen=True)
class LLMCallAttempt:
    source: str
    call: Callable[[LLMTargetConfig, str, int], Any]


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


def _build_error_result(*, error_code: str, error_message: str) -> Dict[str, Any]:
    return _build_result(ok=False, error_code=error_code, error_message=error_message)


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


def _should_use_responses_api(model_name: str) -> bool:
    basename = _model_basename(model_name)
    return basename.startswith("gpt-5") and (
        basename.endswith("-codex") or basename in {"gpt-5.3", "gpt-5.4"}
    )


def _normalize_temperature(model_name: str, requested_temperature: Any) -> Any:
    basename = _model_basename(model_name)
    if basename.startswith("gpt-5") and (basename.endswith("-codex") or basename in {"gpt-5.3", "gpt-5.4"}):
        return 1
    return requested_temperature


def _coerce_part_text(part: Any) -> str:
    if isinstance(part, str):
        return part

    text = getattr(part, "text", None)
    if isinstance(text, str) and text.strip():
        return text

    if isinstance(part, dict):
        for key in ("text", "content", "output_text"):
            value = part.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def _coerce_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return _coerce_part_text(content)
    if isinstance(content, Iterable):
        pieces = []
        for part in content:
            text = _coerce_part_text(part)
            if text:
                pieces.append(text)
        return "\n".join(piece for piece in pieces if piece)
    return ""


def extract_response_content(response: Any) -> str:
    try:
        content = _coerce_content(response.choices[0].message.content)
        if content:
            return content
    except (AttributeError, IndexError, TypeError):
        pass

    try:
        for item in response.output:
            if getattr(item, "type", None) != "message":
                continue
            content = _coerce_content(getattr(item, "content", None))
            if content:
                return content
    except (AttributeError, TypeError):
        pass

    try:
        text = response.output_text
        if isinstance(text, str) and text.strip():
            return text
    except AttributeError:
        pass

    return ""


def _build_target_config(target_type: str) -> LLMTargetConfig:
    if target_type not in GLOBAL_SETTINGS:
        raise ValueError(f"无效目标模型类型: {target_type}")

    config = GLOBAL_SETTINGS[target_type]
    return LLMTargetConfig(
        target_type=target_type,
        name=str(config.get("name", "")).strip(),
        model=str(config.get("model", "")).strip(),
        api_base=str(config.get("api_base", "")).strip(),
        api_key=str(config.get("api_key", "")),
        temperature=config.get("temperature"),
    )


def _ensure_target_config_ready(target: LLMTargetConfig) -> None:
    if target.target_type == "api" and not target.api_key:
        raise PermissionError("错误：未配置 API Key。请点击右上角⚙️设置按钮，填入 Key 并保存。")


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


async def _call_via_responses_api(target: LLMTargetConfig, user_prompt: str, timeout: int = 60) -> LLMCallOutcome:
    client = AsyncOpenAI(
        api_key=target.api_key,
        base_url=target.api_base or None,
        timeout=float(timeout),
        max_retries=0,
    )
    response = await client.responses.create(
        model=target.model,
        temperature=_normalize_temperature(target.model, target.temperature) or 1,
        input=user_prompt,
    )
    return LLMCallOutcome(content=extract_response_content(response).strip(), source="responses")


async def _call_via_litellm(target: LLMTargetConfig, user_prompt: str, timeout: int = 60) -> LLMCallOutcome:
    response = await acompletion(
        **build_completion_kwargs(
            {
                "model": target.model,
                "api_base": target.api_base,
                "api_key": target.api_key,
                "temperature": target.temperature,
                "target_type": target.target_type,
            },
            user_prompt,
            timeout=timeout,
        )
    )
    return LLMCallOutcome(content=extract_response_content(response).strip(), source="litellm")


def _build_call_attempts(target: LLMTargetConfig) -> list[LLMCallAttempt]:
    attempts: list[LLMCallAttempt] = []
    if target.target_type == "api" and _should_use_responses_api(target.model):
        attempts.append(LLMCallAttempt(source="responses", call=_call_via_responses_api))
    attempts.append(LLMCallAttempt(source="litellm", call=_call_via_litellm))
    return attempts


def _is_empty_only_failure(errors: list[str]) -> bool:
    return bool(errors) and all(error.endswith("empty content") for error in errors)


async def _call_model_with_fallback(target: LLMTargetConfig, user_prompt: str, timeout: int = 60) -> LLMCallOutcome:
    errors: list[str] = []
    for attempt in _build_call_attempts(target):
        try:
            outcome = await attempt.call(target, user_prompt, timeout)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{attempt.source}: {exc}")
            continue
        if outcome.content:
            return outcome
        errors.append(f"{attempt.source}: empty content")

    error_summary = "; ".join(errors) if errors else "unknown model call failure"
    raise RuntimeError(error_summary)


def _map_runtime_error_to_result(exc: RuntimeError) -> Dict[str, Any]:
    message = str(exc)
    if _is_empty_only_failure(message.split("; ")):
        return _build_error_result(
            error_code=EMPTY_RESPONSE_ERROR,
            error_message="模型调用成功但未返回可解析的文本内容。",
        )
    return _build_error_result(
        error_code=CALL_FAILED_ERROR,
        error_message=f"模型调用失败: {message}",
    )


async def call_llm_model(target_type: str, user_prompt: str) -> Dict[str, Any]:
    try:
        target = _build_target_config(target_type)
    except ValueError as exc:
        return _build_error_result(error_code=INVALID_TARGET_ERROR, error_message=str(exc))

    try:
        _ensure_target_config_ready(target)
    except PermissionError as exc:
        return _build_error_result(error_code=MISSING_API_KEY_ERROR, error_message=str(exc))

    try:
        outcome = await _call_model_with_fallback(target, user_prompt)
    except RuntimeError as exc:
        return _map_runtime_error_to_result(exc)
    except Exception as exc:  # noqa: BLE001
        return _build_error_result(error_code=CALL_FAILED_ERROR, error_message=f"模型调用失败: {exc}")

    return _build_result(ok=True, content=outcome.content)
