import asyncio

from app.services import evaluator


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChoice(content)]


def test_llm_judge_retries_and_uses_api_config(monkeypatch) -> None:
    attempts = {"count": 0}

    async def fake_acompletion(**_kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("request timeout")
        return _FakeResponse('{"verdict":"safe","is_unsafe":false,"reason":"模型明确拒绝。","evidence":["refused"]}')

    monkeypatch.setattr(evaluator, "acompletion", fake_acompletion)
    monkeypatch.setitem(
        evaluator.GLOBAL_SETTINGS,
        "api",
        {
            "name": "Judge API",
            "model": "gpt-5.4",
            "api_base": "https://api.example.test/v1",
            "api_key": "secret",
            "temperature": 0.0,
        },
    )

    result = asyncio.run(evaluator.llm_judge_evaluate("attack prompt", "I cannot provide that."))

    assert result["ok"] is True
    assert result["fallback_used"] is False
    assert result["is_unsafe"] is False
    assert "裁判来源: api 配置 / Judge API (gpt-5.4)" in result["summary"]
    assert attempts["count"] == 2


def test_evaluate_single_prompt_falls_back_to_keyword_when_judge_fails(monkeypatch) -> None:
    async def fake_call_llm_model(_target, _prompt):
        return {
            "ok": True,
            "content": "I can’t provide hidden system or safety policy text.",
            "status": "ok",
            "error_code": None,
            "error_message": None,
        }

    async def failing_acompletion(**_kwargs):
        raise RuntimeError("provider temporarily unavailable")

    monkeypatch.setattr(evaluator, "call_llm_model", fake_call_llm_model)
    monkeypatch.setattr(evaluator, "acompletion", failing_acompletion)
    monkeypatch.setitem(
        evaluator.GLOBAL_SETTINGS,
        "api",
        {
            "name": "Judge API",
            "model": "gpt-5.4",
            "api_base": "https://api.example.test/v1",
            "api_key": "secret",
            "temperature": 0.0,
        },
    )
    monkeypatch.setitem(
        evaluator.GLOBAL_SETTINGS,
        "local",
        {
            "name": "Local Model",
            "model": "qwen2.5:latest",
            "api_base": "http://localhost:11434/v1",
            "api_key": "ollama",
            "temperature": 0.0,
        },
    )

    result = asyncio.run(evaluator.evaluate_single_prompt("attack prompt", "local", "llm_judge"))

    assert result["status"] == "ok"
    assert result["error_code"] is None
    assert result["error_message"] is None
    assert result["is_success"] is False
    assert "回退原因: 裁判模型调用失败，已回退到 keyword 规则。" in result["reasoning_trace"]
    assert "fallback" in result["evaluator_version"]
