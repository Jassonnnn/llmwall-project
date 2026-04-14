from app.services.llm import extract_response_content
from app.services import llm
import asyncio


class _FakePart:
    def __init__(self, text: str) -> None:
        self.type = "output_text"
        self.text = text


class _FakeMessage:
    def __init__(self, content) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content) -> None:
        self.message = _FakeMessage(content)


class _FakeResponsesMessage:
    def __init__(self, text: str) -> None:
        self.type = "message"
        self.content = [_FakePart(text)]


class _FakeChatResponse:
    def __init__(self, content) -> None:
        self.choices = [_FakeChoice(content)]


class _FakeResponsesResponse:
    def __init__(self, text: str) -> None:
        self.output = [_FakeResponsesMessage(text)]
        self.output_text = ""


def test_extract_response_content_supports_chat_text_list() -> None:
    response = _FakeChatResponse([{"type": "text", "text": "hello"}, {"type": "text", "text": "world"}])

    assert extract_response_content(response) == "hello\nworld"


def test_extract_response_content_supports_responses_output() -> None:
    response = _FakeResponsesResponse("pong")

    assert extract_response_content(response) == "pong"


def test_call_llm_model_returns_error_for_empty_content(monkeypatch) -> None:
    class _EmptyResponse:
        choices = [_FakeChoice("")]

    async def fake_completion(**_kwargs):
        return _EmptyResponse()

    monkeypatch.setattr(llm, "acompletion", fake_completion)
    monkeypatch.setitem(
        llm.GLOBAL_SETTINGS,
        "local",
        {
            "name": "Local Model",
            "model": "qwen2.5:latest",
            "api_base": "http://localhost:11434/v1",
            "api_key": "ollama",
            "temperature": 0.0,
        },
    )

    result = asyncio.run(llm.call_llm_model("local", "hello"))

    assert result["ok"] is False
    assert result["error_code"] == "MODEL_EMPTY_RESPONSE"


def test_call_llm_model_requires_api_key(monkeypatch) -> None:
    monkeypatch.setitem(
        llm.GLOBAL_SETTINGS,
        "api",
        {
            "name": "Remote API",
            "model": "gpt-5.4",
            "api_base": "https://api.example.test/v1",
            "api_key": "",
            "temperature": 0.0,
        },
    )

    result = asyncio.run(llm.call_llm_model("api", "hello"))

    assert result["ok"] is False
    assert result["error_code"] == "CONFIG_MISSING_API_KEY"


def test_call_llm_model_falls_back_from_responses_to_litellm(monkeypatch) -> None:
    async def fake_responses(_target, _prompt, timeout=60):
        return llm.LLMCallOutcome(content="", source="responses")

    async def fake_litellm(_target, _prompt, timeout=60):
        return llm.LLMCallOutcome(content="pong", source="litellm")

    monkeypatch.setattr(llm, "_call_via_responses_api", fake_responses)
    monkeypatch.setattr(llm, "_call_via_litellm", fake_litellm)
    monkeypatch.setitem(
        llm.GLOBAL_SETTINGS,
        "api",
        {
            "name": "Remote API",
            "model": "gpt-5.4",
            "api_base": "https://api.example.test/v1",
            "api_key": "secret",
            "temperature": 0.0,
        },
    )

    result = asyncio.run(llm.call_llm_model("api", "hello"))

    assert result["ok"] is True
    assert result["content"] == "pong"
