import asyncio
import json
from typing import AsyncGenerator, Dict, Any, List

MOCK_PROCESSING_TIME = 0.01

TOKENS_PER_SECOND = 25
TOKEN_PER_CHAR_ESTIMATE = 4.0

class MockSession:
    """一个假的 Session 类，用于压力测试。"""
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.buffer = ""
        print(f"Mock Session {self.session_id} created.")

    def add_chunk(self, chunk: str):
        """将数据块添加到内部缓冲区。"""
        self.buffer += chunk

    async def _process_text(self, text_to_process: str) -> dict:
        """模拟耗时的模型处理，但实际上只做异步休眠。"""
        # 估算输入文本包含的 token 数量
        estimated_tokens = len(text_to_process) * TOKEN_PER_CHAR_ESTIMATE

        # 根据 tokens/s 计算处理延迟
        dynamic_latency = estimated_tokens / TOKENS_PER_SECOND

        # 模拟 API 的动态处理延迟
        await asyncio.sleep(dynamic_latency)
        # 返回一个符合 NDJSON 格式的字典
        return {"status": 200, "message": "Chunk processed", "processed_text": text_to_process}

    async def process_stream(self, checks: List, params: Dict, models: Dict, tokenizers: Dict) -> AsyncGenerator[str, None]:
        """
        一个异步生成器，模拟处理缓冲区中的完整句子。
        在 mock 中，我们简化为处理所有缓冲的数据。
        """
        if self.buffer:
            text_to_yield = self.buffer
            self.buffer = ""
            processed_result = await self._process_text(text_to_yield)
            # 产生一个 NDJSON 格式的字符串
            yield json.dumps(processed_result) + "\n"

    async def final_process(self, checks: List, params: Dict, models: Dict, tokenizers: Dict) -> AsyncGenerator[str, None]:
        """模拟处理流结束时剩余的所有缓冲数据。"""
        if self.buffer:
            text_to_yield = self.buffer
            self.buffer = ""
            processed_result = await self._process_text(text_to_yield)
            yield json.dumps(processed_result) + "\n"


class MockSessionManager:
    """一个假的 SessionManager，返回 MockSession 实例。"""
    _sessions: Dict[str, MockSession] = {}

    @classmethod
    def get_or_create_session(cls, session_id: str) -> MockSession:
        if session_id not in cls._sessions:
            cls._sessions[session_id] = MockSession(session_id)
        return cls._sessions[session_id]
    