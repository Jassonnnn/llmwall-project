# -*- coding: utf-8 -*-
import asyncio
from typing import AsyncGenerator, List, Dict, Any, Tuple

# 模拟一个非常快速的非模型处理时间
TOKENS_PER_SECOND = 25
TOKEN_PER_CHAR_ESTIMATE = 4.0

async def mock_input_check(
    text: str, checks: List[str], params: Dict[str, Any], models: Dict, tokenizers: Dict
) -> Tuple[int, str, str]:
    """
    一个异步的、非阻塞的 mock input_check 函数。
    它的延迟时间根据输入文本的长度和模拟的 tokens/s 动态计算。
    """
    try:
        # 估算输入文本包含的 token 数量
        estimated_tokens = len(text) * TOKEN_PER_CHAR_ESTIMATE

        # 根据 tokens/s 计算处理延迟
        dynamic_latency = estimated_tokens / TOKENS_PER_SECOND

        # 模拟 API 的动态处理延迟
        await asyncio.sleep(dynamic_latency/1000.0)

        # 总是返回“通过”的结果
        return (1, f"Mock check passed after {dynamic_latency:.2f}s delay", text)
    except Exception as e:
        return (3, f"Error during mock check: {e}", text)

# async def mock_output_check(
#     text: str, checks: List[str], params: Dict[str, Any], models: Dict, tokenizers: Dict
# ) -> Tuple[int, str, str]:
#     """模拟 output_check，总是返回通过。现在是异步的。"""
#     await asyncio.sleep(MOCK_PROCESSING_TIME) # 使用 asyncio.sleep
#     return 1, "Pass", text

# async def mock_input_check(text: str, checks: List[str], params: Dict, models: Dict, tokenizers: Dict) -> Tuple[int, str, str]:
#     """一个异步的、非阻塞的 mock input_check 函数。"""
#     # 模拟异步 I/O 操作，例如访问数据库或缓存
#     await asyncio.sleep(MOCK_PROCESSING_TIME)
#     # 总是返回“通过”的结果
#     return (1, "Mock check passed", text)