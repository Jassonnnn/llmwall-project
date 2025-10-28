import asyncio
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import StreamingResponse, JSONResponse
from contextlib import asynccontextmanager
from typing import Dict, Any, List
from pydantic import BaseModel
from vllm import LLM
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from gliner import (
    GLiNER,
)

import os

# 导入新的会话管理逻辑和后台任务
from session.session_handler import SessionManager
from session.background_tasks import stale_session_reaper

# 导入您的检查器和模型加载逻辑
from checkers.input_checker import input_check
from checkers.output_checker import output_check
from registry.models import MODEL_PATHS

os.environ["CUDA_VISIBLE_DEVICES"] = "0"  # 确保只使用第一个GPU

# --- Pydantic 模型定义 ---
class NonStreamingRequest(BaseModel):
    text: str
    checks: List[str]
    params: Dict[str, Any]

class StreamingRequest(BaseModel):
    session_id: str
    text_chunk: str
    checks: List[str]
    params: Dict[str, Any]
    is_finished: bool = False # 客户端用此标志来告知流是否结束


models, tokenizers = {}, {} # 模拟的模型缓存
def load_model():
    """
    读取配置文件，加载所有模型实例到 models 字典中。
    Key是模型名，Value是vLLM的LLM实例。
    """
    for model_name, model_path in MODEL_PATHS.items():
        if not os.path.exists(model_path):
            print(f"模型路径不存在: {model_path}，跳过加载 {model_name}")
            continue
        print(f"加载模型 {model_name}，路径: {model_path}")
        # 这里用vLLM的LLM类加载模型
        if model_name == "llama_guard":
            models[model_name] = LLM(
                model=model_path,
                max_model_len=512,
                gpu_memory_utilization=0.8,
                dtype="bfloat16",
            )
        elif model_name == "prompt_guard":
            models[model_name] = AutoModelForSequenceClassification.from_pretrained(
                model_path, device_map="auto"
            )
            tokenizers[model_name] = AutoTokenizer.from_pretrained(model_path)
        elif model_name == "pii_guard":
            models[model_name] = GLiNER.from_pretrained(model_path, device_map="auto")
    print("所有模型加载完成。")


def unload_model():
    """
    卸载模型或其他资源。
    这里可以添加任何需要在应用关闭时清理的资源。
    """
    import gc
    import torch

    for model_name, model_instance in models.items():
        print(f"释放模型资源: {model_name}")
        del model_instance
    models.clear()
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    print("所有模型资源已释放。")

# --- 应用生命周期 ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    asyncio.create_task(stale_session_reaper())
    yield
    unload_model()

app = FastAPI(
    title="隐式会话安全护栏 API",
    description="一个提供非流式和流式检查的统一服务。",
    version="2.0.0",
    lifespan=lifespan
)

# --- API 端点 ---

@app.post("/check")
async def check_non_streaming(request: NonStreamingRequest):
    """一个用于一次性文本检查的简单、无状态端点。"""
    status, msg, text = await input_check(request.text, request.checks, request.params, models, tokenizers)
    # 根据您的业务逻辑返回结果...
    if status == 0:
        # FastAPI 会正确处理这个异常，并返回一个 403 响应。
        return {"status": 201, "message": msg, "processed_text": text}
    elif status == 1:
        # 200表示检查通过
        return {"status": 200, "message": msg, "processed_text": text}
    elif status == 2:
        # 202表示只有fix类型的插件检测到问题，在processed_text中包含修正后的文本
        return {"status": 202, "message": msg, "processed_text": text}
    else:
        # 3表示发生了异常，返回错误信息和原始文本
        raise HTTPException(status_code=500, detail=msg, headers={"Processed-Text": text})


@app.post("/check_stream")
async def check_streaming(request: StreamingRequest):
    """
    一个用于流式文本检查的端点。
    如果 session_id 不存在，会自动创建一个新的会话。
    """
    # 1. 获取或创建会话
    session = SessionManager.get_or_create_session(request.session_id)

    # 2. 将新的文本块添加到会话缓冲区
    session.add_chunk(request.text_chunk)

    # 3. 创建一个组合的生成器，用于流式返回结果
    async def response_generator():
        # 处理并产生所有已构成完整句子的部分
        async for processed_json_string in session.process_stream(request.checks, request.params, models, tokenizers):
            yield processed_json_string
        
        # 如果客户端发出了结束信号，则处理缓冲区中剩余的所有内容
        if request.is_finished:
            print(f"会话 {request.session_id} 已结束。正在处理最后的缓冲区。")
            async for final_json_string in session.final_process(request.checks, request.params, models, tokenizers):
                yield final_json_string

    return StreamingResponse(response_generator(), media_type="application/x-ndjson; charset=utf-8")

# --- 如何运行 ---
# uvicorn session_app:app --host 0.0.0.0 --port 11514
