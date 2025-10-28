# -*- coding: utf-8 -*-
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, AsyncGenerator # [MODIFIED] 导入 AsyncGenerator
from contextlib import asynccontextmanager
from vllm import LLM
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from gliner import (
    GLiNER,
)
import os
import json
import codecs
import asyncio # [ADD] 导入 asyncio

# 从 'checkers' 包中导入函数
# 注意：这些导入路径是 test_app.py 进行 mock 的目标
from checkers.input_checker import input_check
from checkers.output_checker import output_check
from checkers.stream_checker import stream_output_check
from registry.models import MODEL_PATHS


# --- Pydantic 模型定义 ---
class CheckRequest(BaseModel):
    text: str
    checks: List[str]
    params: Dict[str, Any]


models = {}
tokenizers = {}


def load_model():
    # ... (此函数内容保持不变) ...
    for model_name, model_path in MODEL_PATHS.items():
        if not os.path.exists(model_path):
            print(f"模型路径不存在: {model_path}，跳过加载 {model_name}")
            continue
        print(f"加载模型 {model_name}，路径: {model_path}")
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
    # ... (此函数内容保持不变) ...
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ... (此函数内容保持不变) ...
    load_model()
    yield
    unload_model()
    models.clear()


# --- 初始化 FastAPI 应用 ---
app = FastAPI(
    title="智能护栏 API",
    description="一个用于输入检查和输出审核的 API 服务。",
    lifespan=lifespan,
    version="1.0.0",
)

# --- API 端点定义 ---


@app.post("/check_input")
async def check_input_endpoint(request_data: CheckRequest):
    """
    输入检查端点。
    """
    # [FIX] 对 checker 的调用现在是异步的，需要 await
    is_problematic, message, processed_text = await input_check(
        request_data.text, request_data.checks, request_data.params, models, tokenizers
    )

    if is_problematic == 0:
        return {"status": 201, "message": message, "processed_text": processed_text}
    elif is_problematic == 1:
        return {"status": 200, "message": message, "processed_text": processed_text}
    elif is_problematic == 2:
        return {"status": 202, "message": message, "processed_text": processed_text}
    else:
        raise HTTPException(status_code=500, detail=message, headers={"Processed-Text": processed_text})


@app.post("/check_output")
async def unified_check_output_endpoint(
    config: str = Form(...),
    data: UploadFile = File(...)
):
    """
    一个统一的输出审核端点。
    """
    try:
        try:
            config_data = json.loads(config)
            checks = config_data.get('checks', [])
            params = config_data.get('params', {})
            is_streaming = config_data.get('stream', False)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="'config' 部分包含无效的 JSON")

        if is_streaming:
            print("正在执行流式处理...")

            # [FIX] 将 decode_stream 更改为真正的异步生成器 (async def / async for)
            # 这解决了 'async for' 的 TypeError
            async def decode_stream(input_stream) -> AsyncGenerator[str, None]:
                decoder = codecs.getincrementaldecoder('utf-8')()
                while True:
                    # 使用 await 读取数据块
                    byte_chunk = await input_stream.read(4096)
                    if not byte_chunk:
                        break
                    yield decoder.decode(byte_chunk)
                    # 显式地将控制权交还给事件循环，防止长时间运行的任务阻塞
                    await asyncio.sleep(0)
                final_chunk = decoder.decode(b'', final=True)
                if final_chunk:
                    yield final_chunk

            raw_text_stream = decode_stream(data.file)
            
            processed_stream_generator = stream_output_check(
                raw_text_stream, checks, params, models, tokenizers
            )
            
            return StreamingResponse(processed_stream_generator, media_type='text/plain; charset=utf-8')

        else:
            print("正在执行非流式处理...")
            
            content_bytes = await data.read()
            text_to_check = content_bytes.decode('utf-8')
            
            # [FIX] 对 checker 的调用现在是异步的，需要 await
            status_code, message, processed_text = await output_check(
                text_to_check, checks, params, models, tokenizers
            )

            if status_code == 0: # No-op fail
                return JSONResponse(
                    status_code=400,
                    content={"status": 201, "message": message, "processed_text": processed_text}
                )
            elif status_code == 1: # Pass
                return {"status": 200, "message": message, "processed_text": processed_text}
            elif status_code == 2: # Fix
                return {"status": 202, "message": message, "processed_text": processed_text}
            else: # Exception
                raise HTTPException(status_code=500, detail=message)

    except Exception as e:
        print(f"服务器内部错误: {e}")
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {str(e)}")



# --- 如何运行 ---
# 1. 将此文件保存为 main.py (或任何您选择的名称)。
# 2. 在终端中，确保您的当前工作目录是此文件所在的目录。
# 3. 运行 uvicorn 命令:
#    uvicorn fastapi_app:app --host 0.0.0.0 --port 11514 --reload
