# -*- coding: utf-8 -*-
from unittest.mock import patch
import asyncio

# --- 导入 Mock 模块 ---
from mock_checkers import mock_input_check
from mock_session_handler import MockSessionManager

# --- Mock 后台任务和生命周期函数 ---
async def mock_stale_session_reaper():
    """一个空的 mock 函数，防止后台任务在测试时运行。"""
    print("Mocking stale_session_reaper: 后台任务已禁用。")
    await asyncio.sleep(3600) # 模拟长时间运行

def mock_load_model():
    print("Mocking load_model: 跳过实际的模型加载。")
    pass

def mock_unload_model():
    print("Mocking unload_model: 跳过实际的模型卸载。")
    pass

# --- 在导入主应用之前应用所有补丁 ---
# 目标字符串必须是函数或类被 *使用* 的地方
patch('session_app.load_model', new=mock_load_model).start()
patch('session_app.unload_model', new=mock_unload_model).start()
patch('session_app.stale_session_reaper', new=mock_stale_session_reaper).start()
patch('session_app.input_check', new=mock_input_check).start()
patch('session_app.SessionManager', new=MockSessionManager).start()

# 在所有补丁都生效后，再导入原始的 app 对象
# 此时，app 内部的依赖已经被替换了
from session_app import app

# 运行命令:
# uvicorn test_app:app --host 0.0.0.0 --port 11514


