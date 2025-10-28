import asyncio
import time
from .session_handler import ACTIVE_SESSIONS, SessionManager

SESSION_TIMEOUT_SECONDS = 1800  # 30分钟

async def stale_session_reaper():
    """一个后台任务，定期检查并移除过期的会话。"""
    while True:
        await asyncio.sleep(300) # 每5分钟检查一次
        print("后台任务: 正在检查过期会话...")
        current_time = time.time()
        sessions_to_reap = [
            session_id
            for session_id, session in list(ACTIVE_SESSIONS.items())
            if current_time - session.last_access_time > SESSION_TIMEOUT_SECONDS
        ]

        for session_id in sessions_to_reap:
            print(f"后台任务: 正在清理过期会话 {session_id}")
            SessionManager.delete_session(session_id)
