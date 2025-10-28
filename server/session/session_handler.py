import uuid
import time
import json
from typing import Dict, Iterator, List, Any

# 导入您的检查器逻辑
from checkers.input_checker import input_check

# 1. 全局会话管理器
ACTIVE_SESSIONS: Dict[str, 'ConversationSession'] = {}


class ConversationSession:
    """封装一个独立对话的所有状态和逻辑。"""
    def __init__(self, session_id: str):
        self.session_id: str = session_id
        self.buffer: str = ""
        self.last_access_time: float = time.time()
        self.delimiters = (".", "!", "?", "\n", "。", "！", "？")
        print(f"会话 {self.session_id} 已创建。")

    def update_access_time(self):
        """更新会话的最后访问时间。"""
        self.last_access_time = time.time()

    def add_chunk(self, chunk: str):
        """将新的文本块添加到此会话的缓冲区中。"""
        self.buffer += chunk
        self.update_access_time()

    def process_stream(self, checks: List[str], params: Dict, models: Dict, tokenizers: Dict) -> Iterator[str]:
        """一个生成器，它处理缓冲区中已构成完整句子的部分。"""
        while any(d in self.buffer for d in self.delimiters):
            split_point = -1
            for d in self.delimiters:
                pos = self.buffer.find(d)
                if pos != -1 and (split_point == -1 or pos < split_point):
                    split_point = pos

            if split_point != -1:
                sentence_to_check = self.buffer[:split_point + 1]
                self.buffer = self.buffer[split_point + 1:]

                status_code, message, processed_text = input_check(
                    text_to_check=sentence_to_check, checks=checks, params=params, models=models, tokenizers=tokenizers
                )
                if status_code == 0:
                    print(f"会话 {self.session_id} 检测到问题: {message}")
                    
                # [MODIFIED] 创建一个包含所有信息的字典
                response_payload = {
                    "status": status_code,
                    "message": message,
                    "processed_text": processed_text
                }
                # [MODIFIED] 产生一个JSON字符串，并以换行符结尾 (NDJSON格式)
                yield json.dumps(response_payload, ensure_ascii=False) + "\n"
            else:
                break
        self.update_access_time()

    def final_process(self, checks: List[str], params: Dict, models: Dict, tokenizers: Dict) -> Iterator[str]:
        """当客户端发出结束信号时，处理缓冲区中剩余的所有文本。"""
        if self.buffer:
            print(f"会话 {self.session_id}: 正在处理最后的缓冲区内容...")
            status_code, message, processed_text = input_check(
                text_to_check=self.buffer, checks=checks, params=params, models=models, tokenizers=tokenizers
            )
            self.buffer = ""  # 清空缓冲区
            
            response_payload = {
                "status": status_code,
                "message": message,
                "processed_text": processed_text
            }
            yield json.dumps(response_payload, ensure_ascii=False) + "\n"
        
        # 处理完最后的文本后，明确地删除会话
        SessionManager.delete_session(self.session_id)


class SessionManager:
    """一个用于管理所有对话会话的静态类。"""
    @staticmethod
    def get_or_create_session(session_id: str) -> ConversationSession:
        """
        尝试获取一个已存在的会话。如果未找到，则用给定的ID创建一个新的会话。
        这实现了“无感知”的会话创建逻辑。
        """
        session = ACTIVE_SESSIONS.get(session_id)
        if not session:
            print(f"会话 '{session_id}' 未找到。正在创建一个新的会话。")
            session = ConversationSession(session_id)
            ACTIVE_SESSIONS[session_id] = session
        
        session.update_access_time()
        return session

    @staticmethod
    def delete_session(session_id: str):
        """删除一个会话。"""
        if session_id in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[session_id]
            print(f"会话 {session_id} 已被明确删除。")
