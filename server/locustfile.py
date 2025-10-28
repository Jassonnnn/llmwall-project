import uuid
import json
import random
import string
from locust import task, HttpUser, constant

class SecureApiUser(HttpUser):
    # host = "http://127.0.0.1:11514" # 可以在启动时指定，或在这里取消注释
    
    # [修复] 将 wait_time 从 None 更改为 constant(0) 以实现零等待的全速压测
    wait_time = constant(0)

    def generate_random_text(self, min_len=50, max_len=500):
        """生成指定长度范围内的随机文本。"""
        length = random.randint(min_len, max_len)
        # 使用字母和数字生成随机字符串
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @task(1)
    def check_non_streaming(self):
        """测试 /check 非流式端点。"""

        random_text = self.generate_random_text()

        payload = {
            "text": random_text,
            "checks": ["pii_guard"],
            "params": {}
        }
        self.client.post("/check", json=payload, name="/check (non-stream)")

    @task(1) # 让流式任务的权重更高，更频繁地被执行
    def check_streaming_session(self):
        """模拟一个完整的流式会话，包含多个数据块和结束信号。"""
        session_id = str(uuid.uuid4())
        text_chunks = [self.generate_random_text(min_len=3, max_len=5) for _ in range(random.randint(10, 20))]

        # 模拟发送多个数据块
        for i, chunk in enumerate(text_chunks):
            is_last_chunk = (i == len(text_chunks) - 1)
            payload = {
                "session_id": session_id,
                "text_chunk": chunk,
                "checks": ["pii_guard"],
                "params": {},
                "is_finished": is_last_chunk
            }
            with self.client.post(
                "/check_stream",
                json=payload,
                name="/check_stream",
                stream=True, # 开启流式接收
                catch_response=True # 必须，用于 with 语句
            ) as response:
                # 必须消耗掉响应内容，否则连接会被阻塞
                full_response = ""
                for line in response.iter_lines():
                    if line:
                        full_response += line.decode('utf-8')
                
                # 你可以根据需要添加对 full_response 的断言
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Request failed with status {response.status_code}")

