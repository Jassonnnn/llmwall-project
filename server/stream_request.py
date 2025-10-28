# -*- coding: utf-8 -*-
# 您需要先安装: pip install requests
import requests
import json
import time
import uuid

def run_implicit_streaming_test():
    """
    一个完整的函数，演示如何调用您的“隐式会话”流式护栏服务。
    """
    # --- 1. 准备您的 API 地址和会话 ID ---
    # 这是您护栏服务中 /check_stream 端点的地址
    api_url = "http://127.0.0.1:11514/check_stream"
    
    # 在流式会话开始时，由客户端生成一个唯一的 session_id
    session_id = str(uuid.uuid4())
    print(f"客户端: 已生成新的会话 ID: {session_id}\n")

    # --- 2. 准备您的检查配置 ---
    # 这部分定义了您希望护栏服务执行哪些检查以及相应的参数
    checks_config = {
        "checks": [
            "ban_list",
            "pii_guard"
        ],
        "params": {
            "ban_list": {
                "on_fail": "fix",
                "banned_words": ["个人信息"]
            },
            "pii_guard": {
                "on_fail": "fix",
                "entities": ["name","id_number","phone_number","email"]
            }
        }
    }

    # --- 3. 模拟从大模型接收到的流式文本 ---
    # [MODIFIED] 定义一个完整的长文本
    full_text = "张伟今年35岁，身份证号是110101199001011234，常用手机号13812345678，电子邮箱为zhangwei@example.com。他住在北京市海淀区中关村南大街27号，持有银行卡6222021234567890123，驾驶证号码京A1234567。张伟的出生日期是1990年1月1日，社保号码310123456789012，公司名称是北京某科技有限公司，担任软件工程师。此外，他的医疗记录编号为MD-20210721001，登录密码是Abc123456!。"
    
    # [MODIFIED] 将长文本切分为每块4-5个字的小块
    chunk_size = 5
    text_to_stream = [full_text[i:i + chunk_size] for i in range(0, len(full_text), chunk_size)]
    print(f"将要发送的文本块: {text_to_stream}\n")

    # 创建一个列表来存储所有接收到的响应块，用于最后的完整输出
    full_response_chunks = []

    # --- 4. 循环发送文本块 ---
    # 客户端通过发送一系列独立的 POST 请求来模拟一个持续的流
    for i, chunk in enumerate(text_to_stream):
        payload = {
            "session_id": session_id,
            "text_chunk": chunk,
            "is_finished": False,
            **checks_config
        }
        
        print(f"--- > 正在发送块 {i+1}: '{chunk}' ---")
        
        try:
            with requests.post(api_url, json=payload, stream=True) as response:
                response.raise_for_status()
                
                # [MODIFIED] 修改提示信息，表明这是实时输出
                print(f"< --- 正在实时接收块 {i+1} 的响应: ", end="")
                
                # [MODIFIED] 使用 iter_lines 来处理 NDJSON 流
                for line in response.iter_lines(decode_unicode=True):
                    if line:
                        try:
                            # 解析每一行作为一个独立的 JSON 对象
                            data = json.loads(line)
                            status = data.get("status")
                            message = data.get("message")
                            processed_chunk = data.get("processed_text", "")

                            # 实时打印结构化信息
                            print(f"    [状态: {status}] - {message} -> '{processed_chunk}'")
                            
                            # 将处理后的文本添加到列表中
                            full_response_chunks.append(processed_chunk)
                        except json.JSONDecodeError:
                            print(f"    [错误] 无法解析收到的行: {line}")
                print() # 在每个块的响应后添加一个空行

        except requests.exceptions.RequestException as e:
            print(f"请求失败: {e}")
            return # 如果中途出错，则终止
            
        time.sleep(0.5) # 模拟两次发送之间的间隔

    # --- 5. 发送结束信号 ---
    # 当所有文本块都发送完毕后，发送一个最终请求以结束会话
    print("--- > 所有块已发送完毕，正在发送结束信号... ---")
    final_payload = {
        "session_id": session_id,
        "text_chunk": "",
        "is_finished": True,
        **checks_config
    }
    
    try:
        with requests.post(api_url, json=final_payload, stream=True) as response:
            response.raise_for_status()
            
            print("< --- 正在实时接收最后的响应: ", end="")
            for final_processed_chunk in response.iter_content(chunk_size=None, decode_unicode=True):
                if final_processed_chunk:
                    # [MODIFIED] 同样地，既实时打印，也添加到列表中
                    print(final_processed_chunk, end="", flush=True)
                    full_response_chunks.append(final_processed_chunk)
            
    except requests.exceptions.RequestException as e:
        print(f"发送结束信号失败: {e}")

    # --- 6. 在程序最后，完整输出所有接收到的响应 ---
    # 这部分逻辑保持不变，因为它已经实现了“最后输出完整”的需求
    print("\n\n" + "="*50)
    print("客户端: 会话结束。完整的最终响应如下:")
    print("="*50)
    final_text = "".join(full_response_chunks)
    print(final_text)
    print("="*50)


if __name__ == '__main__':
    # 确保您的护栏服务 (app_implicit_session.py) 正在运行，然后再运行此脚本。
    run_implicit_streaming_test()