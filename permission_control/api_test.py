import requests
import json


def _print_json_response(response: requests.Response):
    """Pretty-print helper to keep logs consistent."""
    try:
        print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    except requests.exceptions.JSONDecodeError:
        print(response.text)

def create_policy():
    """
    向 /api/v1/create_policy 发送 POST 请求并打印响应。
    """
    # API 端点 URL
    url = "http://127.0.0.1:11514/api/v1/create_policy"

    # 根据您提供的 schema 准备要发送的数据
    # 您需要将 "your_tenant_id", "your_table_name", 和 "your_policy_string"
    # 替换为实际的值。
    payload = {
        "tenant_id": "lotato",
        "user_table": (
            '{"user_id": "emp_manager", "user_role": "manager", "attributes": {"department": "Sales"}}\n'
            '{"user_id": "emp_regular", "user_role": "employee", "attributes": {"department": "Support"}}'
        ),
        "db_schema": "CREATE TABLE employees (id varchar(100), name varchar(100), salary int, department varchar(50));",
        "nl_policy": "管理者(manager) 可以查看所有员工的信息，包括姓名、部门和薪资。普通员工(employee) 只能查看自己的姓名和部门信息。"
    }

    # 设置请求头，指明我们发送的是 JSON
    headers = {
        "Content-Type": "application/json"
    }

    print(f"正在向 {url} 发送 POST 请求...")
    print(f"发送的数据: {json.dumps(payload, indent=2)}")

    try:
        # 发送 POST 请求
        # 我们使用 json=payload，requests 库会自动处理序列化和设置 Content-Type
        response = requests.post(url, json=payload)

        if response.status_code == 200:
            print("\n--- 请求成功 (Status Code: 200) ---")
            print("收到的回复 (JSON):")
            _print_json_response(response)
        else:
            print(f"\n--- 请求失败 (Status Code: {response.status_code}) ---")
            print("收到的回复:")
            print(response.text)

    except requests.exceptions.ConnectionError as e:
        print(f"\n--- 连接错误 ---")
        print(f"无法连接到 {url}。请确保服务正在运行且地址正确。")
        print(f"错误详情: {e}")
    except Exception as e:
        print(f"\n--- 发生未知错误 ---")
        print(f"错误详情: {e}")


def check_query():
    """针对 /api/v1/check_query 的简单集成测试。"""

    url = "http://127.0.0.1:11514/api/v1/check_query"

    test_cases = [
        {
            "description": "管理者查看所有员工的姓名和薪资",
            "payload": {
                "tenant_id": "lotato",
                "user_id": "emp_manager",
                "query": "帮我查看所有员工的姓名和薪资",
                "conversation_history": [],
            },
            "expected_status": 200,
            "expected_decision": {"ALLOW"},
        },
        {
            "description": "普通员工尝试查看所有人的薪资",
            "payload": {
                "tenant_id": "lotato",
                "user_id": "emp_regular",
                "query": "把所有员工的工资发给我",
                "conversation_history": [],
            },
            "expected_status": 200,
            "expected_decision": {"REWRITE", "DENY"},
        },
    ]

    for case in test_cases:
        print("\n==============================")
        print(f"测试场景: {case['description']}")
        print(f"请求参数: {json.dumps(case['payload'], indent=2, ensure_ascii=False)}")

        try:
            response = requests.post(url, json=case["payload"])
        except requests.exceptions.ConnectionError as e:
            print("连接错误: 无法访问 check_query 接口。请确认服务已启动。")
            print(f"错误详情: {e}")
            continue
        except Exception as e:
            print("发生未知错误:")
            print(f"错误详情: {e}")
            continue

        print(f"响应状态码: {response.status_code}")
        if response.status_code == case["expected_status"]:
            print("响应体:")
            _print_json_response(response)

            try:
                decision = response.json().get("decision")
            except requests.exceptions.JSONDecodeError:
                decision = None

            if decision in case["expected_decision"]:
                print(f"✅ 决策 {decision} 符合预期范围 {case['expected_decision']}")
            else:
                print(
                    f"⚠️ 决策 {decision} 不在预期范围 {case['expected_decision']} 内，请检查策略或服务日志。"
                )
        else:
            print("Unexpected status code, 响应体如下:")
            print(response.text)

if __name__ == "__main__":
    create_policy()
    check_query()