"""Simple multi-table integration test covering create_policy and check_query."""

import json
import requests

API_BASE = "http://127.0.0.1:8888/api/v1"
POLICY_ID = "riddle_policy"

USER_TABLE = (
	'{"user_id": "boss_001", "user_role": "boss", "attributes": {"team": "executive"}}\n'
	'{"user_id": "lead_001", "user_role": "team_lead", "attributes": {"team": "alpha"}}\n'
	'{"user_id": "staff_001", "user_role": "employee", "attributes": {"team": "alpha"}}'
)

DB_SCHEMA = [
	"""CREATE TABLE employee_profiles (
	user_id VARCHAR(32) PRIMARY KEY,
	name VARCHAR(64),
	title VARCHAR(64)
);""",
	"""CREATE TABLE compensation (
	user_id VARCHAR(32),
	monthly_salary INT,
	annual_bonus INT
);""",
]

NL_POLICY = """1. 老板 (boss) 可以查看任意员工在 A/B 表中的所有字段。
2. 组长 (team_lead) 可以查询普通员工 (employee) 的工资字段 (monthly_salary)，但不能看到 annual_bonus。
3. 普通员工 (employee) 只能查询自己的工资和年终奖信息。
"""

TEST_CASES = [
	{
		"description": "老板查询所有员工的职位、工资和年终奖",
		"payload": {
			"policy_id": POLICY_ID,
			"user_id": "boss_001",
			"query": "列出所有员工的姓名、职位、工资和年终奖",
			"conversation_history": [],
		},
		"expected_status": 200,
		"expected_decision": {"ALLOW", "REWRITE"},
	},
	{
		"description": "组长查询普通员工工资 (允许)",
		"payload": {
			"policy_id": POLICY_ID,
			"user_id": "lead_001",
			"query": "查看所有普通员工的工资",
			"conversation_history": [],
		},
		"expected_status": 200,
		"expected_decision": {"ALLOW", "REWRITE"},
	},
	{
		"description": "组长尝试查看年终奖 (应剥离或拒绝)",
		"payload": {
			"policy_id": POLICY_ID,
			"user_id": "lead_001",
			"query": "查询所有普通员工的工资和年终奖",
			"conversation_history": [],
		},
		"expected_status": 200,
		"expected_decision": {"REWRITE", "DENY"},
	},
	{
		"description": "普通员工查看自己的工资和年终奖",
		"payload": {
			"policy_id": POLICY_ID,
			"user_id": "staff_001",
			"query": "帮我查一下我的工资和年终奖",
			"conversation_history": [],
		},
		"expected_status": 200,
		"expected_decision": {"ALLOW", "REWRITE"},
	},
	{
		"description": "普通员工查看其他人的工资 (应拒绝)",
		"payload": {
			"policy_id": POLICY_ID,
			"user_id": "staff_001",
			"query": "查看老板的工资",
			"conversation_history": [],
		},
		"expected_status": 200,
		"expected_decision": {"DENY"},
	},
]


def _print_json(response: requests.Response) -> None:
	try:
		print(json.dumps(response.json(), indent=2, ensure_ascii=False))
	except requests.exceptions.JSONDecodeError:
		print(response.text)


def create_policy() -> None:
	url = f"{API_BASE}/create_policy"
	payload = {
		"policy_id": POLICY_ID,
		"user_table": USER_TABLE,
		"db_schema": DB_SCHEMA,
		"nl_policy": NL_POLICY,
	}

	print(f"POST {url}")
	print(json.dumps(payload, indent=2, ensure_ascii=False))

	try:
		response = requests.post(url, json=payload)
	except requests.exceptions.RequestException as exc:
		print(f"请求失败: {exc}")
		return

	print(f"状态码: {response.status_code}")
	_print_json(response)


def check_query() -> None:
	url = f"{API_BASE}/check_query"
	for case in TEST_CASES:
		print("\n==============================")
		print(f"场景: {case['description']}")
		print(f"请求: {json.dumps(case['payload'], indent=2, ensure_ascii=False)}")

		try:
			response = requests.post(url, json=case["payload"])
		except requests.exceptions.RequestException as exc:
			print(f"请求失败: {exc}")
			continue

		print(f"状态码: {response.status_code}")
		if response.status_code != case["expected_status"]:
			print("Unexpected status, body: ")
			print(response.text)
			continue

		_print_json(response)
		try:
			decision = response.json().get("decision")
		except requests.exceptions.JSONDecodeError:
			decision = None

		if decision in case["expected_decision"]:
			print(f"✅ 决策 {decision} 在预期范围 {case['expected_decision']}")
		else:
			print(f"⚠️ 决策 {decision} 不在预期范围 {case['expected_decision']}")


if __name__ == "__main__":
	# create_policy()
	check_query()
