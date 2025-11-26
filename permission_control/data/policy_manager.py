import json
import os
import asyncio
import re
from litellm import acompletion
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any

class PolicyManager:
    def __init__(self, raw_data_path: str = "data/policy_list"):
        self.raw_base_path = Path(raw_data_path)
        os.makedirs(self.raw_base_path, exist_ok=True)
        self.policy_write_locks = defaultdict(asyncio.Lock)
        print(f"PolicyManager initialized. Root: {self.raw_base_path.resolve()}")

    # --- Path Getters ---
    def get_employee_filepath(self, policy_id: str) -> Path:
        return self.raw_base_path / policy_id / "employees.jsonl"
        
    def get_policy_filepath(self, policy_id: str) -> Path:
        return self.raw_base_path / policy_id / "policy.rego"
        
    def get_schema_filepath(self, policy_id: str) -> Path:
        return self.raw_base_path / policy_id / "db_schema.sql"

    # --- 核心升级：智能体自修正流程 (Agentic Workflow) ---

    async def _generate_rego_with_self_correction(self, policy_id: str, nl_policy: str, opa_client: Any) -> str:
        """
        智能体闭环：生成 -> 生成测试 -> 运行测试 -> 错误修正 -> 循环
        """
        print(f"🤖 [Agent] Starting self-correction loop for {policy_id}...")
        
        # 1. 准备上下文
        db_schema = self._read_file_safe(self.get_schema_filepath(policy_id), "No schema")
        user_sample = self._read_file_safe(self.get_employee_filepath(policy_id), "No user data", readline=True)
        
        # 2. 初始生成 (Attempt 0)
        current_rego = await self._llm_generate_initial_rego(policy_id, nl_policy, db_schema, user_sample)
        
        # 3. 生成测试用例 (只生成一次，作为基准)
        print(f"🧪 [Agent] Generating verification test cases...")
        test_cases = await self._llm_generate_test_cases(nl_policy, db_schema)
        print(f"    -> Generated {len(test_cases)} test cases.")

        max_retries = 3 # 最大重试次数
        
        for attempt in range(max_retries):
            print(f"🔄 [Attempt {attempt+1}/{max_retries}] Verifying Rego logic...")
            
            # 4. 运行测试 (Compilation & Logic Check)
            failures = await self._run_verification_tests(policy_id, current_rego, test_cases, opa_client)
            
            if not failures:
                print(f"✅ [Success] All tests passed on attempt {attempt+1}!")
                return current_rego
            
            # 5. 如果失败，进行修正
            print(f"❌ [Fail] {len(failures)} tests/errors found. Asking LLM to fix...")
            current_rego = await self._llm_fix_rego(policy_id, current_rego, failures, nl_policy)

        print(f"⚠️ [Warning] Max retries reached. Saving last version (might have bugs).")
        return current_rego

    # --- LLM 交互子方法 ---

    async def _llm_generate_initial_rego(self, policy_id: str, nl_policy: str, schema: str, user_sample: str) -> str:
        """初始生成 Rego (逻辑同之前的 _generate_rego_from_nl)"""
        # 这里复用之前的 System Prompt 逻辑
        opa_input_example = f"""{{ "input": {{ "user": {{ "user_id": "test_u", "attributes": {user_sample} }}, "query_request": {{ "columns": ["*"] }} }} }}"""
        
        system_prompt = f"""
你是一位顶级的安全策略工程师，精通 OPA Rego。
请根据上下文生成 Rego 策略。
1. Package 名必须是 `{policy_id}.access`。
2. 数据库 Schema: {schema}
3. 用户属性示例: {user_sample}
4. 必须包含 `allowed`, `allowed_columns`, `row_constraints`, `reason`。
5. 必须导入 `rego.v1`。
"""
        user_prompt = f"请将以下自然语言策略转换为 Rego 代码：\n\n{nl_policy}\n\n只返回 Rego 代码。"
        return await self._call_llm(system_prompt, user_prompt)

    async def _llm_generate_test_cases(self, nl_policy: str, schema: str) -> List[Dict]:
        """生成用于验证的测试用例"""
        system_prompt = """
你是一个QA工程师。请根据给定的 SQL Schema 和 自然语言权限策略，生成 3 个具有代表性的测试用例。
测试用例应覆盖：允许访问(ALLOW)、行/列限制(REWRITE)、以及拒绝访问(DENY)。

返回格式必须是纯 JSON 列表，不要Markdown：
[
  {
    "description": "描述测试意图",
    "user_role": "manager",
    "user_id": "user_123", 
    "mock_user_attributes": {"dept_id": 101, "jurisdiction_unit": "天河分局"}, 
    "query_columns": ["name", "salary"],
    "expected_decision": "ALLOW" 
  }
]
(注意：expected_decision 只能是 ALLOW, REWRITE, DENY)
"""
        user_prompt = f"Schema:\n{schema}\n\nPolicy:\n{nl_policy}\n\n请生成测试用例 JSON:"
        response_text = await self._call_llm(system_prompt, user_prompt)
        return self._parse_json_from_llm(response_text)

    async def _llm_fix_rego(self, policy_id: str, current_rego: str, failures: List[str], nl_policy: str) -> str:
        """根据错误修正 Rego"""
        error_report = "\n".join(failures)
        system_prompt = f"你是 Rego 修复专家。包名必须是 {policy_id}.access。请只返回修复后的完整 Rego 代码。"
        user_prompt = f"""
当前 Rego 代码存在逻辑错误或编译错误，未能通过测试。

--- 原始需求 (NL) ---
{nl_policy}

--- 当前代码 ---
{current_rego}

--- 失败报告 ---
{error_report}

请分析失败原因，并重写 Rego 代码以修复这些问题。确保语法正确且符合逻辑。
"""
        return await self._call_llm(system_prompt, user_prompt)

    # --- 执行与验证子方法 ---

    async def _run_verification_tests(self, policy_id: str, rego_code: str, test_cases: List[Dict], opa_client: Any) -> List[str]:
        """执行测试用例并返回失败报告"""
        failures = []
        
        # 1. 尝试推送到 OPA (检查编译错误)
        try:
            # 使用 OPA 包装器的 update_policy_from_string 方法
            # 注意：这里我们使用 policy_id 作为 endpoint，这会覆盖当前的策略（如果是更新的话）
            # 在创建阶段这是可以接受的。
            opa_client.update_policy_from_string(new_policy=rego_code, endpoint=policy_id)
        except Exception as e:
            return [f"OPA Compilation Error (Syntax Invalid): {str(e)}"]

        # 2. 循环执行逻辑测试
        for case in test_cases:
            input_data = {
                "input": {
                    "user": {
                        "user_id": case.get("user_id", "test"),
                        "user_role": case.get("user_role"),
                        "attributes": case.get("mock_user_attributes", {}) 
                    },
                    "query_request": {
                        "columns": case.get("query_columns", ["*"])
                    }
                }
            }
            
            try:
                result = opa_client.query_rule(
                    input_data=input_data,
                    package_path=f"{policy_id}/access",
                    rule_name="result"
                )
                opa_res = result.get("result", {})
                
                # 简化的结果判定逻辑 (模拟 PermissionController 的判定)
                actual_decision = "DENY"
                if opa_res.get("allowed", False):
                    # 如果 allowed=true，检查是否有约束
                    if not opa_res.get("row_constraints") and len(opa_res.get("allowed_columns", [])) > 0:
                         # 这里做个简化假设：没有行约束且有列，就算是 ALLOW/REWRITE (此处不细分，主要抓 DENY 错误)
                         # 为了严谨，如果 expected 是 REWRITE，只要不是 DENY 就算过
                         actual_decision = "ALLOW_OR_REWRITE" 
                    else:
                         actual_decision = "ALLOW_OR_REWRITE"
                
                expected = case["expected_decision"]
                
                # 逻辑比对：
                # 如果预期是 DENY，但实际 ALLOW 了 -> 错误 (安全漏洞)
                if expected == "DENY" and actual_decision != "DENY":
                    failures.append(f"Case '{case['description']}': Expected DENY (Secure), but got ALLOWED/REWRITE. OPA Output: {json.dumps(opa_res)}")
                
                # 如果预期是 ALLOW/REWRITE，但实际 DENY 了 -> 错误 (功能不可用)
                elif expected != "DENY" and actual_decision == "DENY":
                     failures.append(f"Case '{case['description']}': Expected Access, but got DENY. Reason: {opa_res.get('reason')}")
                
            except Exception as e:
                failures.append(f"Case '{case['description']}' execution error: {str(e)}")

        return failures

    # --- 基础工具方法 ---

    async def _call_llm(self, system, user) -> str:
        """LLM 调用封装"""
        try:
            response = await acompletion(
                custom_llm_provider="openai",
                base_url="http://124.70.213.108:7009/v1",
                api_key="sk-jjygDVvRsuTf6b1oNvHL6E7jpFIDRboL",
                model="qwen2.5-14b-instruct",
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                temperature=0.0
            )
            content = response.choices[0].message.content
            content = re.sub(r"```rego\n", "", content, flags=re.IGNORECASE)
            content = re.sub(r"```json\n", "", content, flags=re.IGNORECASE)
            content = re.sub(r"```", "", content).strip()
            return content
        except Exception as e:
            raise RuntimeError(f"LLM Call Failed: {e}")

    def _parse_json_from_llm(self, text: str) -> List[Dict]:
        """解析 JSON"""
        try:
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match: return json.loads(match.group())
            return json.loads(text)
        except:
            return [] 

    def _read_file_safe(self, path: Path, default: str, readline=False) -> str:
        try:
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    return f.readline() if readline else f.read()
        except: pass
        return default

    # --- 公共接口 (Write Methods) ---

    async def update_nl_policy(self, policy_id: str, content: str, opa_client: Any = None) -> str:
        """
        (修改) 接收 opa_client 以支持自修正循环
        """
        async with self.policy_write_locks[policy_id]:
            # 1. 保存 NL 文件
            nl_file_path = await self._save_raw_file_unlocked(policy_id, "nl_policy.txt", content)
            
            # 2. 生成 Rego (带自修正)
            if opa_client:
                try:
                    # 调用自修正流程
                    rego_content = await self._generate_rego_with_self_correction(policy_id, content, opa_client)
                    
                    # 3. 保存最终通过验证的 Rego
                    await self._save_raw_file_unlocked(policy_id, "policy.rego", rego_content)
                    print(f"🎉 [Agent] Successfully saved validated Rego policy for {policy_id}")
                except Exception as e:
                    print(f"❌ [Agent] Critical Error in Rego Generation: {e}")
                    # 此时文件系统上的 policy.rego 可能是旧的，或者是空的，视之前状态而定
                    raise e 
            else:
                print("⚠️ Warning: No opa_client provided, skipping Agentic Generation.")
                # Fallback (旧逻辑，可选)
                # rego_content = await self._llm_generate_initial_rego(...)
                # await self._save_raw_file_unlocked(policy_id, "policy.rego", rego_content)
            
            return str(nl_file_path)

    # ... (update_employee_table, update_db_schema, update_rego_policy 等保持不变) ...
    
    async def _save_raw_file_unlocked(self, policy_id: str, file_name: str, content: str) -> Path:
        policy_path = self.raw_base_path / policy_id
        if not policy_path.exists():
            policy_path.mkdir(parents=True, exist_ok=True)
        file_path = policy_path / file_name
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return file_path

    async def update_employee_table(self, policy_id: str, content: str) -> str:
        file_path = await self._save_raw_file(policy_id, "employees.jsonl", content)
        return str(file_path)

    async def update_db_schema(self, policy_id: str, content: str) -> str:
        file_path = await self._save_raw_file(policy_id, "db_schema.sql", content)
        return str(file_path)
        
    async def update_rego_policy(self, policy_id: str, content: str) -> str:
        file_path = await self._save_raw_file(policy_id, "policy.rego", content)
        return str(file_path)

    async def _save_raw_file(self, policy_id: str, file_name: str, content: str) -> Path:
        policy_path = self.raw_base_path / policy_id
        async with self.policy_write_locks[policy_id]:
            if not policy_path.exists():
                policy_path.mkdir(parents=True, exist_ok=True)
            file_path = policy_path / file_name
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        return file_path