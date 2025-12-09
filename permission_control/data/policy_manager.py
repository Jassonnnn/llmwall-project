import json
import os
import asyncio
import re
from litellm import acompletion
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any, Tuple

class PolicyManager:
    """
    (V2 架构) 策略文件管理器
    职责: 负责所有策略和数据文件的写入 (Write)，以及 智能体自修正 (Agentic Workflow) 的编排。
    """
    def __init__(self, raw_data_path: str = "data/policy_list"):
        # 原始策略/Schema文件的路径
        self.raw_base_path = Path(raw_data_path)
        os.makedirs(self.raw_base_path, exist_ok=True)
        
        # 为每个策略组(原租户)的文件提供一个锁，以防止 *写入* 冲突
        self.policy_write_locks = defaultdict(asyncio.Lock)
        
        print(f"PolicyManager initialized. ")
        print(f"  -> Raw config (file) data: {self.raw_base_path.resolve()}")

    # --- Path Getters (获取文件路径) ---
    
    def get_employee_filepath(self, policy_id: str) -> Path:
        """获取员工表文件的路径"""
        return self.raw_base_path / policy_id / "employees.jsonl"
        
    def get_policy_filepath(self, policy_id: str) -> Path:
        """获取策略文件的路径"""
        return self.raw_base_path / policy_id / "policy.rego"
        
    def get_schema_filepath(self, policy_id: str) -> Path:
        """获取 Schema 文件的路径"""
        return self.raw_base_path / policy_id / "db_schema.sql"

    # --- 核心逻辑：NL-to-Rego 转换入口 ---

    async def _generate_rego_from_nl(self, policy_id: str, nl_policy: str, opa_client: Any = None) -> str:
        """
        (核心方法) 将自然语言策略转换为 Rego 策略。
        逻辑：准备上下文 -> 判断是否有 opa_client -> 分发到简单生成或自修正生成。
        """
        print(f"Generating Rego from NL for policy {policy_id}...")
        
        # 1. 准备上下文 (Schema 和 用户示例)
        db_schema_content = self._read_file_safe(self.get_schema_filepath(policy_id), "No db_schema.sql found.")
        user_sample = self._read_file_safe(self.get_employee_filepath(policy_id), "No employees.jsonl found.", readline=True)

        # 2. 构造通用的 System Prompt
        system_prompt = self._get_rego_system_prompt(policy_id, db_schema_content, user_sample)

        # --- 分支 A: 简单生成 (无 OPA 客户端，无法测试) ---
        if not opa_client:
            print("⚠️ Warning: No opa_client provided, skipping Agentic validation (Simple Generation Mode).")
            return await self._llm_generate_initial_rego(nl_policy, system_prompt)

        # --- 分支 B: 智能体自修正循环 (Agentic Workflow) ---
        return await self._generate_rego_with_self_correction(
            policy_id, nl_policy, opa_client, system_prompt, db_schema_content
        )

    # --- 智能体自修正流程 (Agentic Workflow) ---

    async def _generate_rego_with_self_correction(self, policy_id: str, nl_policy: str, opa_client: Any, system_prompt: str, db_schema_content: str) -> str:
        """
        智能体闭环：生成 -> 生成测试 -> 运行测试 -> 错误修正 -> 循环
        """
        print(f"🤖 [Agent] Starting self-correction loop for {policy_id}...")
        
        # Step 1: 初始生成 (Draft)
        print("✍️  [Agent] Drafting initial Rego code...")
        current_rego = await self._llm_generate_initial_rego(nl_policy, system_prompt)
        
        # Step 2: 生成测试用例 (只生成一次，作为固定标准)
        print(f"🧪 [Agent] Generating verification test cases...")
        test_cases = await self._llm_generate_test_cases(nl_policy, db_schema_content)
        print(f"📋 [Agent] Generated {len(test_cases)} test cases:")
        print(json.dumps(test_cases, indent=2, ensure_ascii=False))
        print("-" * 50)

        max_retries = 5
        
        for attempt in range(max_retries):
            print(f"\n🔄 [Attempt {attempt+1}/{max_retries}] Verifying Rego logic...")
            print(f"📝 [Current Rego Code]:\n{'-'*20}\n{current_rego}\n{'-'*20}")
            
            # Step 3: 运行测试 (Execution & Verification)
            failures, pass_count, total_count = await self._run_verification_tests(policy_id, current_rego, test_cases, opa_client)
            
            print(f"📊 [Result] {pass_count}/{total_count} Passed.")
            
            if not failures:
                print(f"✅ [Success] All tests passed on attempt {attempt+1}!")
                return current_rego
            
            # Step 4: 失败修正 (Refinement)
            print(f"❌ [Fail] Found {len(failures)} errors. Asking LLM to fix...")
            for i, fail in enumerate(failures, 1):
                print(f"   ERR #{i}: {fail[:300]}..." if len(fail) > 300 else f"   ERR #{i}: {fail}")

            current_rego = await self._llm_fix_rego(policy_id, current_rego, failures, nl_policy, system_prompt)

        print(f"⚠️ [Warning] Max retries reached. Saving last version (might have bugs).")
        return current_rego

    # --- LLM 交互子方法 ---

    async def _llm_generate_initial_rego(self, nl_policy: str, system_prompt: str) -> str:
        """
        [优化] 初始生成 Rego
        加强了 User Prompt，强制要求完整性、禁止 Markdown。
        """
        user_prompt = f"""
任务：将以下自然语言策略转换为 OPA Rego 代码。

--- 自然语言策略 (NL Policy) ---
{nl_policy}

--- 关键要求 (CRITICAL INSTRUCTIONS) ---
1. **完整性**：生成的 Rego 必须完整包含 `package`, `import`, `default`, `roles`, `valid_row_filters` 以及核心逻辑规则。
2. **列名全集**：必须在代码顶部定义 `all_db_columns`，必须包含 Schema 中的**所有**列名，**绝对不要省略**任何一列。
3. **纯代码输出**：直接输出 Rego 代码文本。**严禁**使用 ```rego``` 或 ``` 包裹代码。**严禁**在代码前后添加任何解释性文字。
4. **默认拒绝**：必须包含 `default allow := false`。
5. **属性安全**：在定义 `roles` 映射时，确保每个角色（即使不需要排除列）都有 `excluded_columns: []` 字段，防止运行时属性缺失错误。

请立即生成代码：
"""
        return await self._call_llm(system_prompt, user_prompt)

    async def _llm_generate_test_cases(self, nl_policy: str, schema: str) -> List[Dict]:
        """生成用于验证的测试用例"""
        system_prompt = """
你是一个高级 QA 工程师，专门负责测试安全策略的漏洞。
你的目标是生成一组 JSON 格式的测试用例，用于验证 OPA 策略是否符合自然语言需求。

### 测试用例设计原则：
1.  **覆盖率**：必须覆盖所有角色（Chief, Supervisor, Officer 等）。
2.  **正向测试**：生成应该被 `ALLOW` 的合法请求。
3.  **负向测试 (关键)**：生成应该被 `DENY` 的越权请求。
4.  **边界测试**：生成应该触发 `REWRITE` 的请求。

### 输出格式要求：
*   必须是纯 JSON 数组列表 `[...]`。
*   **严禁**使用 Markdown 格式（不要 ```json）。
*   JSON 字段必须包含：`description`, `user_role`, `user_id`, `mock_user_attributes` (必须符合逻辑), `query_columns`, `expected_decision`。
*   `expected_decision` 只能是：`ALLOW`, `REWRITE`, `DENY`。
"""
        user_prompt = f"Schema:\n{schema}\n\nPolicy:\n{nl_policy}\n\n请生成测试用例 JSON:"
        response_text = await self._call_llm(system_prompt, user_prompt)
        return self._parse_json_from_llm(response_text)

    async def _llm_fix_rego(self, policy_id: str, current_rego: str, failures: List[str], nl_policy: str, base_system_prompt: str) -> str:
        """根据错误修正 Rego"""
        error_report = "\n".join(failures)
        user_prompt = f"""
当前 Rego 代码未能通过测试。请根据失败报告修复代码。

--- 原始需求 (NL) ---
{nl_policy}

--- 当前有问题代码 ---
{current_rego}

--- 失败报告 ---
{error_report}

请分析失败原因，并重写 Rego 代码以修复这些问题。
1. 确保 `allowed_columns` 逻辑正确处理通配符和排除逻辑。
2. 确保 `row_constraints` 逻辑正确处理 OR/AND 关系。
3. 确保所有角色属性存在性检查（例如 excluded_columns）。
4. 修复任何 OPA 编译错误。

请只返回修复后的完整 Rego 代码。
"""
        return await self._call_llm(base_system_prompt, user_prompt)

    # --- OPA 执行与验证方法 ---

    async def _run_verification_tests(self, policy_id: str, rego_code: str, test_cases: List[Dict], opa_client: Any) -> Tuple[List[str], int, int]:
        failures = []
        pass_count = 0
        total_count = len(test_cases)
        
        try:
            opa_client.update_policy_from_string(new_policy=rego_code, endpoint=policy_id)
        except Exception as e:
            return [f"OPA Compilation Error (Syntax Invalid): {str(e)}"], 0, total_count

        for i, case in enumerate(test_cases, 1):
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
                
                actual_decision = "DENY"
                if opa_res.get("allowed", False):
                    if not opa_res.get("row_constraints") and len(opa_res.get("allowed_columns", [])) > 0:
                         actual_decision = "ALLOW"
                    else:
                         actual_decision = "REWRITE"
                
                expected = case["expected_decision"]
                
                is_fail = False
                fail_msg = ""

                if expected == "DENY" and actual_decision != "DENY":
                    is_fail = True
                    fail_msg = f"Expected DENY, got {actual_decision}. OPA Output: {json.dumps(opa_res)}"
                elif expected != "DENY" and actual_decision == "DENY":
                    is_fail = True
                    fail_msg = f"Expected {expected}, got DENY. Reason: {opa_res.get('reason')}"
                
                if is_fail:
                    failures.append(f"Test #{i} ('{case['description']}'): {fail_msg}")
                else:
                    pass_count += 1
                
            except Exception as e:
                failures.append(f"Test #{i} Execution Error: {str(e)}")

        return failures, pass_count, total_count

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
            # 强制提取代码块
            code_block_pattern = r"```(?:rego)?\s*(.*?)```"
            match = re.search(code_block_pattern, content, re.DOTALL)
            if match:
                return match.group(1).strip()
            else:
                content = re.sub(r"```rego", "", content)
                content = re.sub(r"```", "", content)
                return content.strip()
        except Exception as e:
            raise RuntimeError(f"LLM Call Failed: {e}")

    def _parse_json_from_llm(self, text: str) -> List[Dict]:
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

    def _get_rego_system_prompt(self, policy_id, schema, user_sample):
        """获取完整的 System Prompt (包含详细的 Rego 模板)"""
        opa_input_example = f"""
# OPA Input 结构示例
{{
  "input": {{
    "user": {{ "user_id": "u1", "attributes": {user_sample} }},
    "query_request": {{ "columns": ["salary"], "query_type": "select" }}
  }}
}}
"""
        return f"""
你是一位顶级的安全策略工程师，精通 OPA (Open Policy Agent) 及其 Rego 语言。
你的核心任务是将用户提供的自然语言 (NL) 规则，转换为一个**完整、健壮且可立即执行的 Rego 策略文件**。

---
### 核心指令

你的回答**必须**从 `package {policy_id}.access` 这一行开始，并包含一个完整的 Rego 策略。
你**必须**严格遵循下面的代码结构模板，**不要修改模板中的核心逻辑（特别是列访问逻辑）**，只需要根据用户的 NL 规则填充 `roles` 和 `row_constraints` 部分。

---
### 上下文信息
1. **数据库 Schema**: 
{schema}

2. **用户属性示例**: 
{user_sample}

3. **租户 ID**: {policy_id}

---
### 最终 Rego 代码结构 (必须严格复制并填充)

```rego
package {policy_id}.access

import rego.v1

# 1. 默认值
default allow := false
default allowed_columns := []
default row_constraints := {{}}
default reason := "Access denied by default. No rules matched."

# --- 关键：必须从 Schema 中提取所有列名，填入这里 ---
all_db_columns := [
    # 请根据 SQL Schema 填入所有列名，例如 "id", "name", "salary"...
]

# 2. 角色定义 (请根据 NL 规则填充这里)
# 注意：key 必须是小写 (例如 "manager")，与 user_role 匹配
roles := {{
    # 示例模板:
    # "role_name": {{
    #     "description": "描述",
    #     "allowed_columns": all_db_columns, # 或具体列表 ["id", "name"]
    #     "row_filter": "filter_name",
    #     "excluded_columns": [] # 如果没有排除，必须留空数组
    # }}
}}

# 3. 辅助变量
user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

# 3b. 有效过滤器注册 (请将你用到的 row_filter 名字加进去)
valid_row_filters := {{
    "all", "self_only"
    # ... 添加你的 filter ...
}}

# 4. 列访问逻辑 (核心逻辑 - 请勿修改结构)
allowed_columns := final_allowed if {{
    user_role := input.user.user_role
    role_config := roles[user_role]
    
    # 1. 确定基准列集
    is_wildcard_allowed := true if {{
        some idx; role_config.allowed_columns[idx] == "*"
    }} else := false

    base_columns_set := set(all_db_columns) if {{
        is_wildcard_allowed
    }} else := set(role_config.allowed_columns)

    # 2. 应用黑名单 (excluded_columns)
    blacklisted := set(role_config.excluded_columns)
    base_columns_after_exclusion := base_columns_set - blacklisted

    # 3. 应用请求交集
    requested := set(input.query_request.columns)
    requested_is_wildcard := true if {{
        some idx; input.query_request.columns[idx] == "*"
    }} else := false
    
    final_allowed_set := base_columns_after_exclusion & requested if {{
        not requested_is_wildcard
    }} else := base_columns_after_exclusion

    final_allowed := array.sort(array.concat([], final_allowed_set))
    true
}}

# 5. 行访问逻辑 (请根据 NL 规则编写具体实现)

# 示例：无限制
row_constraints := {{}} if {{ role_config.row_filter == "all" }}

# 示例：仅自己
row_constraints := {{"id": user_id}} if {{ role_config.row_filter == "self_only" }}

# ---在此处根据 NL 规则添加更多 row_constraints---
# 例如: 
# row_constraints := {{"dept_id": input.user.dept_id}} if {{ role_config.row_filter == "dept_match" }}


# 5b. 拒绝无效 row_filter
row_constraints := {{"deny": true}} if {{
    role_config
    not role_config.row_filter in valid_row_filters
}}

# 6. 最终裁决
allow if {{
    role_config
    count(allowed_columns) > 0
    not row_constraints.deny
}}

# 7. 决策理由
reason := sprintf("Access Granted for %s", [role_config.description]) if {{ allow }}
reason := "Access Denied: This role is not defined in the policy." if {{ not allow; not role_config }}
reason := "Access Denied: Column restriction." if {{ not allow; role_config; count(allowed_columns) == 0 }}
reason := "Access Denied: Row restriction." if {{ not allow; role_config; row_constraints.deny }}

# 8. 输出结果
result := {{
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}}
"""
# --- 公共接口 (Write Methods) ---

    async def update_nl_policy(self, policy_id: str, content: str, opa_client: Any = None) -> str:
        """
        (修改) 接收 opa_client 以支持自修正循环
        """
        async with self.policy_write_locks[policy_id]:
            # 1. 保存 NL 文件
            nl_file_path = await self._save_raw_file_unlocked(policy_id, "nl_policy.txt", content)
            
            # 2. 生成 Rego (统一调用 _generate_rego_from_nl)
            print(f"NL policy updated. Triggering Rego generation for {policy_id}...")
            try:
                # 无论是否传入 opa_client，都调用此入口，函数内部会判断
                rego_content = await self._generate_rego_from_nl(policy_id, content, opa_client)
                
                # 3. 保存生成的Rego策略
                await self._save_raw_file_unlocked(policy_id, "policy.rego", rego_content)
                
                if opa_client:
                    print(f"🎉 [Agent] Successfully saved validated Rego policy for {policy_id}")
                else:
                    print(f"✅ Successfully saved Rego policy (Simple Mode) for {policy_id}")
                    
            except Exception as e:
                print(f"Error during auto-generation of Rego: {e}")
                # 抛出异常通知上层
                raise e
            
            return str(nl_file_path)

    async def _save_raw_file_unlocked(self, policy_id: str, file_name: str, content: str) -> Path:
        """非锁定版本，供 update_nl_policy 内部使用"""
        policy_path = self.raw_base_path / policy_id
        if not policy_path.exists():
            policy_path.mkdir(parents=True, exist_ok=True)
        file_path = policy_path / file_name
        print(f"Writing raw file: {file_path}")
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