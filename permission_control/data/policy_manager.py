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

    async def _generate_rego_from_nl(self, policy_id: str, nl_policy: str, opa_client: Any = None, use_agent: bool = False) -> str:
        """
        (核心方法) 将自然语言策略转换为 Rego 策略。
        逻辑：
        - 如果 (opa_client 存在) AND (use_agent 为 True) -> 启用智能体自修正。
        - 否则 -> 仅执行单次简单生成 (快速模式)。
        """
        mode_str = "Agentic Mode" if (opa_client and use_agent) else "Simple Mode"
        print(f"Generating Rego from NL for policy {policy_id} ({mode_str})...")
        
        # 1. 准备上下文
        db_schema_content = self._read_file_safe(self.get_schema_filepath(policy_id), "No db_schema.sql found.")
        user_sample = self._read_file_safe(self.get_employee_filepath(policy_id), "No employees.jsonl found.", readline=True)

        # 2. 构造 System Prompt
        system_prompt = self._get_rego_system_prompt(policy_id, db_schema_content, user_sample)

        # --- 判断分支 ---
        # 只有当客户端存在，且用户显式开启 Agent 时，才跑循环
        if opa_client and use_agent:
            # --- 分支 B: 智能体自修正循环 ---
            return await self._generate_rego_with_self_correction(
                policy_id, nl_policy, opa_client, system_prompt, db_schema_content
            )
        else:
            # --- 分支 A: 简单生成 (快速) ---
            if not opa_client:
                print("⚠️ Warning: No opa_client provided.")
            if not use_agent:
                print("ℹ️ Agent disabled by user request. Running single-pass generation.")
                
            user_prompt = f"请将以下自然语言策略转换为 Rego 代码：\n\n{nl_policy}\n\n请只返回 Rego 代码，不要包含 ```rego 或任何其他解释。"
            return await self._call_llm(system_prompt, user_prompt)

    # --- 智能体自修正流程 (Agentic Workflow) ---

    async def _generate_rego_with_self_correction(
        self,
        policy_id: str,
        nl_policy: str,
        opa_client: Any,
        system_prompt: str,
        db_schema_content: str,
    ) -> str:
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
            print(f"\n[Attempt {attempt+1}/{max_retries}] Verifying Rego logic...")
            print(f"[Current Rego Code]:\n{'-'*20}\n{current_rego}\n{'-'*20}")

            # Step 3: 运行测试 (Execution & Verification)
            failures, pass_count, total_count = await self._run_verification_tests(
                policy_id, current_rego, test_cases, opa_client
            )

            print(f"[Result] {pass_count}/{total_count} Passed.")

            if not failures:
                print(f"✅ [Success] All tests passed on attempt {attempt+1}!")
                return current_rego

            # Step 4: 失败修正 (Refinement)
            print(f"❌ [Fail] Found {len(failures)} errors. Asking LLM to fix...")
            for i, fail in enumerate(failures, 1):
                print(
                    f"   ERR #{i}: {fail[:300]}..."
                    if len(fail) > 300
                    else f"   ERR #{i}: {fail}"
                )

            current_rego = await self._llm_fix_rego(
                policy_id, current_rego, failures, nl_policy, system_prompt
            )

        print(
            f"⚠️ [Warning] Max retries reached. Saving last version (might have bugs)."
        )
        return current_rego

    # --- LLM 交互子方法 ---

    async def _llm_generate_initial_rego(
        self, nl_policy: str, system_prompt: str
    ) -> str:
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
        user_prompt = (
            f"Schema:\n{schema}\n\nPolicy:\n{nl_policy}\n\n请生成测试用例 JSON:"
        )
        response_text = await self._call_llm(system_prompt, user_prompt)
        return self._parse_json_from_llm(response_text)

    async def _llm_fix_rego(
        self,
        policy_id: str,
        current_rego: str,
        failures: List[str],
        nl_policy: str,
        base_system_prompt: str,
    ) -> str:
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

    async def _run_verification_tests(
        self, policy_id: str, rego_code: str, test_cases: List[Dict], opa_client: Any
    ) -> Tuple[List[str], int, int]:
        failures = []
        pass_count = 0
        total_count = len(test_cases)

        try:
            opa_client.update_policy_from_string(
                new_policy=rego_code, endpoint=policy_id
            )
        except Exception as e:
            return [f"OPA Compilation Error (Syntax Invalid): {str(e)}"], 0, total_count

        for i, case in enumerate(test_cases, 1):
            input_data = {
                "input": {
                    "user": {
                        "user_id": case.get("user_id", "test"),
                        "user_role": case.get("user_role"),
                        "attributes": case.get("mock_user_attributes", {}),
                    },
                    "query_request": {"columns": case.get("query_columns", ["*"])},
                }
            }

            try:
                result = opa_client.query_rule(
                    input_data=input_data,
                    package_path=f"{policy_id}/access",
                    rule_name="result",
                )
                opa_res = result.get("result", {})

                actual_decision = "DENY"
                if opa_res.get("allowed", False):
                    if (
                        not opa_res.get("row_constraints")
                        and len(opa_res.get("allowed_columns", [])) > 0
                    ):
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
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0.0,
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
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if match:
                return json.loads(match.group())
            return json.loads(text)
        except:
            return []

    def _read_file_safe(self, path: Path, default: str, readline=False) -> str:
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return f.readline() if readline else f.read()
        except:
            pass
        return default

    def _get_rego_system_prompt(self, policy_id, schema, user_sample):
        """获取完整的 System Prompt (包含详细的 Rego 模板)"""
        opa_input_example = f"""
# OPA Input 结构示例
{{
  "input": {{
    "user": {{ "user_id": "u1", "attributes": {user_sample} }},
    "query_request": {{ "tables": ["employees"], "columns": ["employees.salary"], "conditions": {{}}, "query_type": "select"}}
  }}
}}
"""
        return f"""
你是一位顶级的安全策略工程师，精通 OPA (Open Policy Agent) 及其 Rego 语言。
你的核心任务是将用户提供的自然语言 (NL) 规则，转换为一个**完整、健壮且可立即执行的 Rego 策略文件**。

---
### 核心指令

1.  **结构保持 (Critical)**：
    *   必须严格复制下方的 Rego 代码模板。
    *   **严禁修改** Section 3 (增强型时间引擎) 和 Section 4 (列逻辑) 以及Section 5.2 5.3 5.4 5.5 5.6（固定行处理逻辑）。
    *   你只需要填充 Section 1, Section 2, 和 Section 5.1。

2.  **AST 架构 (Strict Mode)**：
    *   在编写 Section 5.1 (`policy_scope`) 时，所有字段的约束值必须是 **操作符对象列表** (List of Objects)，即使只有一个条件。
    *   **错误写法**: `"dept": {{"op": "=", "val": "Sales"}}`
    *   **正确写法**: `"dept": [ {{"op": "=", "val": "Sales"}} ]`
    *   这是为了完美适配 `BETWEEN` 逻辑（可能包含两个条件）和多重过滤场景。

3.  **时间处理 (Token Aware)**：
    *   模板的 Section 3 已经内置了对标准时间 Token 的支持（如 `{{{{CURRENT_MONTH_START}}}}`, `{{{{AGO_HOUR_24}}}}` 等）。
    *   **不要**在 Rego 中手动编写复杂的日期计算逻辑。
    *   在 `policy_scope` 中，如果需要动态时间，请直接构造包含 Token 的字符串，引擎会自动解析。例如：`"val": "{{{{AGO_DAY_30}}}}"`。

4.  **逻辑核心：约束继承与分层解析 (Constraint Inheritance) [重点]**：
    *   **Layer 1: 识别全局边界 (Global Boundary)**
        *   分析 NL 规则的首句或通用描述。如果提到“基于 X 隔离”、“所有人只能访问归属于 X 的数据”，这属于**全局硬性约束**。
        *   **操作**：全局约束字段（如 `tenant_id`, `project_id`, `app_id` 等）必须**强制注入**到所有角色的 `policy_scope` 中。
    *   **Layer 2: 相对的“全部权限” (Relative "All")**
        *   **陷阱预警**：当规则描述高权限角色（如 Admin）可以查看“所有数据”时，通常是指“**当前全局边界内**的所有数据”。
        *   **禁止操作**：严禁将 Admin 的 scope 设为空对象 `{{}}`（这代表全库扫描），除非规则明确使用了“跨域 (Cross-domain)”、“全局透视”等突破性词汇。
        *   **正确逻辑**：`Admin_Scope = 全局边界字段 + {{}}`。

5.  **你需要填充的部分**：
    *   `all_db_columns`: 根据 Schema 填入所有 "Table.Column"。
    *   `roles`: 根据 NL 规则定义 `allowed_columns` 和 `row_filter_rule` 名称。
    *   `[Step 5.1]`: 编写具体的 if 逻辑，确保**每个分支**都正确继承了全局约束。
    
---
### 上下文信息
1. **数据库 Schema**: 
{schema}

2. **用户属性示例 (User Sample)**: 
{user_sample}

3. **策略 ID (Package Name)**: {policy_id}

---
### 最终 Rego 代码结构 (请逐字复制并填充标记部分)

```rego
package {policy_id}.access

import rego.v1

# =============================================================================
# 1. 默认设置 & 数据库全集
# =============================================================================
default allow := false 
default allowed_columns := []
default row_constraints := {{"deny": true}}
default reason := "Access denied by default."
default role_config := {{}}

# [需填充] 数据库全集
all_db_columns := {{
    # 示例: "orders.id", "orders.amount"
    # 请根据 Schema 完整填充
}}

# 2. 角色定义 (请根据 NL 规则填充这里,**注意**核心指令4)
roles := {{
    # 示例:
    # "manager": {{
    #     "description": "Department Manager",
    #     "allowed_columns": ["*"], 
    #     "row_filter_rule": "dept_scope",
    #     "excluded_columns": ["employees.salary"] 
    # }}
}}

# 3. 全局辅助变量 & 增强型时间引擎 (Enhanced Time Engine) [严禁修改且最终保留]
# =============================================================================
user_role := input.user.user_role
user_attrs := object.get(input.user, "attributes", input.user)
role_config := object.get(roles, user_role, {{}})

# --- [Core] 基础时间计算 (时区: Asia/Shanghai) ---
ns_now := time.now_ns()
fmt_full(ns) := time.format([ns, "Asia/Shanghai", "2006-01-02 15:04:05"])
fmt_date(ns) := time.format([ns, "Asia/Shanghai", "2006-01-02"])

# --- [A] 基础锚点 (Base Anchors) ---
str_now := fmt_full(ns_now)
str_today := fmt_date(ns_now)
str_yesterday := fmt_date(time.add_date(ns_now, 0, 0, -1))
str_tomorrow := fmt_date(time.add_date(ns_now, 0, 0, 1))

# --- [B.1] 月份锚点 (Month Windows) ---
date_vec := time.date(ns_now) # [year, month, day]
curr_year := date_vec[0]
curr_month := date_vec[1]

# 本月 (Current Month)
str_curr_month_start := sprintf("%d-%02d-01", [curr_year, curr_month])
# 计算本月最后一天: 下个月1号 减去 1天 (24小时)
ns_next_month_1st := time.parse_ns("2006-01-02", sprintf("%d-%02d-01", [
    time.date(time.add_date(ns_now, 0, 1, 0))[0], 
    time.date(time.add_date(ns_now, 0, 1, 0))[1]
]))
str_curr_month_end := fmt_date(time.add_date(ns_next_month_1st, 0, 0, -1))

# 上个月 (Last Month)
ns_last_month := time.add_date(ns_now, 0, -1, 0)
str_last_month_start := sprintf("%d-%02d-01", [time.date(ns_last_month)[0], time.date(ns_last_month)[1]])
# 上个月最后一天: 本月1号 减去 1天
ns_curr_month_1st_parsed := time.parse_ns("2006-01-02", str_curr_month_start)
str_last_month_end := fmt_date(time.add_date(ns_curr_month_1st_parsed, 0, 0, -1))

# --- [B.2] 年份锚点 (Year Windows) ---
# 今年
str_curr_year_start := sprintf("%d-01-01", [curr_year])
str_curr_year_end := sprintf("%d-12-31", [curr_year])

# 去年
str_last_year_start := sprintf("%d-01-01", [curr_year - 1])
str_last_year_end := sprintf("%d-12-31", [curr_year - 1])

# --- [B.3] 去年同月 (Last Year Same Month) ---
# 起始: 去年 + 当前月 + 01
str_lysm_start := sprintf("%d-%02d-01", [curr_year - 1, curr_month])
# 结束: 先找到“去年同月”的下个月1号，再减1天
# 逻辑: (当前时间 - 1年 + 1月) 的1号 - 1天
ns_lysm_next_month := time.add_date(ns_now, -1, 1, 0)
str_lysm_next_month_1st := sprintf("%d-%02d-01", [time.date(ns_lysm_next_month)[0], time.date(ns_lysm_next_month)[1]])
str_lysm_end := fmt_date(time.add_date(time.parse_ns("2006-01-02", str_lysm_next_month_1st), 0, 0, -1))


# --- 解析逻辑 Step 1: 静态 Token 替换 ---
resolve_step_1(val) := v1 if {{
    is_string(val)
    # 1. Base Anchors
    s0 := replace(replace(replace(val, "{{{{NOW}}}}", str_now), "{{{{TODAY}}}}", str_today), "{{{{YESTERDAY}}}}", str_yesterday)
    s1 := replace(s0, "{{{{TOMORROW}}}}", str_tomorrow)
    
    # 2. Month Windows
    s2 := replace(replace(s1, "{{{{CURRENT_MONTH_START}}}}", str_curr_month_start), "{{{{CURRENT_MONTH_END}}}}", str_curr_month_end)
    s3 := replace(replace(s2, "{{{{LAST_MONTH_START}}}}", str_last_month_start), "{{{{LAST_MONTH_END}}}}", str_last_month_end)
    
    # 3. Year Windows (新增)
    s4 := replace(replace(s3, "{{{{CURRENT_YEAR_START}}}}", str_curr_year_start), "{{{{CURRENT_YEAR_END}}}}", str_curr_year_end)
    s5 := replace(replace(s4, "{{{{LAST_YEAR_START}}}}", str_last_year_start), "{{{{LAST_YEAR_END}}}}", str_last_year_end)
    
    # 4. Last Year Same Month (新增)
    v1 := replace(replace(s5, "{{{{LAST_YEAR_SAME_MONTH_START}}}}", str_lysm_start), "{{{{LAST_YEAR_SAME_MONTH_END}}}}", str_lysm_end)
}} else := val

# --- 解析逻辑 Step 2: 动态解析 (startswith) ---
resolve_step_2(val) := final_val if {{
    is_string(val)
    startswith(val, "{{{{AGO_DAY_")
    # 截取数字: "{{{{AGO_DAY_" 长度为 10
    num_str := trim(substring(val, 10, -1), "}}}}")
    offset := to_number(num_str)
    final_val := fmt_date(time.add_date(ns_now, 0, 0, 0 - offset))
}} else := final_val if {{
    is_string(val)
    startswith(val, "{{{{AGO_MONTH_")
    # "{{{{AGO_MONTH_" 长度为 12
    num_str := trim(substring(val, 12, -1), "}}}}")
    offset := to_number(num_str)
    final_val := fmt_date(time.add_date(ns_now, 0, 0 - offset, 0))
}} else := val

# --- 主解析函数 (分层处理避免递归错误) ---

# 内部函数：只负责处理单值
_resolve_single_item(val) := result if {{
    v1 := resolve_step_1(val)
    result := resolve_step_2(v1)
}} else := val

# 公共接口：负责分发 (数组 vs 单值)
resolve_value(val) := result if {{
    is_array(val)
    result := [res | some item in val; res := _resolve_single_item(item)]
}} else := result if {{
    result := _resolve_single_item(val)
}}

# -----------------------------------------------------------------------------
# 4. 列访问逻辑 (Pipeline 模式) [严禁修改且最终保留]
# -----------------------------------------------------------------------------
base_columns_set := cols if {{
    "*" in role_config.allowed_columns
    cols := all_db_columns
}} else := cols if {{
    role_config.allowed_columns
    not "*" in role_config.allowed_columns
    cols := {{col | col := role_config.allowed_columns[_]}}
}} else := {{}}

blacklisted := {{c | c := object.get(role_config, "excluded_columns", [])[_]}}
base_valid_set := base_columns_set - blacklisted
requested_cols_raw := object.get(input.query_request, "columns", [])
requested_is_wildcard if {{ "*" in requested_cols_raw }}

requested_set := cols if {{
    requested_is_wildcard
    cols := base_valid_set
}} else := cols if {{
    not requested_is_wildcard
    cols := {{c | c := requested_cols_raw[_]}}
}}

final_allowed_set := base_valid_set & requested_set
allowed_columns := sort([c | final_allowed_set[c]])

# =============================================================================
# 5. 行访问逻辑 (Strict AST 模式)
# =============================================================================

# [Step 5.1 - 需填充] 定义策略强制范围 (Policy Scope)
# 任务：返回 AST 对象列表的 Map: {{ "key": [{{...}}, {{...}}] }}
# 逻辑注意：Scope 最终是 "全局约束 (Layer 1)" 与 "角色约束 (Layer 2)" 的交集
# 值注意：在对用户的属性内容进行限制时，**一定要参照User Sample**中的内容，**避免**所约束的内容在用户属性中**名称不匹配**
policy_scope := scope if {{
    role_config.row_filter_rule == "all"  # 仅当明确允许跨域时使用
    scope := {{}}
}} else := scope if {{
    # [通用示例 A] 全局隔离 + 角色全权 (如: 项目经理看本项目所有数据)
    # NL: "按项目(project_id)隔离。经理可以看所有。" -> 意味着看本项目的 "所有"
    # role_config.row_filter_rule == "manager_scope"
    # scope := {{
    #     "table.project_id": [ {{ "op": "=", "val": user_attrs.project_name }} ]
    # }}
    
    # [通用示例 B] 全局隔离 + 角色细分 (如: 员工只能看本项目中指派给自己的)
    # role_config.row_filter_rule == "employee_scope"
    # scope := {{
    #     # Layer 1: Global
    #     "table.project_id": [ {{ "op": "=", "val": user_attrs.project_name }} ],
    #     # Layer 2: Specific
    #     "table.assignee":   [ {{ "op": "=", "val": user_attrs.uid }} ]
    # }}
    
}} else := {{ "deny": true}}

# [Step 5.2] 提取请求并解析时间 Token [严禁修改且最终保留]
raw_conditions := object.get(input.query_request, "conditions", {{}})
requested_conditions := clean_conds if {{
    clean_conds := {{k: v_list |
        some k, raw_list in raw_conditions
        v_list := [resolved_item |
            some item in raw_list
            resolved_item := {{
                "op": item.op,
                "val": resolve_value(item.val)
            }}
        ]
    }}
}}

# [Step 5.3] 智能合规性检查 [严禁修改且最终保留]

to_list(x) := x if {{ is_array(x) }} else := [] if {{ x == null }} else := [x]

trim_percent(s) := trim(s, "%")

is_compliant(req, pol) if {{
    req.op == pol.op
    req.val == pol.val
}}

is_compliant(req, pol) if {{
    pol.op == "="
    req.op == "IN"
    is_array(req.val)
    some item in req.val
    item == pol.val
}}

is_compliant(req, pol) if {{
    pol.op == "IN"
    req.op == "IN"
    # 集合求交集: 存在 x 同时属于 req 和 pol
    some x in req.val
    x in pol.val
}}

is_compliant(req, pol) if {{
    pol.op == "IN"
    req.op == "="
    req.val in pol.val
}}

is_compliant(req, pol) if {{
    pol.op == "="
    req.op == "LIKE"
    user_core := trim_percent(req.val)
    # 双向包含检查
    contains(pol.val, user_core)
}}
is_compliant(req, pol) if {{
    pol.op == "="
    req.op == "LIKE"
    user_core := trim_percent(req.val)
    contains(user_core, pol.val)
}}

is_compliant(req, pol) if {{
    pol.op == "="
    req.op == "BETWEEN"
    is_array(req.val); count(req.val) == 2
    pol.val >= req.val[0]
    pol.val <= req.val[1]
}}

is_compliant(req, pol) if {{
    pol.op == "BETWEEN"
    req.op == "BETWEEN"
    req.val[0] <= pol.val[1]
    req.val[1] >= pol.val[0]
}}

is_compliant(req, pol) if {{
    pol.op == "BETWEEN"
    req.op == "="
    req.val >= pol.val[0]
    req.val <= pol.val[1]
}}

# [Step 5.4] 核心算法：求交集与清洗 (Intersection & Merge) [严禁修改且最终保留]
_merge_item(req_item, pol_item) := result if {{
    # 1. 策略是强限制 (=) -> 始终覆盖，确保安全
    pol_item.op == "="
    result := pol_item
}} else := result if {{
    # 2. 双方都是 IN -> 计算交集
    pol_item.op == "IN"; req_item.op == "IN"
    intersection := [x | x := req_item.val[_]; x in pol_item.val]
    result := {{ "op": "IN", "val": intersection }}
}} else := result if {{
    # 3. 策略是范围(BETWEEN)，用户是范围(BETWEEN) -> 计算区间重叠
    pol_item.op == "BETWEEN"; req_item.op == "BETWEEN"
    new_start := max([req_item.val[0], pol_item.val[0]])
    new_end := min([req_item.val[1], pol_item.val[1]])
    result := {{ "op": "BETWEEN", "val": [new_start, new_end] }}
}} else := req_item # 默认：策略较宽泛时，保留用户更精细的查询条件

_calculate_constraint(req_list, pol_list) := result if {{
    # Case A: 仅策略有 -> 注入策略
    count(pol_list) > 0; count(req_list) == 0
    result := pol_list
}} else := result if {{
    # Case B: 仅用户有 -> 放行用户
    count(pol_list) == 0; count(req_list) > 0
    result := req_list
}} else := result if {{
    # Case C: 双方都有 -> 清洗求交集
    count(pol_list) > 0; count(req_list) > 0
    
    result := [ final_item | 
        some r in req_list
        some p in pol_list
        
        # 1. 必须合规
        is_compliant(r, p)
        
        # 2. 计算交集结果 (使用高级 Merge)
        final_item := _merge_item(r, p)
    ]
}} else := []

# 主规则：生成清洗后的约束 Map
filtered_constraints[key] := final_list if {{
    some key in object.keys(requested_conditions) | object.keys(policy_scope)
    req_list := to_list(object.get(requested_conditions, key, null))
    pol_list := to_list(object.get(policy_scope, key, null))
    final_list := _calculate_constraint(req_list, pol_list)
}}

# [Step 5.5] 拒绝判定 (Denial Logic) [严禁修改且最终保留]
denial_reasons contains msg if {{
    some key, _ in policy_scope
    
    cleaned := object.get(filtered_constraints, key, [])
    original := object.get(requested_conditions, key, [])
    
    # 触发条件: 用户请求了该字段，但清洗后结果为空 (说明完全不合规)
    count(original) > 0
    count(cleaned) == 0
    
    msg := sprintf("Access Denied: Requested values for '%s' are out of permitted scope.", [key])
}}

row_constraints := res if {{
    count(denial_reasons) == 0
    res := filtered_constraints
}} else := res if {{
    count(denial_reasons) > 0
    res := {{
        "deny": true, 
        "reason": concat("; ", denial_reasons)
    }}
}} else := {{"deny": true, "reason": "Internal Policy Error"}}

# -----------------------------------------------------------------------------
# 6. 最终裁决 [严禁修改且最终保留]
# -----------------------------------------------------------------------------
allow if {{
    count(role_config) > 0
    count(allowed_columns) > 0
    not row_constraints.deny
}}

reason := sprintf("Access Granted for role: %s", [user_role]) if {{ allow }}
else := "Access Denied: Role undefined." if {{ count(role_config) == 0 }}
else := "Access Denied: No valid columns requested or allowed." if {{ not allow; count(allowed_columns) == 0 }}
else := object.get(row_constraints, "reason", "Access Denied: Row constraints.") if {{ not allow; row_constraints.deny }}
else := "Access Denied: Unknown reason."

result := {{
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}}
"""

    # --- 公共接口 (Write Methods) ---

    async def update_nl_policy(self, policy_id: str, content: str, opa_client: Any = None, use_agent: bool = False) -> str:
        """
        更新 NL 策略，并触发 Rego 生成。
        新增参数: use_agent (bool) - 是否启用智能体自修正
        """
        async with self.policy_write_locks[policy_id]:
            # 1. 保存 NL 文件
            nl_file_path = await self._save_raw_file_unlocked(policy_id, "nl_policy.txt", content)
            
            # 2. 生成 Rego
            print(f"NL policy updated. Triggering Rego generation for {policy_id}...")
            try:
                # 将 use_agent 传递给生成函数
                rego_content = await self._generate_rego_from_nl(
                    policy_id, 
                    content, 
                    opa_client, 
                    use_agent=use_agent
                )
                
                # 3. 保存生成的Rego策略
                await self._save_raw_file_unlocked(policy_id, "policy.rego", rego_content)
                
                if opa_client and use_agent:
                    print(f"🎉 [Agent] Successfully saved validated Rego policy for {policy_id}")
                else:
                    print(f"✅ Successfully saved Rego policy (Fast Mode) for {policy_id}")
                    
            except Exception as e:
                print(f"Error during auto-generation of Rego: {e}")
                raise e
            
            return str(nl_file_path)

    async def _save_raw_file_unlocked(
        self, policy_id: str, file_name: str, content: str
    ) -> Path:
        """非锁定版本，供 update_nl_policy 内部使用"""
        policy_path = self.raw_base_path / policy_id
        if not policy_path.exists():
            policy_path.mkdir(parents=True, exist_ok=True)
        file_path = policy_path / file_name
        print(f"Writing raw file: {file_path}")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return file_path

    async def update_employee_table(self, policy_id: str, content: str) -> str:
        file_path = await self._save_raw_file(policy_id, "employees.jsonl", content)
        return str(file_path)

    async def update_db_schema(self, policy_id: str, content: Any) -> str:
        # 1. 如果传进来的是列表 (List)，把它拼接成一个大字符串
        if isinstance(content, list):
            # 用两个换行符拼接，保证 SQL 语句之间有空行
            content_str = "\n\n".join(content)
        else:
            # 如果已经是字符串，保持不变
            content_str = str(content)
        file_path = await self._save_raw_file(policy_id, "db_schema.sql", content_str)
        return str(file_path)

    async def update_rego_policy(self, policy_id: str, content: str) -> str:
        file_path = await self._save_raw_file(policy_id, "policy.rego", content)
        return str(file_path)

    async def _save_raw_file(
        self, policy_id: str, file_name: str, content: str
    ) -> Path:
        policy_path = self.raw_base_path / policy_id
        async with self.policy_write_locks[policy_id]:
            if not policy_path.exists():
                policy_path.mkdir(parents=True, exist_ok=True)
            file_path = policy_path / file_name
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
        return file_path
