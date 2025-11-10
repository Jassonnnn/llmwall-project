import json
import re
import asyncio
from pathlib import Path
from typing import Dict, Any, List
from collections import defaultdict
from litellm import acompletion # 用于 LLM 解析

from .policy_manager import PolicyManager
from opa_client import OpaClient

# --- 缓存 ---
# (key = tenant_id, value = dict)
_employee_cache: Dict[str, Dict[str, Any]] = {}
# (key = tenant_id, value = str)
_policy_cache: Dict[str, str] = {}
# (key = file_path, value = asyncio.Lock)
_file_locks = defaultdict(asyncio.Lock)

class PermissionController:
    """
    (新版本) 权限控制器 (无状态服务，带内部缓存)
    负责在运行时 "读取" 数据和策略, "执行" 权限检查
    """
    
    def __init__(self, policy_manager: PolicyManager, opa_client: OpaClient):
        """
        初始化
        Args:
            policy_manager: PolicyManager 实例 (用于获取文件路径)
            opa_client: OPAClient 实例 (用于评估)
        """
        self.policy_manager = policy_manager
        self.opa_client = opa_client
        # (已移除) self.llm_model，因为它已在 acompletion 调用中硬编码
        print("[PermissionController] 初始化完成 (新版本, 自定义 LLM 配置)")

    # --- 核心检查方法 ---

    async def check_query(self, tenant_id: str, user_id: str, query: str, conversation_history: List[Dict] = None) -> Dict[str, Any]:
        """
        (新) 核心检查方法：
        1. 获取用户信息
        2. 将自然语言 (query) 解析为 SQL-like JSON
        3. 构建 OPA 输入
        4. 获取策略
        5. 评估策略
        6. (可选) 重写查询
        """
        if conversation_history is None:
            conversation_history = []
            
        print(f"[check_query] 开始处理 Tenant: {tenant_id}, User: {user_id}")

        # 1. 获取用户信息 (来自缓存或文件)
        user_info = await self._get_user_attributes(tenant_id, user_id)
        if not user_info:
            print(f"错误: 无法找到用户 {user_id} 在租户 {tenant_id} 中")
            return {"decision": "DENY", "reason": "User or Tenant not found."}

        # 2. 将自然语言解析为 SQL-like JSON (使用 V1 demo 的提示词)
        try:
            parsed_query_request = await self._parse_query_to_json(
                query, user_id, conversation_history, tenant_id # (新增) 传入 tenant_id
            )
            print(f"[check_query] LLM 解析结果: {parsed_query_request}")
        except Exception as e:
            print(f"错误: LLM 解析失败 - {e}")
            return {"decision": "DENY", "reason": f"LLM parsing failed: {e}"}

        # 3. 构建 OPA 输入 (使用 V1 demo 的格式)
        opa_input = {
            "input": {
                "user": user_info,
                "query_request": parsed_query_request
            }
        }
        
        opa_input = {
            "user": user_info,
            "query_request": parsed_query_request
        }

        # 4. 获取 Rego 策略 (来自缓存或文件)
        rego_policy = await self._get_policy(tenant_id)
        if not rego_policy:
            print(f"错误: 租户 {tenant_id} 缺少 'policy.rego' 文件")
            return {"decision": "DENY", "reason": "Policy file not found for tenant."}
            
        # 5. 评估策略
        # 我们查询 'sqlopa.access.result'，这与 V1 demo 和 PolicyManager 中的 LLM 生成提示词一致
        policy_data_path = "sqlopa.access.result" 
        try:
            opa_result = await self.opa_client.evaluate_policy(
                input_data=opa_input,
                rego_policy=rego_policy,
                policy_data_path=policy_data_path
            )
            print(f"[check_query] OPA 评估结果: {opa_result}")

            # 检查 OPA 是否返回了有效的决策
            if not opa_result or 'allowed' not in opa_result:
                raise ValueError("OPA anwser doesn't contain 'allowed' field")

        except Exception as e:
            print(f"错误: OPA 评估失败 - {e}")
            return {"decision": "DENY", "reason": f"OPA evaluation failed: {e}"}

        # 6. 处理结果 (重写逻辑)
        if not opa_result.get("allowed", False):
            # 完全拒绝
            return {
                "decision": "DENY",
                "reason": opa_result.get("reason", "Access denied by policy.")
            }

        # 检查是否需要重写 (V1 demo 逻辑)
        allowed_columns = opa_result.get("allowed_columns", [])
        requested_columns = parsed_query_request.get("columns", [])
        row_constraints = opa_result.get("row_constraints", {})
        
        # 简单的检查：如果允许的列少于请求的列，或者存在行约束，则认为需要重写
        needs_rewrite = (
            set(allowed_columns) != set(requested_columns) or
            bool(row_constraints)
        )

        if not needs_rewrite:
            return {
                "decision": "ALLOW",
                "rewritten_query": query, # 无需重写，返回原始查询
                "opa_result": opa_result
            }
        
        # --- 需要重写 ---
        print("[check_query] 检测到需要重写查询...")
        try:
            rewritten_query = await self._rewrite_query_with_llm(
                original_query=query,
                allowed_columns=allowed_columns,
                row_constraints=row_constraints
            )
            print(f"[check_query] LLM 重写结果: {rewritten_query}")
            return {
                "decision": "REWRITE",
                "rewritten_query": rewritten_query,
                "opa_result": opa_result
            }
        except Exception as e:
            print(f"错误: LLM 重写查询失败 - {e}")
            return {"decision": "DENY", "reason": f"Query rewrite failed: {e}"}

    # --- LLM 辅助方法 ---

    async def _parse_query_to_json(self, natural_query: str, user_id: str, conversation_history: List[Dict], tenant_id: str) -> Dict[str, Any]:
        """
        (新) 使用 LLM 将自然语言解析为 SQL-like JSON
        (基于用户提供的 llm_parser.py)
        (已修改) 使用用户指定的 litellm 参数
        """
        
        # (可选) 动态从 PolicyManager 加载 schema 描述
        schema_desc = await self._get_schema_description(tenant_id)
        if not schema_desc:
             schema_desc = "employees表包含列：id, name, department, salary, position" # 备用硬编码

        # (已修改) 拆分 system_prompt 和 user_prompt
        system_prompt = f"""
你是一个专业的SQL查询解析专家，擅长理解自然语言和对话上下文，并将其转换为结构化的JSON查询。

解析规则：
1.  **上下文理解**：优先分析`conversation_history`。如果当前查询是基于上一轮的结果进行筛选 (例如使用“他们中”)，你必须将上一轮`conditions`继承下来并与当前查询合并。
2.  **重置上下文**：如果当前查询是一个全新的、与历史无关的请求，你必须忽略`conversation_history`。
3.  **个人化查询**：当用户查询包含“我的”、“我自己的”等词语时，必须在`conditions`中添加`"id": "{user_id}"`的过滤条件。

示例1 - 查询自己信息：
用户查询："帮我查一下我的工资"
输出：{{"tables": ["employees"], "columns": ["salary"], "conditions": {{"id": "{user_id}"}}, "query_type": "select"}}

示例2 - 查询所有员工：
用户查询："查询所有员工的姓名和工资"
输出：{{"tables": ["employees"], "columns": ["name", "salary"], "conditions": {{}}, "query_type": "select"}}
"""
        
        user_prompt = f"""
数据库表结构：
- {schema_desc}

用户查询："{natural_query}"
用户ID：{user_id}
历史对话：{conversation_history}

请返回JSON格式的解析结果，包含以下字段：
- tables: (list) 涉及的表名列表
- columns: (list) 需要查询的列名列表  
- conditions: (dict) 查询条件 (键值对格式)
- query_type: (str) 查询类型 (例如: "select")

只返回JSON块，不要包含 "```json" 标记或任何其他解释：
"""
        
        # (已修改) 使用用户指定的 litellm 调用参数
        response = await acompletion(
            custom_llm_provider="openai",
            base_url="http://124.70.213.108:7009/v1",
            api_key="sk-jjygDVvRsuTf6b1oNvHL6E7jpFIDRboL",
            model="qwen2.5-14b-instruct",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0,
            # (注意) 移除了 response_format={"type": "json_object"}
            # 因为它可能与自定义 provider 不兼容
            # 我们将依赖提示词中的 "只返回JSON块"
        )
        
        content = response.choices[0].message.content
        
        # (新增) 清理 LLM 可能返回的 markdown 标记
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            return json.loads(json_str)
        else:
            raise ValueError("无法从LLM响应中提取JSON")

    async def _rewrite_query_with_llm(self, original_query: str, allowed_columns: List[str], row_constraints: Dict[str, Any]) -> str:
        """
        (新) 使用 LLM 重写查询以符合 OPA 约束
        (基于用户提供的 llm_parser.py)
        (已修改) 使用用户指定的 litellm 参数
        """
        
        # (已修改) 拆分 system_prompt 和 user_prompt
        system_prompt = """
你是一个查询重写专家。用户的原始查询由于权限限制需要修改。

重写规则：
1. 只保留允许的列
2. 添加必要的行级过滤条件 (例如，如果 row_constraints 是 {"id": "emp001"}，查询应被重写为查询该特定用户的信息)
3. 保持自然语言的表达方式
"""
        
        user_prompt = f"""
原始查询："{original_query}"
允许查询的列：{allowed_columns}
行级约束：{row_constraints}

只返回重写后的自然语言查询，不要其他解释：
"""
        
        # (已修改) 使用用户指定的 litellm 调用参数
        response = await acompletion(
            custom_llm_provider="openai",
            base_url="http://124.70.213.108:7009/v1",
            api_key="sk-jjygDVvRsuTf6b1oNvHL6E7jpFIDRboL",
            model="qwen2.5-14b-instruct",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1, # 重写时允许一点创造性
        )
        
        rewritten = response.choices[0].message.content.strip()
        # 清理可能的引号
        rewritten = rewritten.strip('"\'')
        return rewritten

    # --- 缓存和文件 I/O 辅助方法 ---

    async def _get_user_attributes(self, tenant_id: str, user_id: str) -> Dict[str, Any]:
        """
        从缓存或文件中获取特定用户的信息
        """
        if tenant_id not in _employee_cache:
            # 缓存未命中，需要从文件加载
            filepath = self.policy_manager.get_employee_filepath(tenant_id)
            async with _file_locks[filepath]:
                # 再次检查，防止在等待锁时已被其他协程加载
                if tenant_id not in _employee_cache:
                    print(f"缓存未命中: 正在从 {filepath} 加载员工表...")
                    try:
                        employee_map = {}
                        with open(filepath, "r", encoding="utf-8") as f:
                            for line in f:
                                if line.strip():
                                    data = json.loads(line)
                                    employee_map[data["user_id"]] = data
                        _employee_cache[tenant_id] = employee_map
                    except FileNotFoundError:
                        print(f"错误: 员工文件 {filepath} 未找到")
                        _employee_cache[tenant_id] = {} # 存入空字典防止重复读取
                    except Exception as e:
                        print(f"错误: 解析员工文件 {filepath} 失败 - {e}")
                        _employee_cache[tenant_id] = {}
            
        # 从缓存中查找用户
        return _employee_cache.get(tenant_id, {}).get(user_id)

    async def _get_policy(self, tenant_id: str) -> str:
        """
        从缓存或文件中获取租户的 Rego 策略字符串
        """
        if tenant_id not in _policy_cache:
            filepath = self.policy_manager.get_policy_filepath(tenant_id)
            async with _file_locks[filepath]:
                if tenant_id not in _policy_cache:
                    print(f"缓存未命中: 正在从 {filepath} 加载 Rego 策略...")
                    try:
                        with open(filepath, "r", encoding="utf-8-sig") as f:
                            _policy_cache[tenant_id] = f.read()
                    except FileNotFoundError:
                        print(f"错误: 策略文件 {filepath} 未找到")
                        _policy_cache[tenant_id] = "" # 存入空字符串防止重复读取
                    except Exception as e:
                        print(f"错误: 读取策略文件 {filepath} 失败 - {e}")
                        _policy_cache[tenant_id] = ""

        return _policy_cache.get(tenant_id)

    async def _get_schema_description(self, tenant_id: str) -> str:
        """
        (新增) 尝试从文件加载 schema 描述
        """
        filepath = self.policy_manager.get_schema_filepath(tenant_id)
        try:
            # 注意: 这是一个非I/O密集型读取，暂不加锁
            if filepath.exists():
                with open(filepath, "r", encoding="utf-8") as f:
                    return f.read()
            else:
                return ""
        except Exception as e:
            print(f"Warning: 读取 schema 文件失败 ({filepath}): {e}")
            return ""

    def clear_cache(self, tenant_id: str):
        """
        (公开方法) 清除指定租户的缓存
        (由 setup_routes.py 在文件更新时调用)
        """
        if tenant_id in _employee_cache:
            del _employee_cache[tenant_id]
            print(f"缓存清除: 员工表 ({tenant_id})")
        if tenant_id in _policy_cache:
            del _policy_cache[tenant_id]
            print(f"缓存清除: 策略 ({tenant_id})")
            
import tempfile
import logging
import sys

# (新增) 动态添加
# sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

async def main_test():
    """(新增) 用于 PermissionController 的异步 E2E 测试函数"""
    
    # 设置日志记录
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # 1. 使用临时目录
    with tempfile.TemporaryDirectory() as temp_dir_path:
        print(f"--- PermissionController E2E Test ---")
        print(f"使用临时目录: {temp_dir_path}")
        
        # 2. 定义模拟数据
        tenant_id = "e2e_test_tenant"
        
        mock_employees = (
            '{"user_id": "emp_manager", "user_role": "manager", "attributes": {"department": "Sales"}}\n'
            '{"user_id": "emp_regular", "user_role": "employee", "attributes": {"department": "Support"}}'
        )
        
        mock_schema = "CREATE TABLE employees (id varchar(100), name varchar(100), salary int, department varchar(50));"
        
        # 一个模拟的 Rego 策略
        mock_rego_policy = """package sqlopa.access

import rego.v1

default allow := false
default allowed_columns := []
default row_constraints := {}
default reason := "Access denied by default. No rules matched."

roles := {
    "manager": {
        "description": "Manager",
        "allowed_columns": ["name", "department", "salary"],
        "row_filter": "all"
    },
    "employee": {
        "description": "Regular Employee",
        "allowed_columns": ["name", "department"],
        "row_filter": "self_only"
    }
}

user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

allowed_columns := role_config.allowed_columns if {
    role_config
    input.query_request.columns[_] == "*"
}

allowed_columns := intersection if {
    role_config
    not "*" in input.query_request.columns
    
    intersection := [col |
        col := input.query_request.columns[_]
        col in role_config.allowed_columns
    ]
}

row_constraints := {} if {
    role_config.row_filter == "all"
}

row_constraints := {"id": user_id} if {
    role_config.row_filter == "self_only"
}

row_constraints := {"deny": true} if {
    role_config
    not role_config.row_filter in {"all", "self_only"}
}

allow if {
    role_config
    
    count(allowed_columns) > 0
    
    not row_constraints.deny
}

reason := sprintf("Access Granted for %s", [role_config.description]) if {
    allow
}

reason := "Access Denied: This role is not defined in the policy." if {
    not allow
    not role_config
}

reason := "Access Denied: The query does not request any columns this role is allowed to see." if {
    not allow
    role_config
    count(allowed_columns) == 0
}

reason := "Access Denied: This role has no row-level access permissions." if {
    not allow
    row_constraints.deny
}

result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}
"""
        
        # 3. 初始化服务
        # (重要) OPAClient 在我们的项目中是模拟的, 它会返回空字典。
        # 我们需要一个能 *真正* 执行 Rego 的 OPAClient。
        #
        # 解决方案: 我将在这里 *Monkey-Patch* (猴子补丁) OPAClient
        # 以便它使用真实的 'opa_python_client' (如果已安装)
        
        try:
            from opa_client import OpaClient as RealOPAClient
            
            # 创建一个 *真实的* OPAClient (如果 pip install opa-python-client)
            # 这需要一个 OPA 服务在 http://localhost:8181 运行
            # $ opa run -s
            
            # (已修正) 将 host 和 port 分开
            real_opa_instance = RealOPAClient(host="localhost", port=8181)
            
            # 检查 OPA 服务是否在运行
            if not real_opa_instance.check_health():
                raise ConnectionError("OPA 服务未在 http://localhost:8181 运行")

            # 创建一个包装器
            class TestOPAClient(OpaClient):
                async def evaluate_policy(self, input_data: dict, rego_policy: str, policy_data_path: str) -> dict:
                    print("    (OPA 客户端: 使用 *真实* OPA 服务)")
                    # 1. 动态推送策略
                    policy_id = f"test_{tenant_id}"
                    # print(f"rego策略:\n{rego_policy}\n")
                    # (已修正) 将 save_policy 替换为正确的库方法名
                    real_opa_instance.update_policy_from_string(
                        new_policy = rego_policy,
                        endpoint = policy_id
                    )
                    
                    print(input_data)
                    
                    # 2. 评估
                    # result_full = real_opa_instance.check_permission(
                    #     input_data=input_data,
                    #     policy_name = policy_id,
                    #     rule_name = "result",
                    # )
                    result_full = real_opa_instance.query_rule(
                        input_data=input_data,
                        package_path="sqlopa/access",
                        rule_name="result",
                    )
                    # 提取 'result' 部分
                    return result_full.get("result", {})

            opa_client = TestOPAClient()
            print("\n*** 成功连接到真实 OPA 服务 (http://localhost:8181) ***\n")
            
        except (ImportError, ConnectionError) as e:
            print(f"\n*** 警告: 未找到 'opa-python-client' 或 OPA 服务未运行 ({e}) ***")
            print("*** 将使用 PolicyManager 中的 Rego LLM 生成提示词进行 *模拟* OPA 评估 ***\n")
            
            # 回退到使用模拟 OPA 客户端
            # (注意: 我们的 opa_client.py 模拟器是空的, 
            #  所以我们在这里模拟 V1 demo 的返回)
            class MockOPAClient(OpaClient):
                 async def evaluate_policy(self, input_data: dict, rego_policy: str, policy_data_path: str) -> dict:
                    print("    (OPA 客户端: 使用 *模拟* 逻辑)")
                    user = input_data["input"]["user"]
                    query = input_data["input"]["query_request"]
                    
                    if user.get("user_role") == "manager":
                        return {"allowed": True, "allowed_columns": ["name", "department", "salary"], "row_constraints": {}}
                    
                    if user.get("user_role") == "employee":
                        if query.get("conditions", {}).get("id") == user.get("user_id"):
                            return {"allowed": True, "allowed_columns": ["name", "department"], "row_constraints": {"id": user.get("user_id")}}
                        else:
                            return {"allowed": False, "reason": "Employee can only query self"}
                    
                    return {"allowed": False, "reason": "No rule matched"}

            opa_client = MockOPAClient()


        # --- 继续初始化 ---
        policy_manager = PolicyManager(raw_data_path=temp_dir_path)
        controller = PermissionController(
            policy_manager=policy_manager,
            opa_client=opa_client
        )
        
        # 4. 写入模拟文件
        print("--- 正在设置测试文件... ---")
        await policy_manager.update_employee_table(tenant_id, mock_employees)
        await policy_manager.update_db_schema(tenant_id, mock_schema)
        await policy_manager.update_rego_policy(tenant_id, mock_rego_policy)
        print("--- 测试文件设置完毕 ---")

        # 5. 定义测试用例
        test_cases = [
            {
                "name": "测试1: Manager 查询所有员工工资 (应 ALLOW 且无需重写)",
                "user_id": "emp_manager",
                "query": "查询所有员工的工资和部门"
            },
            {
                "name": "测试2: Employee 查询自己的信息 (应 REWRITE, 移除 'salary')",
                "user_id": "emp_regular",
                "query": "帮我查一下我的工资和部门"
            },
            {
                "name": "测试3: Employee 查询他人信息 (应 DENY)",
                "user_id": "emp_regular",
                "query": "帮我查一下 emp_manager 的工资"
            }
        ]
        
        # 6. 运行测试
        for test in test_cases:
            print(f"\n{'='*20} {test['name']} {'='*20}")
            
            try:
                result = await controller.check_query(
                    tenant_id=tenant_id,
                    user_id=test["user_id"],
                    query=test["query"]
                )
                
                print("\n  --- 最终结果 (Formatted) ---")
                print(json.dumps(result, indent=2, ensure_ascii=False))
                print(f"  ------------------------------")
                
            except Exception as e:
                print(f"\n--- 测试用例失败 (异常) ---")
                print(f"Error: {e}")
            
            print(f"{'='*60}")

        print("\n--- E2E 测试完成 ---")
        print(f"临时目录 {temp_dir_path} 将被自动清理。")


if __name__ == "__main__":
    # (新增) 主入口点
    #
    # 运行说明:
    # 1. (推荐) 安装 OPA 客户端: pip install opa-python-client
    # 2. (推荐) 启动 OPA 服务: opa run -s
    # 3. (必须) 在项目根目录运行此脚本:
    #    python -m permission_control.services.PermissionController1
    #
    # 4. (如果 LLM 失败) 确保您的自定义 LLM 服务正在运行
    #    ([http://124.70.213.108:7009/v1](http://124.70.213.108:7009/v1))
    
    # (新增) 修复相对导入
    # 这一行将 'permission_control' 的父目录添加到 sys.path
    # 使得 'from .policy_manager import ...' 可以被解析
    sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

    asyncio.run(main_test())