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
# (key = policy_id, value = dict)
_employee_cache: Dict[str, Dict[str, Any]] = {}
# (key = policy_id, value = str)
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
    
    print("[PermissionController] 初始化完成 (新版本, 自定义 LLM 配置)")

    # --- 核心检查方法 ---

    async def check_query(self, policy_id: str, user_id: str, query: str, conversation_history: List[Dict] = None) -> Dict[str, Any]:
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
            
        print(f"[check_query] 开始处理 Policy: {policy_id}, User: {user_id}")

        # 1. 获取用户信息 (来自缓存或文件)
        user_info = await self._get_user_attributes(policy_id, user_id)
        if not user_info:
            print(f"错误: 无法找到用户 {user_id} 在策略组 {policy_id} 中")
            return {"decision": "DENY", "reason": "User or Policy ID not found."}

        # 2. 将自然语言解析为 SQL-like JSON (使用 V1 demo 的提示词)
        try:
            parsed_query_request = await self._parse_query_to_json(
                query, user_info, conversation_history, policy_id # (修改) 传入 policy_id
            )
            print(f"[check_query] LLM 解析结果: {parsed_query_request}")
        except Exception as e:
            print(f"错误: LLM 解析失败 - {e}")
            return {"decision": "DENY", "reason": f"LLM parsing failed: {e}"}

        # 3. 构建 OPA 输入 (使用 V1 demo 的格式)
        opa_input = {
            "user": user_info,
            "query_request": parsed_query_request
        }
        print("opa_input:", json.dumps(opa_input, indent=2, ensure_ascii=False))

        # 4. 获取 Rego 策略 (来自缓存或文件)
        rego_policy = await self._get_policy(policy_id)
        if not rego_policy:
            print(f"错误: 策略组 {policy_id} 缺少 'policy.rego' 文件")
            return {"decision": "DENY", "reason": "Policy file not found."}
            
        # 5. 评估策略
        # 我们查询 '{policy_id}.access.result'
        policy_data_path = f"{policy_id}.access.result" 
        try:
            opa_result = await self.opa_client.evaluate_policy(
                policy_id=policy_id, # (修改) 传入 policy_id
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
                row_constraints=row_constraints,
                policy_id=policy_id
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

    async def _parse_query_to_json(self, natural_query: str, user_info: str, conversation_history: List[Dict], policy_id: str) -> Dict[str, Any]:
        """
        (新) 使用 LLM 将自然语言解析为 SQL-like JSON
        (基于用户提供的 llm_parser.py)
        (已修改) 使用用户指定的 litellm 参数
        """
        
        # (可选) 动态从 PolicyManager 加载 schema 描述
        schema_prompt = await self._get_schema_description(policy_id)
        if not schema_prompt:
            schema_prompt = "CREATE TABLE employees (id varchar(100), name varchar(100), salary int, department varchar(50));"

        history_str = str(conversation_history) if conversation_history else "无"

        # (已修改) 拆分 system_prompt 和 user_prompt
        system_prompt = """
你是一个专业的SQL查询解析专家，擅长理解自然语言、对话上下文，并将其转换为符合 AST（抽象语法树）标准的结构化 JSON 对象。

### 核心任务
你的目标是将用户的自然语言请求转换为结构化的元数据，供后续的 OPA (Open Policy Agent) 进行鉴权和 SQL 生成。

### 严格解析规则 (必须遵守)

1.  **AST 格式强制 (Critical)**：
    `conditions` 字段必须是字典，Key 为 `Table.Column`，Value **必须是操作符对象列表**。
    - **标准格式**：`"Table.Column": [{"op": "操作符", "val": 值}]`
    - **操作符映射指南**：
        - 等于/是 -> `"="`
        - 不等于 -> `"!="`
        - 大于/高于/之后 -> `">"` 或 `">="`
        - 小于/低于/之前 -> `"<"` 或 `"<="`
        - 包含/搜索/模糊匹配 -> `"LIKE"` (值需自动包裹 `%`, 如 `"%关键词%"`)
        - 在...之中 -> `"IN"` (值为数组 `["A", "B"]`)

2.  **命名空间限定 (Namespace)**：
    `columns` 和 `conditions` 中的所有字段名必须严格遵循 `Table.Column` 格式（例如 `products.price`）。
    - **严禁**输出不带表前缀的裸列名（如 `price` 是非法的）。

3.  **上下文处理**：
    - **继承**：如果查询隐含指代（如“他们”、“这些”），必须继承历史对话中的筛选条件。
    - **重置**：如果查询与历史无关，忽略历史上下文。

4.  **个人化查询触发器 (Security)**：
    - **触发条件**（非常重要！）：只有当用户自然语言中**显式包含**“我的”、“我自己”、“本人”、“我”时。
    - **执行动作**：在 `conditions` 中追加相应user_info的约束，格式为 `[{"op": "=", "val": "{相应值}"}]`。
    - **禁止隐含**：如果用户查询中未提到触发条件如“我的”、”我自己“、”本人“时，**严禁**自动添加过滤。

5.  **空缺与默认值**：
    - `columns`: 如果未指定，默认为 `["*"]`。
    - `query_type`: 提取动作类型，如 "select", "count", "sum"。

6.  **时间语义标准化协议 (Time Tokenization) - 核心规则**：
    你必须作为“语义翻译官”，**严禁**自行计算具体日期。所有时间必须转换为以下标准 Token：

    *   **A. 基础锚点 (Base Anchors)**：
        - 昨天: `{{YESTERDAY}}` | 今天: `{{TODAY}}` | 明天: `{{TOMORROW}}`

    *   **B. 日历窗口 (Calendar Windows - 优先级最高)**：
        当用户提到完整的自然月/年时，**严禁使用 AGO**，必须使用起止锚点。
        *格式要求：使用 BETWEEN 操作符*
        - **本月**: `val: ["{{CURRENT_MONTH_START}}", "{{CURRENT_MONTH_END}}"]`
        - **上个月**: `val: ["{{LAST_MONTH_START}}", "{{LAST_MONTH_END}}"]`
        - **今年**: `val: ["{{CURRENT_YEAR_START}}", "{{CURRENT_YEAR_END}}"]`
        - **去年**: `val: ["{{LAST_YEAR_START}}", "{{LAST_YEAR_END}}"]`
        - **去年同月**: `val: ["{{LAST_YEAR_SAME_MONTH_START}}", "{{LAST_YEAR_SAME_MONTH_END}}"]`

    *   **C. 滚动窗口 (Rolling Offsets - 仅限“近/前”语境)**：
        仅在用户明确说“近N天”、“前N个月”时，使用 `AGO` 函数。
        - **近7天**: `val: ["{{AGO_DAY_7}}", "{{TODAY}} 23:59:59"]`
        - **近3个月**: `val: ["{{AGO_MONTH_3}}", "{{TODAY}} 23:59:59"]`

    *   **D. 模糊时段 (Intra-day Precision)**：
        对于一天内的模糊描述，必须基于锚点拼接具体时间：
        - **凌晨**: `00:00:00` 至 `06:00:00`
        - **上午/早晨**: `06:00:00` 至 `12:00:00`
        - **中午**: `11:00:00` 至 `14:00:00`
        - **下午**: `12:00:00` 至 `18:00:00`
        - **晚上/今晚**: `18:00:00` 至 `23:59:59`
        - *示例 ("昨晚")*: `val: ["{{YESTERDAY}} 18:00:00", "{{YESTERDAY}} 23:59:59"]`

    *   **E. 多段对比逻辑 (Disjoint Segments - CRITICAL)**：
        当查询涉及**不连续的时间段**（如“今年和去年”、“今天和昨天”）时：
        1. **严禁**将时间合并为一个大范围。
        2. **必须**输出多个独立的 `BETWEEN` 对象列表。
        - *示例 ("今天和昨天")*:
          `"table.time": [`
             `{"op": "BETWEEN", "val": ["{{YESTERDAY}} 00:00:00", "{{YESTERDAY}} 23:59:59"]},`
             `{"op": "BETWEEN", "val": ["{{TODAY}} 00:00:00", "{{TODAY}} 23:59:59"]}`
          `]`
        
### 输出格式示例 (Few-Shot)

**User**: "帮我查一下我的订单详情" (User ID: u_001)
**Output**:
{
  "tables": ["orders"],
  "columns": ["orders.id", "orders.amount", "orders.status", "orders.created_at"],
  "conditions": {
    "orders.customer_id": [{"op": "=", "val": "u_001"}]
  },
  "query_type": "select"
}

**User**: "查询上个月处理完成的工单总数"
**Output**:
{
  "tables": ["work_orders"],
  "columns": ["*"],
  "conditions": {
    "work_orders.status": [{"op": "=", "val": "completed"}],
    "work_orders.processed_at": [
      {"op": "BETWEEN", "val": ["{{LAST_MONTH_START}}", "{{LAST_MONTH_END}}"]}
    ]
  },
  "query_type": "count"
}

**User**: "查看过去24小时内包含'服务器'的告警记录"
**Output**:
{
  "tables": ["alarms"],
  "columns": ["alarms.message", "alarms.timestamp", "alarms.level"],
  "conditions": {
    "alarms.message": [{"op": "LIKE", "val": "%服务器%"}],
    "alarms.timestamp": [
      {"op": "BETWEEN", "val": ["{{AGO_HOUR_24}}", "{{NOW}}"]}
    ]
  },
  "query_type": "select"
}

**User**: "统计最近7天的销售额趋势"
**Output**:
{
  "tables": ["sales"],
  "columns": ["sales.date", "sales.amount"],
  "conditions": {
    "sales.date": [
      {"op": "BETWEEN", "val": ["{{AGO_DAY_7}}", "{{TODAY}} 23:59:59"]}
    ]
  },
  "query_type": "select"
}

**User**: "本月房价比去年同月高吗？" (跨段对比场景)
**Output**:
{
  "tables": ["house_info"],
  "columns": ["house_info.price"],
  "conditions": {
    "house_info.time": [
      {"op": "BETWEEN", "val": ["{{LAST_YEAR_SAME_MONTH_START}}", "{{LAST_YEAR_SAME_MONTH_END}}"]},
      {"op": "BETWEEN", "val": ["{{CURRENT_MONTH_START}}", "{{CURRENT_MONTH_END}}"]}
    ]
  },
  "query_type": "compare"
}
"""
        
        user_prompt = f"""
数据库表结构：
{schema_prompt}

用户查询："{natural_query}"
用户信息：{user_info}(**只有触发个人查询**的条件时使用)
历史对话：{history_str}

请返回JSON格式的解析结果，包含以下字段：
- tables: (list) 涉及的表名列表
- columns: (list) 需要查询的列名列表,必须以表名.列名的形式输出  
- conditions: (dict) 查询条件 (AST格式)
- query_type: (str) 操作类型 (例如: "select","count","sum")

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
        )
        
        content = response.choices[0].message.content
        
        # (新增) 清理 LLM 可能返回的 markdown 标记
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group()
            return json.loads(json_str)
        else:
            raise ValueError("无法从LLM响应中提取JSON")

    async def _rewrite_query_with_llm(self, original_query: str, allowed_columns: List[str], row_constraints: Dict[str, Any], policy_id: str) -> str:
        """
        (新) 使用 LLM 重写查询以符合 OPA 约束
        (基于用户提供的 llm_parser.py)
        (已修改) 使用用户指定的 litellm 参数
        """
        
        # (可选) 动态从 PolicyManager 加载 schema 描述
        schema_prompt = await self._get_schema_description(policy_id)
        if not schema_prompt:
            schema_prompt = "CREATE TABLE employees (id varchar(100), name varchar(100), salary int, department varchar(50));"
        
        # (已修改) 拆分 system_prompt 和 user_prompt
        system_prompt = """
你是一个查询重写专家。用户的原始查询由于权限限制需要修改。

重写规则：
1. 只保留允许的列
2. 添加必要的行级过滤条件 (例如，如果行级约束是 {"id": "emp001"}，查询应被重写为查询用户id为emp001的信息),但如果行级约束为空，则不添加任何行级过滤条件
3. 在用户原始查询的基础上进行改写，保持自然语言的表达方式
"""
        
        user_prompt = f"""
原始查询："{original_query}"
允许查询的列：{allowed_columns}
行级约束：{row_constraints}
表字段意义参考: {schema_prompt}

只返回重写后的自然语言查询，不要其他解释
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
        if "\n" in rewritten:
            rewritten = rewritten.split("\n")[0]
        # 清理可能的引号 (放在 split 之后，防止引号跨行)
        rewritten = rewritten.strip('"\'').strip()
        return rewritten

    # --- 缓存和文件 I/O 辅助方法 ---

    async def _get_user_attributes(self, policy_id: str, user_id: str) -> Dict[str, Any]:
        """
        从缓存或文件中获取特定用户的信息
        """
        if policy_id not in _employee_cache:
            # 缓存未命中，需要从文件加载
            filepath = self.policy_manager.get_employee_filepath(policy_id)
            async with _file_locks[filepath]:
                # 再次检查，防止在等待锁时已被其他协程加载
                if policy_id not in _employee_cache:
                    print(f"缓存未命中: 正在从 {filepath} 加载员工表...")
                    try:
                        employee_map = {}
                        with open(filepath, "r", encoding="utf-8") as f:
                            for line in f:
                                if line.strip():
                                    data = json.loads(line)
                                    employee_map[data["user_id"]] = data
                        _employee_cache[policy_id] = employee_map
                    except FileNotFoundError:
                        print(f"错误: 员工文件 {filepath} 未找到")
                        _employee_cache[policy_id] = {} # 存入空字典防止重复读取
                    except Exception as e:
                        print(f"错误: 解析员工文件 {filepath} 失败 - {e}")
                        _employee_cache[policy_id] = {}
            
        # 从缓存中查找用户
        return _employee_cache.get(policy_id, {}).get(user_id)

    async def _get_policy(self, policy_id: str) -> str:
        """
        从缓存或文件中获取租户的 Rego 策略字符串
        """
        if policy_id not in _policy_cache:
            filepath = self.policy_manager.get_policy_filepath(policy_id)
            async with _file_locks[filepath]:
                if policy_id not in _policy_cache:
                    print(f"缓存未命中: 正在从 {filepath} 加载 Rego 策略...")
                    try:
                        with open(filepath, "r", encoding="utf-8-sig") as f:
                            _policy_cache[policy_id] = f.read()
                    except FileNotFoundError:
                        print(f"错误: 策略文件 {filepath} 未找到")
                        _policy_cache[policy_id] = "" # 存入空字符串防止重复读取
                    except Exception as e:
                        print(f"错误: 读取策略文件 {filepath} 失败 - {e}")
                        _policy_cache[policy_id] = ""

        return _policy_cache.get(policy_id)

    async def _get_schema_description(self, policy_id: str) -> str:
        """
        (新增) 尝试从文件加载 schema 描述
        """
        filepath = self.policy_manager.get_schema_filepath(policy_id)
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


    async def invalidate_cache(self, policy_id: str):
        """异步接口，供路由层失效指定租户缓存"""
        self.clear_cache(policy_id)

    def clear_cache(self, policy_id: str):
        """
        (公开方法) 清除指定租户的缓存
        (由 setup_routes.py 在文件更新时调用)
        """
        if policy_id in _employee_cache:
            del _employee_cache[policy_id]
            print(f"缓存清除: 员工表 ({policy_id})")
        if policy_id in _policy_cache:
            del _policy_cache[policy_id]
            print(f"缓存清除: 策略 ({policy_id})")
            
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
        # (修改) tenant_id -> policy_id
        policy_id = "e2e_test_policy"
        
        mock_employees = (
            '{"user_id": "emp_manager", "user_role": "manager", "attributes": {"department": "Sales"}}\n'
            '{"user_id": "emp_regular", "user_role": "employee", "attributes": {"department": "Support"}}'
        )
        
        mock_schema = "CREATE TABLE employees (id varchar(100), name varchar(100), salary int, department varchar(50));"
        
        # 一个模拟的 Rego 策略 (Package name 也要相应修改以符合逻辑，虽然 OPA 不强制，但为了清晰)
        mock_rego_policy = """package e2e_test_policy.access

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
        try:
            from opa_client import OpaClient
            
            real_opa_instance = OpaClient(host="localhost", port=8181)
            
            if not real_opa_instance.check_health():
                raise ConnectionError("OPA 服务未在 http://localhost:8181 运行")

            # 创建一个包装器
            class OpaClientWrapper(OpaClient):
                async def evaluate_policy(
                    self,
                    policy_id: str, # (修改) tenant_id -> policy_id
                    input_data: dict,
                    rego_policy: str,
                    policy_data_path: str = "sqlopa.access.result",
                ) -> dict:
                    # 1. 动态推送策略
                    # (修改) endpoint 使用 policy_id
                    real_opa_instance.update_policy_from_string(
                        new_policy = rego_policy,
                        endpoint = policy_id
                    )
                    
                    # 2. 评估
                    package_path, _, rule_name = policy_data_path.rpartition(".")
                    # (修改) 默认路径 fallback
                    package_path = package_path.replace(".", "/") if package_path else f"{policy_id}/access"
                    result_full = real_opa_instance.query_rule(
                        input_data=input_data,
                        package_path=package_path,
                        rule_name=rule_name or policy_data_path,
                    )
                    # 提取 'result' 部分
                    return result_full.get("result", {})

            opa_client = OpaClientWrapper()
            print("\n*** 成功连接到真实 OPA 服务 (http://localhost:8181) ***\n")
            
        except (ImportError, ConnectionError) as e:
            print(f"\n*** 警告: 未找到 'opa-python-client' 或 OPA 服务未运行 ({e}) ***")
            print("*** 将使用 PolicyManager 中的 Rego LLM 生成提示词进行 *模拟* OPA 评估 ***\n")
            
            class MockOPAClient(OpaClient):
                async def evaluate_policy(
                    self,
                    policy_id: str, # (修改) tenant_id -> policy_id
                    input_data: dict,
                    rego_policy: str,
                    policy_data_path: str,
                ) -> dict:
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
        
        # 4. 写入模拟文件 (参数名修改)
        print("--- 正在设置测试文件... ---")
        await policy_manager.update_employee_table(policy_id, mock_employees)
        await policy_manager.update_db_schema(policy_id, mock_schema)
        await policy_manager.update_rego_policy(policy_id, mock_rego_policy)
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
                # (修改) 调用 check_query 时使用 policy_id
                result = await controller.check_query(
                    policy_id=policy_id,
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
    #    python -m permission_control.data.permission_controller
    
    # (新增) 修复相对导入
    sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

    asyncio.run(main_test())