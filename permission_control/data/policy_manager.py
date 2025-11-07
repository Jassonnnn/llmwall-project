import json
import os
import pickle
import asyncio
import re # (新增) 用于清理LLM输出
from litellm import acompletion # (新增) 导入 litellm
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any
# (已移除) from .opa_client import OPAClient

class PolicyManager:
    """
    (需求4 - 类) 规则管理器
    职责: (已修改) 只负责管理和写入（Write）策略和数据文件。
    不负责读取或缓存。
    """
    def __init__(self, 
                 # (已移除) opa_client: OPAClient, 
                 raw_data_path: str = "data/policy_list"):
        # self.opa_client = opa_client # (已移除)

        # 原始策略/Schema文件的路径
        self.raw_base_path = Path(raw_data_path)
        os.makedirs(self.raw_base_path, exist_ok=True)
        
        # 为每个租户的文件提供一个锁，以防止 *写入* 冲突
        self.tenant_write_locks = defaultdict(asyncio.Lock)
        
        # --- (已移除) 运行时内存缓存 ---
        # self.user_cache: ...
        # self.policy_cache: ...
        
        print(f"PolicyManager initialized. ")
        print(f"  -> Raw config (file) data: {self.raw_base_path.resolve()}")

    # --- (已移除) "Read" and "Cache" methods ---
    # async def get_user_attributes(...
    # async def get_policy(...

    # --- (新增) "Path Getters" ---
    # 允许 Controller 知道文件在哪里
    
    def get_employee_filepath(self, tenant_id: str) -> Path:
        """(新增) 获取员工表文件的路径"""
        return self.raw_base_path / tenant_id / "employees.jsonl"
        
    def get_policy_filepath(self, tenant_id: str) -> Path:
        """(新增) 获取策略文件的路径"""
        return self.raw_base_path / tenant_id / "policy.rego"
        
    def get_schema_filepath(self, tenant_id: str) -> Path:
        """(新增) 获取 Schema 文件的路径"""
        return self.raw_base_path / tenant_id / "db_schema.sql"

    # --- (新增) NL-to-Rego 转换 ---

    async def _generate_rego_from_nl(self, tenant_id: str, nl_policy: str) -> str:
        """
        (新增) 使用LLM将自然语言策略转换为Rego策略。
        它会读取 db_schema.sql 和 employees.jsonl (示例) 作为上下文。
        """
        print(f"Generating Rego from NL for tenant {tenant_id}...")
        
        db_schema_content = "No db_schema.sql found."
        employee_sample = "No employees.jsonl found."
        
        # (已修改) 使用新的 Path Getters
        # 注意: 这是一个 "write" 操作的一部分，因此它在写锁内部
        # 读取文件是安全的。
        try:
            db_schema_path = self.get_schema_filepath(tenant_id)
            if db_schema_path.exists():
                with open(db_schema_path, 'r', encoding='utf-8') as f:
                    db_schema_content = f.read()
        except Exception as e:
            print(f"Warning: Could not read db_schema.sql: {e}")
            
        try:
            employee_path = self.get_employee_filepath(tenant_id)
            if employee_path.exists():
                with open(employee_path, 'r', encoding='utf-8') as f:
                    employee_sample = f.readline() # 只读第一行作为示例
        except Exception as e:
            print(f"Warning: Could not read employees.jsonl: {e}")

        # (已修改) OPA Input 结构 (基于 V1 demo 的 opa_client.py)
        opa_input_example = f"""
# OPA Input 结构 (V1 Demo 格式)
{{
  "input": {{
    "user": {{
      "user_id": "emp003", 
      "attributes": {employee_sample}
    }},
    "query_request": {{
      "tables": ["employees"],
      "columns": ["salary"],
      "conditions": {{"id": "emp003"}},
      "query_type": "select"
    }}
  }}
}}
"""
        
        # (已修改) 构建系统提示词
        system_prompt = f"""
你是一个顶级的安全工程师，精通 OPA (Open Policy Agent) 和 Rego 语言。
你的任务是将自然语言 (NL) 规则转换为一个完整、可执行的 Rego 策略。

你必须使用以下上下文来生成策略：

1.  **数据库 Schema (`db_schema.sql`)**:
    ```sql
    {db_schema_content}
    ```

2.  **用户属性示例 (`employees.jsonl` line 1)**:
    ```json
    {employee_sample}
    ```
    (注意: 用户的属性在 'attributes' 键下)

3.  **OPA Input 结构**:
    你的 Rego 策略需要处理如下结构的 `input`：

    {opa_input_example}

4.  **Rego 规则 (必须全部生成)**:
    
    - 策略包(package)必须命名为 `sqlopa.access` (与 V1 demo 兼容)。
    - 你必须生成一个名为 `result` 的规则。
    - `result` 必须是一个包含以下键的**对象**:
        - `allowed` (boolean): 是否允许此查询。
        - `allowed_columns` (array[string]): 允许查询的列的列表。
        - `row_constraints` (object): 行级约束 (例如 {{"id": "emp003"}})。

    示例规则 (员工只能看自己的信息):
    ```rego
    package sqlopa.access

    default result = {{
        "allowed": false,
        "allowed_columns": [],
        "row_constraints": {{}}
    }}

    # 规则：员工(employee)
    result = {{
        "allowed": true,
        "allowed_columns": ["id", "name", "department"],
        "row_constraints": {{"id": input.user.user_id}}
    }} {{
        input.user.attributes.user_role == "employee"
        input.query_request.conditions.id == input.user.user_id
    }}
    ```

请严格遵守上述所有上下文和规则，在一个文件中生成所有需要的 package 和 policy。
"""
        
        # 构建用户提示词
        user_prompt = f"""
请将以下自然语言策略转换为 Rego 代码：

--- NL Policy ---
{nl_policy}
--- End NL Policy ---

请只返回 Rego 代码，不要包含 ```rego 或任何其他解释。
"""
        
        try:
            response = await acompletion(
                base_url="http://124.70.213.108:7009/v1",
                api_key = "sk-jjygDVvRsuTf6b1oNvHL6E7jpFIDRboL",
                model="qwen2.5-14b-instruct", # 示例, 请确保您已配置litellm
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.0
            )
            
            rego_code = response.choices[0].message.content
            
            # 清理LLM可能添加的 markdown 标记
            rego_code = re.sub(r"```rego\n", "", rego_code, flags=re.IGNORECASE)
            rego_code = re.sub(r"```", "", rego_code)
            rego_code = rego_code.strip()
            
            print(f"Successfully generated Rego code for tenant {tenant_id}")
            return rego_code
            
        except Exception as e:
            print(f"Error generating Rego from NL: {e}")
            return f"# ERROR: Failed to generate Rego policy. {e}"


    # --- 原始文件管理 (Raw File Management) ---

    async def _save_raw_file(self, tenant_id: str, file_name: str, content: str) -> Path:
        """
        (已修改) 内部辅助函数，用于保存原始配置文件。
        执行您要求的逻辑：检查/创建目录，然后创建/修改文件。
        (新增) 增加缓存失效逻辑。
        """
        # 路径: /data/policy_list/{tenant_id}
        tenant_path = self.raw_base_path / tenant_id
        
        # (已修改) 使用 "write" 锁
        async with self.tenant_write_locks[tenant_id]:
            
            # 1. 检查/创建文件夹
            if not tenant_path.exists():
                print(f"Creating directory: {tenant_path}")
                tenant_path.mkdir(parents=True, exist_ok=True)
            
            file_path = tenant_path / file_name
            
            # 2. 检查文件是否存在，然后创建或修改
            action = "Modifying" if file_path.exists() else "Creating"
            print(f"{action} raw file: {file_path}")
            
            # 在异步函数中执行同步I/O (FastAPI会处理线程池)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # --- (已移除) 缓存失效 ---
            # PolicyManager 不再管理缓存，移除所有失效逻辑
            
        return file_path

    async def update_nl_policy(self, tenant_id: str, content: str) -> str:
        # (已修改) 我们需要一个 "write" 锁来执行这个复合操作
        async with self.tenant_write_locks[tenant_id]:
            
            # 1. 保存自然语言策略文件 (nl_policy.txt)
            #    (我们调用一个内部非锁定版本)
            nl_file_path = await self._save_raw_file_unlocked(tenant_id, "nl_policy.txt", content)
            
            # 2. (新增) 调用LLM生成Rego策略
            print(f"NL policy updated. Triggering Rego generation for {tenant_id}...")
            try:
                rego_content = await self._generate_rego_from_nl(tenant_id, content)
                
                # 3. (新增) 保存生成的Rego策略
                await self._save_raw_file_unlocked(
                    tenant_id, 
                    "policy.rego", 
                    rego_content
                )
                print(f"Successfully saved auto-generated Rego policy for {tenant_id}")
                
            except Exception as e:
                print(f"Error during auto-generation of Rego: {e}")
            
            return str(nl_file_path)

    async def _save_raw_file_unlocked(self, tenant_id: str, file_name: str, content: str) -> Path:
        """(新增) _save_raw_file 的非锁定版本，供内部复合操作使用"""
        tenant_path = self.raw_base_path / tenant_id
        if not tenant_path.exists():
            print(f"Creating directory: {tenant_path}")
            tenant_path.mkdir(parents=True, exist_ok=True)
        
        file_path = tenant_path / file_name
        action = "Modifying" if file_path.exists() else "Creating"
        print(f"{action} raw file: {file_path}")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return file_path

    async def update_employee_table(self, tenant_id: str, content: str) -> str:
        """
        (新增) (Add/Modify) 员工表 (jsonl文件).
        """
        file_path = await self._save_raw_file(tenant_id, "employees.jsonl", content)
        return str(file_path)

    async def update_db_schema(self, tenant_id: str, content: str) -> str:
        """
        (新增) (Add/Modify) 数据库描述 (.sql).
        """
        file_path = await self._save_raw_file(tenant_id, "db_schema.sql", content)
        return str(file_path)
        
    async def update_rego_policy(self, tenant_id: str, content: str) -> str:
        """
        (已修改) (Add/Modify) Rego 策略文件 (policy.rego).
        - 移除了 policy_id
        """
        file_path = await self._save_raw_file(tenant_id, "policy.rego", content)
        return str(file_path)