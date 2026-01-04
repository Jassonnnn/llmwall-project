import os
import json
import re
import ast
import asyncio
from pathlib import Path
from typing import Dict, Any, List
from collections import defaultdict
from litellm import acompletion # 用于 LLM 解析
from opa_client import OpaClient

def extract_json_from_llm_response(content: str) -> dict:
    """
    从 LLM 响应中鲁棒地提取 JSON 数据，能够处理多个独立 JSON 块的情况。
    """
    all_json_objects = {}
    
    # --- 步骤 1: 查找所有 Markdown 代码块 ---
    # 使用 re.findall 找到所有匹配 ```json ... ``` 的内容
    code_block_pattern = r"```(?:json)?\s*(\{.*?})\s*```"
    matches = re.findall(code_block_pattern, content, re.DOTALL | re.IGNORECASE)

    if matches:
        for json_str_block in matches:
            try:
                # 尝试解析每个独立的 JSON 块
                parsed_block = json.loads(json_str_block)
                all_json_objects.update(parsed_block) # 合并到最终结果
            except json.JSONDecodeError:
                # 如果标准解析失败，尝试 ast.literal_eval (处理单引号等Python字典格式)
                try:
                    if json_str_block.strip().startswith("{"):
                        parsed_block = ast.literal_eval(json_str_block)
                        all_json_objects.update(parsed_block)
                except (ValueError, SyntaxError):
                    print(f"警告: 无法解析内部JSON块，跳过: {json_str_block[:100]}...")
                    continue # 跳过当前块，继续处理下一个

        if all_json_objects:
            return all_json_objects # 如果成功合并了任何JSON块，返回合并后的结果

    # --- 步骤 2: 如果没有Markdown代码块，或者代码块解析失败，尝试寻找最外层的单一JSON对象 ---
    # 清理所有可能的Markdown标记残留，以防它们干扰后续的整体JSON匹配
    cleaned_content_for_fallback = re.sub(r"```(?:json)?", "", content, flags=re.IGNORECASE)
    cleaned_content_for_fallback = cleaned_content_for_fallback.replace("```", "")
    
    start_idx = cleaned_content_for_fallback.find('{')
    end_idx = cleaned_content_for_fallback.rfind('}')
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_str_fallback = cleaned_content_for_fallback[start_idx : end_idx + 1]
        try:
            return json.loads(json_str_fallback)
        except json.JSONDecodeError as e:
            try:
                if json_str_fallback.strip().startswith("{"):
                    return ast.literal_eval(json_str_fallback)
            except (ValueError, SyntaxError):
                pass
            print(f"JSON解析失败（回退模式）: {e}")
            print(f"原始回退片段: {json_str_fallback[:100]}...")
            raise ValueError(f"JSON解析失败（回退模式）: {str(e)}")
    else:
        # 如果既没有代码块，也没有找到单一的 {} 结构
        raise ValueError("无法从LLM响应中提取任何JSON数据")

async def _parse_query_to_json(natural_query: str, user_info: str) -> Dict[str, Any]:
        """
        (新) 使用 LLM 将自然语言解析为 SQL-like JSON
        (基于用户提供的 llm_parser.py)
        (已修改) 使用用户指定的 litellm 参数
        """
        
        # (可选) 动态从 PolicyManager 加载 schema 描述
        schema_file_path = "db_schema.sql"
        if os.path.exists(schema_file_path):
            try:
                with open(schema_file_path, "r", encoding="utf-8") as f:
                    schema_desc = f.read()
            except Exception as e:
                print(f"读取schema文件出错：{e}")
                schema_desc = "employees表包含列：id, name, department, salary, position" # 备用硬编码
        else:
            print(f"警告：找不到文件{schema_file_path}，使用默认Schema")
            schema_desc = "employees表包含列：id, name, department, salary, position" # 备用硬编码
        
        # 2. (新增) 加载 Policy 描述
        policy_file_path = "nl_policy.txt"
        if os.path.exists(policy_file_path):
            try:
                with open(policy_file_path, "r", encoding="utf-8") as f:
                    policy_desc = f.read()
            except Exception as e:
                print(f"读取policy文件出错：{e}")
                policy_desc = "无特殊权限限制策略" # 默认备用
        else:
            print(f"警告：找不到文件{policy_file_path}，使用默认Policy")
            policy_desc = "无特殊权限限制策略" # 默认备用
        
        # (已修改) 拆分 system_prompt 和 user_prompt
        system_prompt = f"""
你是一个基于**多维校验架构**的数据库安全网关。你的任务是严格执行 **Schema（列）** 和 **Policy（行）** 的双重校验。

---
### 上下文信息
1. **数据库库表结构 (DDL)**:
{schema_desc}

2. **动态权限策略 (Policy)**:
{policy_desc}

---
### 核心思维链 (必须严格按顺序执行)

请在生成 JSON 之前，在内心依次执行以下两个维度的校验：

#### 维度一：列 (Column) 存在性校验 —— “关卡 1”
1.  **提取**: 分析用户请求中涉及的所有**目标字段** (Target Columns)。
2.  **比对**: 将这些字段与 DDL 表结构进行比对。
3.  **裁决**:
    *   **致命错误 (Fatal)**: 如果用户请求的核心字段在 DDL 中**完全不存在**（例如查警情表的“股票代码”），标记为 **ILLEGAL_SCHEMA**。
    *   **部分清洗 (Clean)**: 如果部分字段存在，部分不存在，**必须自动剔除**不存在的字段，仅保留合法字段进入下一关。
    *   **通过 (Pass)**: 所有字段均存在。

#### 维度二：行 (Row) 权限约束叠加 —— “关卡 2”
*(仅当通过“关卡 1”后执行此步)*

1.  **全量权限集 (Set_P) 构建**:
    *   **Layer 1 (Global)**: 提取“所有人”、“必须”等全局约束。
    *   **Layer 2 (Role)**: 根据 `role` 提取角色约束。
    *   **Set_P** = (Layer 1) AND (Layer 2)。

2.   **定义请求集 (Set_Q) —— “实例锁定与属性剥离”**: 
    *   **核心任务**: 从用户请求中**剥离**属于 Column 范畴的“属性词”，**只保留**属于 Row 范畴的“限定词/实体名”。
    *   **重要原则**: 在构建 Set_Q 时，**严禁使用 Set_P 中的内容**填充空白。如果用户没有指定过滤条件，Set_Q 应为空或全量。
    *   **执行步骤**:
        *   **Step 1: 右侧剥离 (Stripping)**
            *   **标准句式 ("...的...")**: 剥离 `[中心语]` (属性)，保留 `[定语]` (实体)。
            *   **紧凑句式 (无连接词)**: 执行**“右侧末尾剥离法”**。扫描句子最右侧的名词，如果它是 DDL 中的**列名**，则将其剥离。
        *   **Step 2: 实体映射 (Entity Mapping)**
            *   剥离后**剩余的文本**（如 "张三"、"iPhone15"）必须被保留。
            *   **必须**将其映射到 DDL 中最匹配的**标识字段**（如 `name`, `id`, `title`, `status` 等）。
            *   **构建条件**: `Set_Q` = `[标识字段] = '剩余文本'`。
    *   **通用对比示例 (Generic Contrast Examples)**:
        *   *场景A (标准)*: "查询 **张三** 的 **电话号码**" -> 剥离"电话号码" -> 剩余"张三" -> 映射 `name` -> `Set_Q = name='张三'`。
        *   *场景B (紧凑)*: "查询 **iPhone15价格**" -> 剥离"价格" -> 剩余"iPhone15" -> 映射 `product_name` -> `Set_Q = product_name='iPhone15'`。
        *   *场景C (反面教材)*: "查询 **ProjectX** 进度" -> ❌ `Set_Q = dept_id=10` (错！滥用权限填充) -> ✅ `Set_Q = project_name='ProjectX'` (对！映射具体实体)。

3.  **计算交集与冲突检测 (Intersection & Conflict Detection)**:
    *   **逻辑**: `Result_Set = Set_P ∩ Set_Q`。
    *   **同维互斥校验 (Same-Dimension Mutex Check)**:
        *   检查 `Set_P` (权限) 和 `Set_Q` (请求) 是否在**同一维度**上存在冲突。
        *   如果 Policy 限制 `Dimension_A = 'X'`，而 User 请求 `Dimension_A = 'Y'` (且 X!=Y)，则交集为**空 (Empty Set)**。
        *   *示例*: Policy=`region='Beijing'`, Request=`city='Shanghai'` -> **Conflict!** -> Empty Result.

4.  **裁决**:
    *   **ILLEGAL_PERMISSION**: `Result_Set` 为空（包含因逻辑冲突导致的空集）。
    *   **VALID**: `Result_Set` 非空。

---
### 输出生成规则 (关键！)

#### 1. 判定为非法的情况
如果 **关卡 1** 结果是 ILLEGAL_SCHEMA 或 **关卡 2** 结果是 ILLEGAL_PERMISSION：
*   `rewritten_query_logic.query_description` **必须严格输出**字符串 **"用户查询不合法"**。

#### 2. 判定为合法的情况
必须生成一句**重写后的结构化自然语言**，规则如下：
*   **体现清洗结果**: 描述中**只能包含** DDL 中实际存在的合法字段,同时**不得遗漏**用户请求的合法字段。
*   **体现权限收窄**: 描述中必须明确体现出`Result_Set` 的限制条件。
*   **参照用户输入**: 最终生成的自然语言最好在用户的原输入上进行改写

---
### 输出格式 (严格 JSON)
```json
{{
  "internal_analysis": {{
    "schema_check": {{
      "requested_columns": "用户想要查的列",
      "status": "VALID 或 PARTIAL_CLEANED 或 ILLEGAL_SCHEMA"
    }},
    "permission_check": {{
      "user_perm_set": "Set_P (权限集)",
      "query_target_set": "Set_Q (请求集)",
      "intersection": "Set_P ∩ Set_Q (交集)",
      "status": "VALID 或 ILLEGAL_PERMISSION"
    }}
  }},
  "rewritten_query_logic": {{
    "query_description": "最终查询逻辑描述。若非法则固定填 '用户查询不合法'。"
  }}
}}
"""
        user_prompt = f"""
请处理以下 Input Data：
{{
    "user": {user_info},
    "query_request": {natural_query}
}}
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
        
        print("LLM原始输出：", content)
        # (新增) 清理 LLM 可能返回的 markdown 标记
        return extract_json_from_llm_response(content)

test_cases = [
    # --- Group 1: Super Admin ---
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "从公司规章制度知识库中检索考勤相关的内容"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "从标书知识库中检索审批相关内容"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "研发知识库最新更新时间是何时"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "财务知识库关键词提取规则？"},
    {"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "测试知识库文本分块大小？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "运维知识库 PDF 解析器类型？"},
    {"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "分公司知识库图标链接？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "博思惟是知识库标签？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "长沙知识库是否含文件单元？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "深圳知识库页面排名值？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "财务知识库自动问题提取开关状态？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "财务知识库权限字段格式？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "财务知识库的表格转 HTML 是否开启？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "财务知识库是否开启知识图谱提取开关？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "文本分段标识符有哪些？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "含“预算”的知识库有哪些？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "运维知识库关键词“备份”出现几次？"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "长沙分公司知识库关于业绩的描述？"  },
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "SELECT * FROM knowledge_base LIMIT 10;"},
    #{"uid": "100", "role": "common", "dept_list": ["105"], "tenant": "1","query": "SELECT * FROM knowledge_base WHERE dept_id IN (105, 101) LIMIT 10;" }
]

async def show_comparison():
    # 1. 定义表头格式
    # 增加 Tenant 列，宽度设为 8
    header_fmt = "{:<4} | {:<12} | {:<8} | {:<12} | {:<25} | {}"
    
    print(header_fmt.format("UID", "Role", "Tenant", "Dept", "Input Query", "Model Output"))
    print("-" * 130)
    
    for case in test_cases:
        # 2. 构造 User Info JSON
        attributes = {
            "department": case["dept_list"],
            "tenant": case["tenant"]
        }
        user_info_dict = {
            "user_id": case["uid"],
            "user_role": case["role"],
            "attributes": attributes
        }
        user_info_str = json.dumps(user_info_dict, ensure_ascii=False)
        
        # 3. 调用模型
        try:
            result = await _parse_query_to_json(case["query"], user_info_str)
            output = result.get("rewritten_query_logic", {}).get("query_description", "Error")
        except Exception as e:
            output = f"Error: {e}"

        # 4. 格式化输出
        # 处理 None 显示
        dept_display = str(case["dept_list"]) if case["dept_list"] else "None"
        # 截断长 Query
        q_display = (case['query'][:23] + '..') if len(case['query']) > 23 else case['query']
        
        print(header_fmt.format(
            case['uid'], 
            case['role'], 
            case['tenant'],  # 新增列数据
            dept_display, 
            q_display, 
            output
        ))

if __name__ == "__main__":
    asyncio.run(show_comparison())