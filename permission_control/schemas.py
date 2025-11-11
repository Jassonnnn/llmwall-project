from pydantic import BaseModel
from typing import List, Dict, Any
from enum import Enum # (新增) 导入 Enum

# --- (已移除) 旧的 Setup API Schemas ---
# RawDataRequest, RawDataResponse

# --- 检查 (Check) API Schemas ---
# (这些保持不变, 但我将使用 PermissionController1.py 中的新模型)

class ChatQueryRequest(BaseModel):
    tenant_id: str
    user_id: str
    query: str
    conversation_history: List[Dict[str, Any]] = []

class ChatQueryResponse(BaseModel):
    decision: str
    rewritten_query: str | None = None
    reason: str | None = None
    opa_result: Dict[str, Any] | None = None


# --- (新增) 策略管理 (Policy Management) API Schemas ---

class CreatePolicyRequest(BaseModel):
    """
    用于 /create_policy 接口的请求体
    """
    tenant_id: str
    user_table: str  # 员工表 (jsonl) 的完整内容
    db_schema: str   # 数据库描述文件 (sql) 的完整内容
    nl_policy: str   # 自然语言规则 (txt) 的完整内容

class UpdateFileType(str, Enum):
    """
    用于 /update_policy 接口的文件类型
    """
    sql = "sql"
    user_table = "user_table"
    policy = "policy" # 代表 "nl_policy"

class UpdatePolicyRequest(BaseModel):
    """
    用于 /update_policy 接口的请求体
    """
    tenant_id: str
    file_type: UpdateFileType # 必须是 "sql", "user_table", 或 "policy"
    content: str            # 要更新的文件内容

class PolicyUpdateResponse(BaseModel):
    """
    create/update 接口的通用成功响应
    """
    status: str
    tenant_id: str
    files_updated: List[str]
    message: str