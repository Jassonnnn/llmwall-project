from pydantic import BaseModel, validator
from typing import List, Dict, Any
from enum import Enum # (新增) 导入 Enum

# --- (已移除) 旧的 Setup API Schemas ---
# RawDataRequest, RawDataResponse

# --- 检查 (Check) API Schemas ---
# (这些保持不变, 但我将使用 PermissionController1.py 中的新模型)

class ChatQueryRequest(BaseModel):
    policy_id: str
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
    policy_id: str
    user_table: str  # 员工表 (jsonl) 的完整内容
    db_schema: List[str]   # 数据库描述文件 (sql) 的完整内容, 支持按表拆分提交
    nl_policy: str   # 自然语言规则 (txt) 的完整内容

    @validator("db_schema", pre=True)
    def _ensure_schema_list(cls, value):
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            normalized = [str(item).strip() for item in value if str(item).strip()]
            if not normalized:
                raise ValueError("db_schema must include at least one table definition")
            return normalized
        raise ValueError("db_schema must be a string or a list of SQL table definitions")

class UpdateFileType(str, Enum):
    """
    用于 /update_policy 接口的文件类型
    """
    sql = "sql"
    user_table = "user_table"
    policy = "policy" # 代表 "nl_policy"
    rego = "rego"

class UpdatePolicyRequest(BaseModel):
    """
    用于 /update_policy 接口的请求体
    """
    policy_id: str
    file_type: UpdateFileType # 必须是 "sql", "user_table", 或 "policy"
    content: str            # 要更新的文件内容

class PolicyUpdateResponse(BaseModel):
    """
    create/update 接口的通用成功响应
    """
    status: str
    policy_id: str
    files_updated: List[str]
    message: str