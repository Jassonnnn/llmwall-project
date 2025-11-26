"""
(新文件) 策略管理 API 路由
- 包含 create_policy 和 update_policy
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from enum import Enum
from typing import List
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Form
from .schemas import UpdateFileType, PolicyUpdateResponse

# 导入服务和依赖注入
from data.policy_manager import PolicyManager
from data.permission_controller import PermissionController
from main import get_policy_manager, get_permission_controller

# 导入新的 Schemas (将在 schemas.py 中定义)
from .schemas import (
    CreatePolicyRequest, 
    UpdatePolicyRequest, 
    PolicyUpdateResponse,
    UpdateFileType
)

router = APIRouter()


@router.post("/create_policy", response_model=PolicyUpdateResponse, summary="创建新租户策略")
async def create_policy(
    request: CreatePolicyRequest,
    policy_manager: PolicyManager = Depends(get_policy_manager),
    controller: PermissionController = Depends(get_permission_controller)
):
    """
    接收租户ID、用户表和自然语言规则，并保存所有文件。
    这将自动触发 policy.rego 的生成。
    """
    try:
        files_updated = []

        # 1. 保存员工表
        employee_path = await policy_manager.update_employee_table(request.policy_id, request.user_table)
        files_updated.append(employee_path)

        # 2. 保存数据库 Schema
        schema_path = await policy_manager.update_db_schema(request.policy_id, request.db_schema)
        files_updated.append(schema_path)

        # 3. 保存自然语言规则 (这将自动触发 Rego 生成和保存)
        nl_path = await policy_manager.update_nl_policy(request.policy_id, request.nl_policy)
        files_updated.append(nl_path)
        # policy.rego 也会被创建
        files_updated.append(str(policy_manager.get_policy_filepath(request.policy_id)))

        # 4. (重要) 清除此租户的缓存
        await controller.invalidate_cache(request.policy_id)

        return PolicyUpdateResponse(
            status="success",
            policy_id=request.policy_id,
            files_updated=files_updated,
            message="Policy created, files saved, and Rego generated."
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create policy: {e}")


@router.post("/update_policy", response_model=PolicyUpdateResponse, summary="更新租户的单个文件")
async def update_policy(
    request: UpdatePolicyRequest,
    policy_manager: PolicyManager = Depends(get_policy_manager),
    controller: PermissionController = Depends(get_permission_controller)
):
    """
    根据 'file_type' 更新租户的单个文件。
    - sql: 更新 db_schema.sql
    - user_table: 更新 employees.jsonl
    - policy: 更新 nl_policy.txt (并触发 Rego 重新生成)
    - rego : 只更新rego文件（注意，需要把整段 Rego 代码变成 单行字符串）
    """
    try:
        file_path = ""
        
        # 根据文件类型调用 PolicyManager 中相应的方法
        if request.file_type == UpdateFileType.sql:
            file_path = await policy_manager.update_db_schema(request.policy_id, request.content)
            
        elif request.file_type == UpdateFileType.user_table:
            file_path = await policy_manager.update_employee_table(request.policy_id, request.content)
            
        elif request.file_type == UpdateFileType.policy:
            # 更新自然语言策略 (这将自动触发 Rego 重新生成)
            file_path = await policy_manager.update_nl_policy(request.policy_id, request.content)
        # 【新增】处理 纯 Rego 代码 (直接写入)
        elif request.file_type == UpdateFileType.rego:
            # 调用 PolicyManager 中已有的 update_rego_policy 方法
            file_path = await policy_manager.update_rego_policy(request.policy_id, request.content)
        
        else:
            # 这是一个理论上的情况, Pydantic 的 Enum 应该已经阻止了它
            raise HTTPException(status_code=400, detail="Invalid file_type")

        # (重要) 任何更新都必须清除缓存
        await controller.invalidate_cache(request.policy_id)
        
        return PolicyUpdateResponse(
            status="success",
            policy_id=request.policy_id,
            files_updated=[file_path],
            message=f"File '{request.file_type.value}' updated successfully."
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update policy: {e}")
    
    
    
# --- （新增接口）通过文件上传更新策略 ---
@router.post("/upload_file", response_model=PolicyUpdateResponse, summary="通过文件上传更新策略")
async def upload_file(
    policy_id: str = Form(...),         
    file_type: UpdateFileType = Form(...), 
    file: UploadFile = File(...),        
    policy_manager: PolicyManager = Depends(get_policy_manager),
    controller: PermissionController = Depends(get_permission_controller)
):
    """
    上传本地文件直接更新策略内容 (无需手动转义 JSON)。
    适合上传 .rego, .sql, .jsonl 文件。
    """
    try:
        # 1. 读取文件内容
        content_bytes = await file.read()
        content_str = content_bytes.decode("utf-8") # 将二进制转为字符串
        
        file_path = ""

        # 2. 复用之前的逻辑 (完全一样，只是数据源变成了 content_str)
        if file_type == UpdateFileType.sql:
            file_path = await policy_manager.update_db_schema(policy_id, content_str)
            
        elif file_type == UpdateFileType.user_table:
            file_path = await policy_manager.update_employee_table(policy_id, content_str)
            
        elif file_type == UpdateFileType.policy:
            file_path = await policy_manager.update_nl_policy(policy_id, content_str)
            
        elif file_type == UpdateFileType.rego:
            file_path = await policy_manager.update_rego_policy(policy_id, content_str)

        # 3. 清除缓存
        await controller.invalidate_cache(policy_id)
        
        return PolicyUpdateResponse(
            status="success",
            policy_id=policy_id,
            files_updated=[str(file_path)],
            message=f"File uploaded and updated successfully via {file.filename}"
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload policy: {e}")