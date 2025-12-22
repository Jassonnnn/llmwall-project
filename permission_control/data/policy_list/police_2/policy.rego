package police_2.access

import rego.v1

# 1. 默认设置
default allow := false
default allowed_columns := []
default row_constraints := {"deny": true}
default reason := "Access denied by default. No rules matched."
default role_config := {}

# --- 关键：从 Schema 中提取所有列名，填入这里 ---
all_db_columns := {
    "tb_case_info.id", "tb_case_info.alarm_number", "tb_case_info.alarm_time", "tb_case_info.police_details", "tb_case_info.phone_number", "tb_case_info.jurisdiction_unit", "tb_case_info.name_unit", "tb_case_info.alarm_mode", "tb_case_info.alarm_type", "tb_case_info.alarm_category", "tb_case_info.case_category", "tb_case_info.case_type", "tb_case_info.subcategories_cases", "tb_case_info.alarm_content", "tb_case_info.police_time", "tb_case_info.police_situation", "tb_case_info.first_level", "tb_case_info.second_level", "tb_case_info.third_level", "tb_case_info.attribute_label", "tb_case_info.number_personnel", "tb_case_info.detailed_address", "tb_case_info.street_name", "tb_case_info.community_name", "tb_case_info.area_name", "tb_case_info.label_status", "tb_case_info.data_status", "tb_case_info.deleted", "tb_case_info.creator", "tb_case_info.create_time", "tb_case_info.updater", "tb_case_info.update_time", "tb_case_info.remark", "tb_case_info.user_id", "tb_case_info.tenant_id"
}

# 2. 角色定义
roles := {
    "super_admin": {
        "description": "Full access super admin",
        "allowed_columns": ["*"], 
        "row_filter": "all",
        "excluded_columns": [] 
    },
    "common": {
        "description": "Standard common role",
        "allowed_columns": ["*"],
        "row_filter": "dept_match",
        "excluded_columns": []
    }
}

# 3. 全局辅助变量
user_role := input.user.user_role
user_id := input.user.user_id
user_department := input.user.attributes.department

# 安全获取配置
role_config := object.get(roles, user_role, {})

# 3b. 有效过滤器注册
valid_row_filters := {
    "all", "self_only", "dept_match"
}

# -----------------------------------------------------------------------------
# 4. 列访问逻辑 (Pipeline 模式)
# -----------------------------------------------------------------------------

# [Step A] 计算基准列集 (Base Set)
base_columns_set := cols if {
    "*" in role_config.allowed_columns
    cols := all_db_columns
} else := cols if {
    role_config.allowed_columns
    not "*" in role_config.allowed_columns
    cols := {col | col := role_config.allowed_columns[_]}
} else := {}

# [Step B] 提取黑名单
blacklisted := {c | c := object.get(role_config, "excluded_columns", [])[_]}

# [Step C] 计算基准有效集
base_valid_set := base_columns_set - blacklisted

# [Step D] 处理请求的列 (支持模糊匹配)
requested_cols_raw := object.get(input.query_request, "columns", [])
requested_is_wildcard if { "*" in requested_cols_raw }

# 辅助函数：列名匹配 (处理 user_id vs tb_case_info.user_id)
match_column(req, db) if { req == db }
match_column(req, db) if { endswith(db, concat(".", ["", req])) }

final_allowed_set := allowed if {
    requested_is_wildcard
    allowed := base_valid_set
} else := allowed if {
    not requested_is_wildcard
    allowed := {db_col |
        some req_col in requested_cols_raw
        some db_col in base_valid_set
        match_column(req_col, db_col)
    }
}

# [Step F] 格式化输出
allowed_columns := sort([c | final_allowed_set[c]])

# -----------------------------------------------------------------------------
# 5. 行访问逻辑
# -----------------------------------------------------------------------------

# 场景 1: 无限制
row_constraints := {} if { role_config.row_filter == "all" }

# 场景 2: 仅自己 (修复：加上表名)
row_constraints := {"tb_case_info.user_id": user_id} if { role_config.row_filter == "self_only" }

# 场景 3: 部门匹配 (修复：加上表名)
# 这里的键必须与 all_db_columns 中的格式一致
row_constraints := {
    "tb_case_info.jurisdiction_unit": user_department
} if { 
    role_config.row_filter == "dept_match" 
}

# 兜底: 拒绝无效或未定义的 row_filter
row_constraints := {"deny": true} if {
    count(role_config) > 0
    filter := object.get(role_config, "row_filter", "")
    not filter in valid_row_filters
}

# -----------------------------------------------------------------------------
# 6. 最终裁决
# -----------------------------------------------------------------------------
allow if {
    count(role_config) > 0        
    count(allowed_columns) > 0    
    not row_constraints.deny      
}

# 7. 决策理由
reason := sprintf("Access Granted for role: %s", [user_role]) if { allow }
else := "Access Denied: Role undefined." if { count(role_config) == 0 }
else := "Access Denied: No valid columns requested or allowed." if { not allow; count(allowed_columns) == 0 }
else := "Access Denied: Row constraint restriction." if { not allow; row_constraints.deny }

# 8. 输出结果
result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}