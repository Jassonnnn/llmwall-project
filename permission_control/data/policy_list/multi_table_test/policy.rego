package multi_table_test.access

import future.keywords.in

# 1. 默认值
default allow := false
default allowed_columns := []
default row_constraints := {}
default reason := "Access denied by default. No rules matched."

# --- 关键：必须从 Schema 中提取所有列名，填入这里 ---
all_db_columns := [
    "id", "name", "salary", "dept_id", "dept_name", "location"
]

# 2. 角色定义 (请根据 NL 规则填充这里)
# 注意：key 必须是小写 (例如 "manager")，与 user_role 匹配
roles := {
    "admin": {
        "description": "管理员可以查看所有表的所有信息。",
        "allowed_columns": all_db_columns,
        "row_filter": "all",
        "excluded_columns": []
    },
    "employee": {
        "description": "员工只能查看自己的信息。",
        "allowed_columns": all_db_columns,
        "row_filter": "self_only",
        "excluded_columns": []
    }
}

# 3. 辅助变量
user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

# 3b. 有效过滤器注册 (请将你用到的 row_filter 名字加进去)
valid_row_filters := {
    "all", "self_only"
}

# 4. 列访问逻辑 (核心逻辑 - 请勿修改结构)
allowed_columns := final_allowed if {
    user_role := input.user.user_role
    role_config := roles[user_role]
    
    # 1. 确定基准列集
    is_wildcard_allowed := true if {
        some idx; role_config.allowed_columns[idx] == "*"
    } else := false

    base_columns_set := set(all_db_columns) if {
        is_wildcard_allowed
    } else := set(role_config.allowed_columns)

    # 2. 应用黑名单 (excluded_columns)
    blacklisted := set(role_config.excluded_columns)
    base_columns_after_exclusion := base_columns_set - blacklisted

    # 3. 应用请求交集
    requested := set(input.query_request.columns)
    requested_is_wildcard := true if {
        some idx; input.query_request.columns[idx] == "*"
    } else := false
    
    final_allowed_set := base_columns_after_exclusion & requested if {
        not requested_is_wildcard
    } else := base_columns_after_exclusion

    final_allowed := array.sort(array.concat([], final_allowed_set))
    true
}

# 5. 行访问逻辑 (请根据 NL 规则编写具体实现)

# 示例：无限制
row_constraints := {} if { role_config.row_filter == "all" }

# 示例：仅自己
row_constraints := {"id": user_id} if { role_config.row_filter == "self_only" }

# --- 在此处根据 NL 规则添加更多 row_constraints ---
# 例如: 
# row_constraints := {"dept_id": input.user.dept_id} if { role_config.row_filter == "dept_match" }

# 5b. 拒绝无效 row_filter
row_constraints := {"deny": true} if {
    role_config
    not role_config.row_filter in valid_row_filters
}

# 6. 最终裁决
allow if {
    role_config
    count(allowed_columns) > 0
    not row_constraints.deny
}

# 7. 决策理由
reason := sprintf("Access Granted for %s", [role_config.description]) if { allow }
reason := "Access Denied: This role is not defined in the policy." if { not allow; not role_config }
reason := "Access Denied: Column restriction." if { not allow; role_config; count(allowed_columns) == 0 }
reason := "Access Denied: Row restriction." if { not allow; role_config; row_constraints.deny }

# 8. 输出结果
result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}