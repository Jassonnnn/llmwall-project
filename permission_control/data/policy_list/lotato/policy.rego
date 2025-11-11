package lotato.access

import rego.v1

# 1. 默认值 (Deny-by-default)
default allow := false
default allowed_columns := []
default row_constraints := {}
default reason := "Access denied by default. No rules matched."

# 2. 角色定义
roles := {
    "manager": {
        "description": "Manager",
        "allowed_columns": ["name", "department", "salary"],
        "row_filter": "all"
    },
    "employee": {
        "description": "Employee",
        "allowed_columns": ["name", "department"],
        "row_filter": "self_only"
    }
}

# 3. 辅助变量
user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

# 3b. 定义所有有效的过滤器类型
valid_row_filters := {
    "all",
    "self_only"
}

# 4. 列访问逻辑 (处理 "SELECT *")
allowed_columns := role_config.allowed_columns if {
    role_config
    input.query_request.columns[_] == "*"
}

# 4. 列访问逻辑 (处理特定列)
allowed_columns := intersection if {
    role_config
    not "*" in input.query_request.columns
    
    intersection := [col |
        col := input.query_request.columns[_]
        col in role_config.allowed_columns
    ]
}

# 5. 行访问逻辑 (根据 role_config.row_filter 扩展)
row_constraints := {} if {
    role_config.row_filter == "all"
}

row_constraints := {"id": user_id} if {
    role_config.row_filter == "self_only"
}

# 5b. (已改进) 拒绝无效的 row_filter
row_constraints := {"deny": true} if {
    role_config
    not role_config.row_filter in valid_row_filters
}

# 6. 最终 `allow` 决策
allow if {
    role_config
    count(allowed_columns) > 0 # 必须请求至少一个允许的列
    not row_constraints.deny   # 确保行过滤器有效
}

# 7. 决策理由
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

reason := "Access Denied: This role has no valid row-level access permissions." if {
    not allow
    role_config
    row_constraints.deny
}

# 8. 最终聚合结果 (不得修改此结构)
result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}