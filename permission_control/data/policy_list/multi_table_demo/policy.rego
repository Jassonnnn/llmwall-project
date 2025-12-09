package multi_table_demo.access

import future.keywords.in
import future.keywords.if
import future.keywords.contains

# -----------------------------------------------------------------------------
# 1. 默认设置
# -----------------------------------------------------------------------------
default allow := false
default allowed_columns := []
default row_constraints := {"deny": true}
default reason := "Access denied by default."

# 【关键修改】这里定义数据库中所有的 "表名.列名"
# 这是 wildcard (*) 展开的基础
all_db_columns := {
    "employee_profiles.user_id",
    "employee_profiles.name",
    "employee_profiles.title",
    "compensation.user_id",
    "compensation.monthly_salary",
    "compensation.annual_bonus"
}

# -----------------------------------------------------------------------------
# 2. 角色策略配置
# -----------------------------------------------------------------------------
roles := {
    "boss": {
        "description": "Boss can view everything.",
        "allowed_columns": ["*"], 
        "row_filter_type": "no_restriction",
        "excluded_columns": []
    },
    "team_lead": {
        "description": "Team Lead sees employee salaries, but no bonuses.",
        # 【关键修改】明确指定带表名的字段
        "allowed_columns": [
            "employee_profiles.user_id",
            "employee_profiles.name",
            "employee_profiles.title",
            "compensation.user_id", 
            "compensation.monthly_salary"
        ],
        "row_filter_type": "team_scope_employees",
        # 【关键修改】明确排除带表名的字段
        "excluded_columns": ["compensation.annual_bonus"]
    },
    "employee": {
        "description": "Employees see only their own data.",
        "allowed_columns": [
            "employee_profiles.user_id", 
            "employee_profiles.name",
            "employee_profiles.title",
            "compensation.monthly_salary", 
            "compensation.annual_bonus"
        ],
        "row_filter_type": "self_only",
        "excluded_columns": []
    }
}

# 提取上下文
user_role := input.user.user_role
user_id := input.user.user_id
user_team := input.user.attributes.team
role_config := roles[user_role]

# -----------------------------------------------------------------------------
# 3. 列权限逻辑 (Strict Matching)
# -----------------------------------------------------------------------------

# 3.1 计算基础允许集合 (Base Set)
# 如果配置了 "*"，则展开为 all_db_columns，否则使用配置列表
base_allowed_set := cols if {
    "*" in role_config.allowed_columns
    cols := all_db_columns
} else := cols if {
    not "*" in role_config.allowed_columns
    cols := {col | col := role_config.allowed_columns[_]}
}

# 3.2 计算请求集合 (Requested Set)
# 直接使用 input 中的全名，不再进行 split 清洗
requested_set := cols if {
    "*" in input.query_request.columns
    # 如果用户请求 SELECT *，则赋予该角色所能拥有的最大权限
    cols := base_allowed_set
} else := cols if {
    not "*" in input.query_request.columns
    cols := {col | col := input.query_request.columns[_]}
}

# 3.3 计算最终允许集合
# 公式: (Base - Excluded) AND Requested
# 这样可以确保请求的字段既在白名单内，又不在黑名单内，且名称完全匹配
final_allowed_set := (base_allowed_set - {c | c := role_config.excluded_columns[_]}) & requested_set

# 3.4 格式化输出
allowed_columns := sort([c | final_allowed_set[c]])

# -----------------------------------------------------------------------------
# 4. 行级权限逻辑
# -----------------------------------------------------------------------------

row_constraints := {} if {
    role_config.row_filter_type == "no_restriction"
}

row_constraints := {"user_id": user_id} if {
    role_config.row_filter_type == "self_only"
}

row_constraints := {
    "team": user_team,
    "target_role": "employee" 
} if {
    role_config.row_filter_type == "team_scope_employees"
}

# -----------------------------------------------------------------------------
# 5. 最终裁决
# -----------------------------------------------------------------------------

allow if {
    role_config
    count(allowed_columns) > 0
    not row_constraints.deny
}

reason := sprintf("Allowed. Role: %s", [user_role]) if { allow }
else := "Denied: Permission mismatch or role undefined."

result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}