package riddle_policy.access

import rego.v1

# 1. 默认设置
default allow := false
default allowed_columns := []
default row_constraints := {"deny": true}
default reason := "Access denied by default. No rules matched."
default role_config := {}

# --- 关键：从 Schema 中提取所有列名，填入这里 ---
all_db_columns := {
    "employee_profiles.user_id": true,
    "employee_profiles.name": true,
    "employee_profiles.title": true,
    "compensation.user_id": true,
    "compensation.monthly_salary": true,
    "compensation.annual_bonus": true
}

# 2. 角色定义 (请根据 NL 规则填充这里)
roles := {
    "boss": {
        "description": "Full access boss",
        "allowed_columns": ["*"],
        "row_filter": "all",
        "excluded_columns": []
    }
}

# 3. 全局辅助变量
user_role := input.user.user_role
user_id := input.user.user_id

# 安全获取配置，如果角色不存在返回空对象
role_config := object.get(roles, user_role, {})

# 3b. 有效过滤器注册
valid_row_filters := {
    "all", "self_only"
}

# -----------------------------------------------------------------------------
# 4. 列访问逻辑 (严禁修改结构 - Pipeline 模式)
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

# [Step C] 计算基准有效集 (Base - Blacklist)
base_valid_set := base_columns_set - blacklisted

# [Step D] 处理请求的列 (Requested Set)
requested_cols_raw := object.get(input.query_request, "columns", [])
requested_is_wildcard if { "*" in requested_cols_raw }

requested_set := cols if {
    requested_is_wildcard
    cols := base_valid_set
} else := cols if {
    not requested_is_wildcard
    cols := {c | c := requested_cols_raw[_]}
}

# [Step E] 最终允许集合 = (Base - Blacklist) AND Requested
final_allowed_set := base_valid_set & requested_set

# [Step F] 格式化输出
allowed_columns := sort([c | final_allowed_set[c]])

# -----------------------------------------------------------------------------
# 5. 行访问逻辑 (请根据 NL 规则编写具体实现)
# -----------------------------------------------------------------------------

# 场景 1: 无限制
row_constraints := {} if { role_config.row_filter == "all" }

# 场景 2: 仅自己
row_constraints := {"user_id": user_id} if { role_config.row_filter == "self_only" }

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
    count(role_config) > 0        # 角色存在
    count(allowed_columns) > 0    # 至少有一列权限
    not row_constraints.deny      # 行权限未被拒绝
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