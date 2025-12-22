package police_1.access

import rego.v1

# 1. 默认设置
default allow := false
default allowed_columns := []
default row_constraints := {"deny": true}
default reason := "Access denied by default. No rules matched."
default role_config := {}

# --- 关键：从 Schema 中提取所有列名，填入这里 ---
# 这是通配符 (*) 展开的基础
all_db_columns := {
    "tb_case_info.id",
    "tb_case_info.alarm_number",
    "tb_case_info.alarm_time",
    "tb_case_info.police_details",
    "tb_case_info.phone_number",
    "tb_case_info.jurisdiction_unit",
    "tb_case_info.name_unit",
    "tb_case_info.alarm_mode",
    "tb_case_info.alarm_type",
    "tb_case_info.alarm_category",
    "tb_case_info.case_category",
    "tb_case_info.case_type",
    "tb_case_info.subcategories_cases",
    "tb_case_info.alarm_content",
    "tb_case_info.police_time",
    "tb_case_info.police_situation",
    "tb_case_info.first_level",
    "tb_case_info.second_level",
    "tb_case_info.third_level",
    "tb_case_info.attribute_label",
    "tb_case_info.number_personnel",
    "tb_case_info.detailed_address",
    "tb_case_info.street_name",
    "tb_case_info.community_name",
    "tb_case_info.area_name",
    "tb_case_info.label_status",
    "tb_case_info.data_status",
    "tb_case_info.deleted",
    "tb_case_info.creator",
    "tb_case_info.create_time",
    "tb_case_info.updater",
    "tb_case_info.update_time",
    "tb_case_info.remark",
    "tb_case_info.user_id",
    "tb_case_info.tenant_id"
}

# 2. 角色定义 (请根据 NL 规则填充这里)
# NL: 超级管理者(super_admin) 可以查看所有警情数据。普通角色(common) 只能查看自己部门的警情数据
roles := {
    "super_admin": {
        "description": "Super Administrator with full access",
        "allowed_columns": ["*"], 
        "row_filter": "all",
        "excluded_columns": [] 
    },
    "common": {
        "description": "Common user restricted to their own department",
        "allowed_columns": ["*"],
        "row_filter": "dept_match",
        "excluded_columns": []
    }
}

# 3. 全局辅助变量(请根据{user_sample}中的attributes添加新的全局辅助变量)
user_role := input.user.user_role
user_id := input.user.user_id
# 从 user attributes 中提取 department (e.g., "白杨派出所")
user_dept := input.user.attributes.department

# 安全获取配置，如果角色不存在返回空对象
role_config := object.get(roles, user_role, {})

# 3b. 有效过滤器注册 (请将你用到的 row_filter 名字加进去)
valid_row_filters := {
    "all", "self_only", "dept_match"
}

# -----------------------------------------------------------------------------
# 4. 列访问逻辑 (严禁修改结构 - Pipeline 模式)
# -----------------------------------------------------------------------------

# [Step A] 计算基准列集 (Base Set)
# 如果配置包含 "*"，则展开为 all_db_columns，否则使用配置列表
base_columns_set := cols if {
    "*" in role_config.allowed_columns
    cols := all_db_columns
} else := cols if {
    role_config.allowed_columns # 确保字段存在
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
    # 如果请求 select *，则返回所有该角色允许的列
    cols := base_valid_set
} else := cols if {
    not requested_is_wildcard
    cols := {c | c := requested_cols_raw[_]}
}

# [Step E] 最终允许集合 = (Base - Blacklist) AND Requested
# 只有既在白名单、又不在黑名单、且被请求的列才会被返回
final_allowed_set := base_valid_set & requested_set

# [Step F] 格式化输出
allowed_columns := sort([c | final_allowed_set[c]])

# -----------------------------------------------------------------------------
# 5. 行访问逻辑 (请根据 NL 规则编写具体实现)
# -----------------------------------------------------------------------------

# 场景 1: 无限制
row_constraints := {} if { role_config.row_filter == "all" }

# 场景 2: 仅自己 (虽然本例未明确使用，但作为模板保留)
row_constraints := {"tb_case_info.user_id": user_id} if { role_config.row_filter == "self_only" }

# 场景 3: 部门匹配 (Scope Match)
# 规则: 普通角色(common) 只能查看自己部门的警情数据
# 对应关系: 用户属性(department) == 数据库字段(name_unit - 管辖单位名称)
row_constraints := {
    "tb_case_info.name_unit": user_dept
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