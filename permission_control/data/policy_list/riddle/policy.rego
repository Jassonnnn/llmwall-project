package riddle.access

import rego.v1

# 1. 默认值 (Deny-by-default)
default allow := false
default allowed_columns := []
default row_constraints := {}
default reason := "Access denied by default. No rules matched."

# 2. 角色定义
roles := {
    "chief": {
        "description": "Chief",
        "allowed_columns": [
            "alarm_number",
            "alarm_time",
            "police_details",
            "jurisdiction_unit",
            "alarm_mode",
            "alarm_type",
            "alarm_category",
            "case_category",
            "case_type",
            "subcategories_cases",
            "alarm_content",
            "police_time",
            "police_situation",
            "first_level",
            "second_level",
            "third_level",
            "attribute_label",
            "number_personnel",
            "phone_number",         # 新增字段
            "detailed_address",     # 保留但需脱敏
            "street_name",
            "community_name",
            "area_name",
            "label_status",
            "data_status",
            "deleted",
            "creator",
            "create_time",
            "updater",
            "update_time",
            "remark",
            "user_id",
            "dept_id",
            "tenant_id"
        ],
        "row_filter": "all",
        "mask_columns": ["phone_number", "detailed_address"] # 脱敏字段
    },
    "engineer": {
        "description": "Engineer",
        "allowed_columns": [
            "creator",
            "create_time",
            "update_time",
            "updater",
            "remark",
            "data_status"
        ],
        "row_filter": "data_status_0"
    },
    "analyst": {
        "description": "Analyst",
        "allowed_columns": [
            # 继承 Supervisor 的列权限（排除 alarm_content 和 police_situation）
            "alarm_number",
            "alarm_time",
            "police_details",
            "jurisdiction_unit",
            "alarm_mode",
            "alarm_type",
            "alarm_category",
            "case_category",
            "case_type",
            "subcategories_cases",
            "first_level",
            "second_level",
            "third_level",
            "attribute_label",
            "number_personnel",
            "street_name",
            "community_name",
            "area_name",
            "label_status",
            "data_status",
            "deleted",
            "creator",
            "create_time",
            "updater",
            "update_time",
            "remark",
            "user_id",
            "dept_id",
            "tenant_id"
        ],
        # 必须同时满足 Supervisor 的行级权限 AND 近 180 天
        "row_filter": "dept_id_or_theft_recent_180_days"
    },
    "supervisor": {
        "description": "Supervisor",
        "allowed_columns": [
            "alarm_number",
            "alarm_time",
            "police_details",
            "jurisdiction_unit",
            "alarm_mode",
            "alarm_type",
            "alarm_category",
            "case_category",
            "case_type",
            "subcategories_cases",
            "first_level",
            "second_level",
            "third_level",
            "attribute_label",
            "number_personnel",
            "street_name",
            "community_name",
            "area_name",
            "label_status",
            "data_status",
            "deleted",
            "creator",
            "create_time",
            "updater",
            "update_time",
            "remark",
            "user_id",
            "dept_id",
            "tenant_id"
        ],
        "row_filter": "dept_id_or_theft"
    },
    "officer": {
        "description": "Officer",
        "allowed_columns": [
            "alarm_number",
            "alarm_time",
            "police_details",
            "jurisdiction_unit"
        ],
        # 必须同时满足自己创建 AND 上季度
        "row_filter": "created_by_self_last_quarter"
    },
    "auditor": {
        "description": "Auditor",
        "allowed_columns": [
            # 排除系统维护相关字段
            "alarm_number",
            "alarm_time",
            "police_details",
            "jurisdiction_unit",
            "alarm_mode",
            "alarm_type",
            "alarm_category",
            "case_category",
            "case_type",
            "subcategories_cases",
            "first_level",
            "second_level",
            "third_level",
            "attribute_label",
            "number_personnel",
            "street_name",
            "community_name",
            "area_name",
            "user_id",
            "dept_id",
            "tenant_id"
        ],
        "row_filter": "label_status_0"
    }
}

# 3. 辅助变量
user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

# 3b. 定义所有有效的过滤器类型
valid_row_filters := {
    "all",
    "self_only",
    "data_status_0",
    "recent_180_days",
    "dept_id_or_theft",
    "dept_id_or_theft_recent_180_days",
    "created_by_self",
    "created_by_self_last_quarter",
    "label_status_0",
    "last_quarter"
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

row_constraints := {"data_status": "0"} if {
    role_config.row_filter == "data_status_0"
}

row_constraints := {"alarm_time": {"$gte": "now() - 180 days"}} if {
    role_config.row_filter == "recent_180_days"
}

row_constraints := {"or": [{"dept_id": user_id}, {"case_type": "盗窃"}]} if {
    role_config.row_filter == "dept_id_or_theft"
}

row_constraints := {"and": [
    {"or": [{"dept_id": user_id}, {"case_type": "盗窃"}]},
    {"alarm_time": {"$gte": "now() - 180 days"}}
]} if {
    role_config.row_filter == "dept_id_or_theft_recent_180_days"
}

row_constraints := {"creator": user_id} if {
    role_config.row_filter == "created_by_self"
}

row_constraints := {"and": [
    {"creator": user_id},
    {"alarm_time": {"$between": "last_quarter"}}
]} if {
    role_config.row_filter == "created_by_self_last_quarter"
}

row_constraints := {"label_status": "0"} if {
    role_config.row_filter == "label_status_0"
}

row_constraints := {"deny": true} if {
    role_config
    not role_config.row_filter in valid_row_filters
}

# 6. 最终 `allow` 决策
allow if {
    role_config
    count(allowed_columns) > 0
    not row_constraints.deny
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

# 8. 最终聚合结果
result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}