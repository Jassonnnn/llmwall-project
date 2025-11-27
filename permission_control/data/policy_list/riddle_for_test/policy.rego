package riddle_for_test.access

import future.keywords.in
import future.keywords.or_
import data.time

# 1. 默认值
default allow := false
default allowed_columns := []
default row_constraints := {}
default reason := "Access denied by default. No rules matched."

# --- 关键：必须从 Schema 中提取所有列名，填入这里 ---
all_db_columns := [
    "id", "alarm_number", "alarm_time", "police_details", "phone_number", "jurisdiction_unit", "name_unit", "alarm_mode", "alarm_type", "alarm_category", "case_category", "case_type", "subcategories_cases", "alarm_content", "police_time", "police_situation", "first_level", "second_level", "third_level", "attribute_label", "number_personnel", "detailed_address", "street_name", "community_name", "area_name", "label_status", "data_status", "deleted", "creator", "create_time", "updater", "update_time", "remark", "user_id", "dept_id", "tenant_id"
]

# 2. 角色定义 (请根据 NL 规则填充这里)
# 注意：key 必须是小写 (例如 "manager")，与 user_role 匹配
roles := {
    "chief": {
        "description": "拥有最高权限，可以查看所有警情信息。但必须对涉及个人隐私的字段进行数据脱敏。",
        "allowed_columns": all_db_columns,
        "row_filter": "all",
        "excluded_columns": ["phone_number", "detailed_address"]
    },
    "engineer": {
        "description": "只能查看系统维护相关字段，且只能查询 data_status 为 '0' 的警单。",
        "allowed_columns": ["creator", "create_time", "update_time", "updater", "remark", "data_status"],
        "row_filter": "data_status_match",
        "excluded_columns": []
    },
    "analyst": {
        "description": "拥有科长的所有权限，但只能查询近 180 天内的警单。",
        "allowed_columns": all_db_columns,
        "row_filter": "recent_180_days",
        "excluded_columns": []
    },
    "supervisor": {
        "description": "拥有警员的所有权限，可以查看 dept_id 相同或 case_type 为 '诈骗' 的警单，但不能查看报警内容和处警情况，且不得查询本月的警单。",
        "allowed_columns": all_db_columns,
        "row_filter": "dept_or_case_type_match",
        "excluded_columns": ["alarm_content", "police_situation"]
    },
    "officer": {
        "description": "只能查看自己创建的警单，且只能查询上季度的警单。",
        "allowed_columns": ["alarm_number", "alarm_time", "police_details"],
        "row_filter": "self_created_quarter",
        "excluded_columns": []
    },
    "auditor": {
        "description": "只能查询 label_status 为 '0' 且 first_level 匹配 dept_id 的警单，且不能查看任何系统维护相关的字段。",
        "allowed_columns": all_db_columns,
        "row_filter": "label_status_and_dept_match",
        "excluded_columns": ["creator", "create_time", "updater", "update_time", "remark", "data_status", "label_status", "deleted"]
    }
}

# 3. 辅助变量
user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

# 3b. 有效过滤器注册 (请将你用到的 row_filter 名字加进去)
valid_row_filters := {
    "all", "self_only", "data_status_match", "recent_180_days", "dept_or_case_type_match", "self_created_quarter", "label_status_and_dept_match"
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

# 总工程师 (Engineer): 只能查询 data_status 为 '0' 的警单
row_constraints := {"data_status": "0"} if { role_config.row_filter == "data_status_match" }

# 分析师 (Analyst): 只能查询近 180 天内的警单
row_constraints := {"alarm_time": {"$gt": time.add(time.now(), -180 * 24 * 60 * 60)}} if { role_config.row_filter == "recent_180_days" }

# 科长 (Supervisor): 可以查看 dept_id 相同或 case_type 为 '诈骗' 的警单，且不得查询本月的警单
row_constraints := {"or": [{"dept_id": input.user.dept_id}, {"case_type": "诈骗"}], "alarm_time": {"$lt": time.add(time.now(), 30 * 24 * 60 * 60)}} if { role_config.row_filter == "dept_or_case_type_match" }

# 警员 (Officer): 只能查看自己创建的警单，且只能查询上季度的警单
row_constraints := {"creator": user_id, "alarm_time": {"$gte": time.add(time.now(), -90 * 24 * 60 * 60), "$lt": time.now()}} if { role_config.row_filter == "self_created_quarter" }

# 审计员 (Auditor): 只能查询 label_status 为 '0' 且 first_level 匹配 dept_id 的警单
row_constraints := {"label_status": "0", "first_level": input.user.dept_id} if { role_config.row_filter == "label_status_and_dept_match" }

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