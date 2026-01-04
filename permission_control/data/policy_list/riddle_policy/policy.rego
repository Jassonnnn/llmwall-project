package riddle_policy.access
import rego.v1

# =============================================================================
# 1. 默认设置 & 数据库全集
# =============================================================================
default allow := false 
default allowed_columns := []
default row_constraints := {"deny": true}
default reason := "Access denied by default."
default role_config := {}

# [需填充] 数据库全集
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
roles := {
    "super_admin": {
        "description": "超级管理者可以查看所有警情数据",
        "allowed_columns": ["*"],
        "row_filter_rule": "full_access",
        "excluded_columns": []
    },
    "common": {
        "description": "普通角色只能查看自己部门的警情数据",
        "allowed_columns": ["*"],
        "row_filter_rule": "department_restricted",
        "excluded_columns": []
    }
}

# 3. 全局辅助变量 & 增强型时间引擎 (Enhanced Time Engine) [严禁修改且最终保留]
# =============================================================================
user_role := input.user.user_role
user_attrs := object.get(input.user, "attributes", input.user)
role_config := object.get(roles, user_role, {})

# --- [Core] 基础时间计算 (时区: Asia/Shanghai) ---
ns_now := time.now_ns()
fmt_full(ns) := time.format([ns, "Asia/Shanghai", "2006-01-02 15:04:05"])
fmt_date(ns) := time.format([ns, "Asia/Shanghai", "2006-01-02"])

# --- [A] 基础锚点 (Base Anchors) ---
str_now := fmt_full(ns_now)
str_today := fmt_date(ns_now)
str_yesterday := fmt_date(time.add_date(ns_now, 0, 0, -1))
str_tomorrow := fmt_date(time.add_date(ns_now, 0, 0, 1))

# --- [B.1] 月份锚点 (Month Windows) ---
date_vec := time.date(ns_now) # [year, month, day]
curr_year := date_vec[0]
curr_month := date_vec[1]

# 本月 (Current Month)
str_curr_month_start := sprintf("%d-%02d-01", [curr_year, curr_month])
# 计算本月最后一天: 下个月1号 减去 1天 (24小时)
ns_next_month_1st := time.parse_ns("2006-01-02", sprintf("%d-%02d-01", [
    time.date(time.add_date(ns_now, 0, 1, 0))[0], 
    time.date(time.add_date(ns_now, 0, 1, 0))[1]
]))
str_curr_month_end := fmt_date(time.add_date(ns_next_month_1st, 0, 0, -1))

# 上个月 (Last Month)
ns_last_month := time.add_date(ns_now, 0, -1, 0)
str_last_month_start := sprintf("%d-%02d-01", [time.date(ns_last_month)[0], time.date(ns_last_month)[1]])
# 上个月最后一天: 本月1号 减去 1天
ns_curr_month_1st_parsed := time.parse_ns("2006-01-02", str_curr_month_start)
str_last_month_end := fmt_date(time.add_date(ns_curr_month_1st_parsed, 0, 0, -1))

# --- [B.2] 年份锚点 (Year Windows) ---
# 今年
str_curr_year_start := sprintf("%d-01-01", [curr_year])
str_curr_year_end := sprintf("%d-12-31", [curr_year])

# 去年
str_last_year_start := sprintf("%d-01-01", [curr_year - 1])
str_last_year_end := sprintf("%d-12-31", [curr_year - 1])

# --- [B.3] 去年同月 (Last Year Same Month) ---
# 起始: 去年 + 当前月 + 01
str_lysm_start := sprintf("%d-%02d-01", [curr_year - 1, curr_month])
# 结束: 先找到“去年同月”的下个月1号，再减1天
# 逻辑: (当前时间 - 1年 + 1月) 的1号 - 1天
ns_lysm_next_month := time.add_date(ns_now, -1, 1, 0)
str_lysm_next_month_1st := sprintf("%d-%02d-01", [time.date(ns_lysm_next_month)[0], time.date(ns_lysm_next_month)[1]])
str_lysm_end := fmt_date(time.add_date(time.parse_ns("2006-01-02", str_lysm_next_month_1st), 0, 0, -1))


# --- 解析逻辑 Step 1: 静态 Token 替换 ---
resolve_step_1(val) := v1 if {
    is_string(val)
    # 1. Base Anchors
    s0 := replace(replace(replace(val, "{{NOW}}", str_now), "{{TODAY}}", str_today), "{{YESTERDAY}}", str_yesterday)
    s1 := replace(s0, "{{TOMORROW}}", str_tomorrow)
    
    # 2. Month Windows
    s2 := replace(replace(s1, "{{CURRENT_MONTH_START}}", str_curr_month_start), "{{CURRENT_MONTH_END}}", str_curr_month_end)
    s3 := replace(replace(s2, "{{LAST_MONTH_START}}", str_last_month_start), "{{LAST_MONTH_END}}", str_last_month_end)
    
    # 3. Year Windows (新增)
    s4 := replace(replace(s3, "{{CURRENT_YEAR_START}}", str_curr_year_start), "{{CURRENT_YEAR_END}}", str_curr_year_end)
    s5 := replace(replace(s4, "{{LAST_YEAR_START}}", str_last_year_start), "{{LAST_YEAR_END}}", str_last_year_end)
    
    # 4. Last Year Same Month (新增)
    v1 := replace(replace(s5, "{{LAST_YEAR_SAME_MONTH_START}}", str_lysm_start), "{{LAST_YEAR_SAME_MONTH_END}}", str_lysm_end)
} else := val

# --- 解析逻辑 Step 2: 动态解析 (startswith) ---
resolve_step_2(val) := final_val if {
    is_string(val)
    startswith(val, "{{AGO_DAY_")
    # 截取数字: "{{AGO_DAY_" 长度为 10
    num_str := trim(substring(val, 10, -1), "}}")
    offset := to_number(num_str)
    final_val := fmt_date(time.add_date(ns_now, 0, 0, 0 - offset))
} else := final_val if {
    is_string(val)
    startswith(val, "{{AGO_MONTH_")
    # "{{AGO_MONTH_" 长度为 12
    num_str := trim(substring(val, 12, -1), "}}")
    offset := to_number(num_str)
    final_val := fmt_date(time.add_date(ns_now, 0, 0 - offset, 0))
} else := val

# --- 主解析函数 (分层处理避免递归错误) ---

# 内部函数：只负责处理单值
_resolve_single_item(val) := result if {
    v1 := resolve_step_1(val)
    result := resolve_step_2(v1)
} else := val

# 公共接口：负责分发 (数组 vs 单值)
resolve_value(val) := result if {
    is_array(val)
    result := [res | some item in val; res := _resolve_single_item(item)]
} else := result if {
    result := _resolve_single_item(val)
}

# -----------------------------------------------------------------------------
# 4. 列访问逻辑 (Pipeline 模式) [严禁修改且最终保留]
# -----------------------------------------------------------------------------
base_columns_set := cols if {
    "*" in role_config.allowed_columns
    cols := all_db_columns
} else := cols if {
    role_config.allowed_columns
    not "*" in role_config.allowed_columns
    cols := {col | col := role_config.allowed_columns[_]}
} else := {}

blacklisted := {c | c := object.get(role_config, "excluded_columns", [])[_]}
base_valid_set := base_columns_set - blacklisted
requested_cols_raw := object.get(input.query_request, "columns", [])
requested_is_wildcard if { "*" in requested_cols_raw }

requested_set := cols if {
    requested_is_wildcard
    cols := base_valid_set
} else := cols if {
    not requested_is_wildcard
    cols := {c | c := requested_cols_raw[_]}
}

final_allowed_set := base_valid_set & requested_set
allowed_columns := sort([c | final_allowed_set[c]])

# =============================================================================
# 5. 行访问逻辑 (Strict AST 模式)
# =============================================================================

# [Step 5.1 - 需填充] 定义策略强制范围 (Policy Scope)
# 任务：返回 AST 对象列表的 Map: { "key": [{...}, {...}] }
# 逻辑注意：Scope 最终是 "全局约束 (Layer 1)" 与 "角色约束 (Layer 2)" 的交集
# 值注意：在对用户的属性内容进行限制时，**一定要参照User Sample**中的内容，**避免**所约束的内容在用户属性中**名称不匹配**
policy_scope := scope if {
    # [角色: 超级管理者 (super_admin)]
    # 语义: "可以查看所有警情数据"
    # 算法: Scope = [Phase 1 Baseline] + [Empty Modifier]
    role_config.row_filter_rule == "full_access"
    scope := {
        # 1. 在此填入 Phase 1 识别出的全局基准 (如 school_id/tenant_id)。
        #    注意: 如果 NL 没说"首先要隔离"，这里留空。
        #          如果 NL 说了"首先要隔离"，这里必须填入隔离键。
        # NL Policy 前两句未提及全局隔离，因此 Baseline = {}
    }
} else := scope if {
    # [角色: 普通角色 (common)]
    # 语义: "只能查看自己部门的警情数据"
    # 算法: Scope = [Phase 1 Baseline] + [Specific Modifier]
    role_config.row_filter_rule == "department_restricted"
    scope := {
        # 1. 填入 Phase 1 全局基准 (必须与上面一致)
        # NL Policy 前两句未提及全局隔离，因此 Baseline = {}
        
        # 2. 填入 Phase 2 角色修正
        "tb_case_info.jurisdiction_unit": [ {"op": "=", "val": user_attrs.department} ]
    }
} else := {
    "deny": true
}

# [Step 5.2] 提取请求并解析时间 Token [严禁修改且最终保留]
raw_conditions := object.get(input.query_request, "conditions", {})
requested_conditions := clean_conds if {
    clean_conds := {k: v_list |
        some k, raw_list in raw_conditions
        v_list := [resolved_item |
            some item in raw_list
            resolved_item := {
                "op": item.op,
                "val": resolve_value(item.val)
            }
        ]
    }
}

# [Step 5.3] 智能合规性检查 [严禁修改且最终保留]

to_list(x) := x if { is_array(x) } else := [] if { x == null } else := [x]

trim_percent(s) := trim(s, "%")

is_compliant(req, pol) if {
    req.op == pol.op
    req.val == pol.val
}

is_compliant(req, pol) if {
    pol.op == "="
    req.op == "IN"
    is_array(req.val)
    some item in req.val
    item == pol.val
}

is_compliant(req, pol) if {
    pol.op == "IN"
    req.op == "IN"
    # 集合求交集: 存在 x 同时属于 req 和 pol
    some x in req.val
    x in pol.val
}

is_compliant(req, pol) if {
    pol.op == "IN"
    req.op == "="
    req.val in pol.val
}

is_compliant(req, pol) if {
    pol.op == "="
    req.op == "LIKE"
    user_core := trim_percent(req.val)
    # 双向包含检查
    contains(pol.val, user_core)
}
is_compliant(req, pol) if {
    pol.op == "="
    req.op == "LIKE"
    user_core := trim_percent(req.val)
    contains(user_core, pol.val)
}

is_compliant(req, pol) if {
    pol.op == "="
    req.op == "BETWEEN"
    is_array(req.val); count(req.val) == 2
    pol.val >= req.val[0]
    pol.val <= req.val[1]
}

is_compliant(req, pol) if {
    pol.op == "BETWEEN"
    req.op == "BETWEEN"
    req.val[0] <= pol.val[1]
    req.val[1] >= pol.val[0]
}

is_compliant(req, pol) if {
    pol.op == "BETWEEN"
    req.op == "="
    req.val >= pol.val[0]
    req.val <= pol.val[1]
}

# [Step 5.4] 核心算法：求交集与清洗 (Intersection & Merge) [严禁修改且最终保留]
_merge_item(req_item, pol_item) := result if {
    # 1. 策略是强限制 (=) -> 始终覆盖，确保安全
    pol_item.op == "="
    result := pol_item
} else := result if {
    # 2. 双方都是 IN -> 计算交集
    pol_item.op == "IN"; req_item.op == "IN"
    intersection := [x | x := req_item.val[_]; x in pol_item.val]
    result := { "op": "IN", "val": intersection }
} else := result if {
    # 3. 策略是范围(BETWEEN)，用户是范围(BETWEEN) -> 计算区间重叠
    pol_item.op == "BETWEEN"; req_item.op == "BETWEEN"
    new_start := max([req_item.val[0], pol_item.val[0]])
    new_end := min([req_item.val[1], pol_item.val[1]])
    result := { "op": "BETWEEN", "val": [new_start, new_end] }
} else := req_item # 默认：策略较宽泛时，保留用户更精细的查询条件

_calculate_constraint(req_list, pol_list) := result if {
    # Case A: 仅策略有 -> 注入策略
    count(pol_list) > 0; count(req_list) == 0
    result := pol_list
} else := result if {
    # Case B: 仅用户有 -> 放行用户
    count(pol_list) == 0; count(req_list) > 0
    result := req_list
} else := result if {
    # Case C: 双方都有 -> 清洗求交集
    count(pol_list) > 0; count(req_list) > 0
    
    result := [ final_item | 
        some r in req_list
        some p in pol_list
        
        # 1. 必须合规
        is_compliant(r, p)
        
        # 2. 计算交集结果 (使用高级 Merge)
        final_item := _merge_item(r, p)
    ]
} else := []

# 主规则：生成清洗后的约束 Map
filtered_constraints[key] := final_list if {
    some key in object.keys(requested_conditions) | object.keys(policy_scope)
    req_list := to_list(object.get(requested_conditions, key, null))
    pol_list := to_list(object.get(policy_scope, key, null))
    final_list := _calculate_constraint(req_list, pol_list)
}

# [Step 5.5] 拒绝判定 (Denial Logic) [严禁修改且最终保留]
denial_reasons contains msg if {
    some key, _ in policy_scope
    
    cleaned := object.get(filtered_constraints, key, [])
    original := object.get(requested_conditions, key, [])
    
    # 触发条件: 用户请求了该字段，但清洗后结果为空 (说明完全不合规)
    count(original) > 0
    count(cleaned) == 0
    
    msg := sprintf("Access Denied: Requested values for '%s' are out of permitted scope.", [key])
}

row_constraints := res if {
    count(denial_reasons) == 0
    res := filtered_constraints
} else := res if {
    count(denial_reasons) > 0
    res := {
        "deny": true, 
        "reason": concat("; ", denial_reasons)
    }
} else := {"deny": true, "reason": "Internal Policy Error"}

# -----------------------------------------------------------------------------
# 6. 最终裁决 [严禁修改且最终保留]
# -----------------------------------------------------------------------------
allow if {
    count(role_config) > 0
    count(allowed_columns) > 0
    not row_constraints.deny
}

reason := sprintf("Access Granted for role: %s", [user_role]) if { allow }
else := "Access Denied: Role undefined." if { count(role_config) == 0 }
else := "Access Denied: No valid columns requested or allowed." if { not allow; count(allowed_columns) == 0 }
else := object.get(row_constraints, "reason", "Access Denied: Row constraints.") if { not allow; row_constraints.deny }
else := "Access Denied: Unknown reason."

result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}