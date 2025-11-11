package e2e_test_tenant.access

import rego.v1

default allow := false
default allowed_columns := []
default row_constraints := {}
default reason := "Access denied by default. No rules matched."

roles := {
    "manager": {
        "description": "Manager",
        "allowed_columns": ["name", "department", "salary"],
        "row_filter": "all"
    },
    "employee": {
        "description": "Regular Employee",
        "allowed_columns": ["name", "department"],
        "row_filter": "self_only"
    }
}

user_role := input.user.user_role
user_id := input.user.user_id
role_config := roles[user_role]

allowed_columns := role_config.allowed_columns if {
    role_config
    input.query_request.columns[_] == "*"
}

allowed_columns := intersection if {
    role_config
    not "*" in input.query_request.columns
    
    intersection := [col |
        col := input.query_request.columns[_]
        col in role_config.allowed_columns
    ]
}

row_constraints := {} if {
    role_config.row_filter == "all"
}

row_constraints := {"id": user_id} if {
    role_config.row_filter == "self_only"
}

row_constraints := {"deny": true} if {
    role_config
    not role_config.row_filter in {"all", "self_only"}
}

allow if {
    role_config
    
    count(allowed_columns) > 0
    
    not row_constraints.deny
}

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

reason := "Access Denied: This role has no row-level access permissions." if {
    not allow
    row_constraints.deny
}

result := {
    "allowed": allow,
    "allowed_columns": allowed_columns,
    "row_constraints": row_constraints,
    "reason": reason
}
