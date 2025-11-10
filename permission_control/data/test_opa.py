from opa_client import OpaClient

# policy_string = """
# package sqlopa.access

# import rego.v1

# # ======================================================================
# # 1. 默认值 (默认拒绝)
# # ======================================================================

# # 默认情况下，不允许任何操作
# default allow := false
# # 默认情况下，没有允许的列
# default allowed_columns := []
# # 默认情况下，没有行约束（注意：这不等于 "deny"）
# default row_constraints := {}
# # 默认的拒绝原因
# default reason := "Access denied by default. No rules matched."

# # ======================================================================
# # 2. 权限配置中心 (数据驱动)
# # 这是从您的 "灵感" 代码中学来的核心思想
# # ======================================================================

# roles := {
#     "manager": {
#         "description": "Manager",
#         "allowed_columns": ["name", "department", "salary"],
#         "row_filter": "all" # 对应您的需求：查询所有员工
#     },
#     "employee": {
#         "description": "Regular Employee",
#         "allowed_columns": ["name", "department"],
#         "row_filter": "self_only" # 对应您的需求：只能查询自己
#     }
#     # 您可以在这里轻松添加 "hr_admin", "auditor" 等，而无需更改下面的逻辑
# }

# # ======================================================================
# # 3. 辅助变量
# # ======================================================================

# # 获取当前用户的角色、ID 和对应的权限配置
# user_role := input.user.user_role
# user_id := input.user.user_id
# role_config := roles[user_role]


# # ======================================================================
# # 4. 模块化规则 (独立计算)
# # ======================================================================

# # --- 规则 A: 计算允许的列 (allowed_columns) ---

# # 规则 A.1: 如果用户查询 "SELECT *"
# allowed_columns := role_config.allowed_columns if {
#     role_config # 确保角色配置存在
#     input.query_request.columns[_] == "*" # 检查请求的列中是否包含通配符
# }

# # 规则 A.2: 如果用户查询了具体的列 (例如 "SELECT name")
# allowed_columns := intersection if {
#     role_config # 确保角色配置存在
#     not "*" in input.query_request.columns # 确保请求中没有 "*"
    
#     # 计算 "用户请求的列" 与 "角色允许的列" 之间的交集
#     intersection := [col |
#         col := input.query_request.columns[_]
#         col in role_config.allowed_columns
#     ]
# }


# # --- 规则 B: 计算行约束 (row_constraints) ---

# # 规则 B.1: 处理 "all" 过滤器 (例如 Manager)
# row_constraints := {} if {
#     role_config.row_filter == "all"
# }

# # 规则 B.2: 处理 "self_only" 过滤器 (例如 Employee)
# row_constraints := {"id": user_id} if {
#     role_config.row_filter == "self_only"
# }

# # 规则 B.3: (可选) 处理未定义的过滤器类型，作为安全保障
# row_constraints := {"deny": true} if {
#     role_config
#     not role_config.row_filter in {"all", "self_only"}
# }


# # --- 规则 C: 最终裁决 (allow) ---

# allow if {
#     # 1. 角色必须在我们的配置中心里有定义
#     role_config
    
#     # 2. 经过列过滤后，至少有一列是用户可以查看的
#     count(allowed_columns) > 0
    
#     # 3. 行级安全策略没有明确返回 "deny"
#     not row_constraints.deny
# }


# # --- 规则 D: 生成可读的原因 (reason) ---

# reason := sprintf("Access Granted for %s", [role_config.description]) if {
#     allow
# }

# reason := "Access Denied: This role is not defined in the policy." if {
#     not allow
#     not role_config
# }

# reason := "Access Denied: The query does not request any columns this role is allowed to see." if {
#     not allow
#     role_config
#     count(allowed_columns) == 0
# }

# reason := "Access Denied: This role has no row-level access permissions." if {
#     not allow
#     row_constraints.deny
# }

# # ======================================================================
# # 5. 最终输出 (组装)
# # ======================================================================

# # result 规则只是一个简单的 "组装工"，它收集所有独立计算的结果。
# result := {
#     "allowed": allow,
#     "allowed_columns": allowed_columns,
#     "row_constraints": row_constraints,
#     "reason": reason
# }
# """

client = OpaClient(host="localhost", port=8181)

# print(client.update_policy_from_string(new_policy=policy_string, endpoint="sample"))
client.delete_policy(policy_name="test_e2e_test_tenant")
print(client.get_policies_info())

# 假设 opa_client 是您的客户端实例
# from your_app import opa_client 

# opa_client = OpaClient(host="localhost", port=8181)

# print("正在尝试清理 OPA 中的所有策略...")

# try:
#     # 1. 获取所有策略的列表
#     # (方法名可能是 get_policies, list_policies, 或 get_policies_list)
#     policies = opa_client.get_policies_list() 
    
#     print(policies)
    
#     if not policies:
#         print("OPA 中没有需要清理的策略。")

#     print(f"找到了 {len(policies)} 个策略，正在删除...")

#     # 2. 循环遍历并删除每一个策略
#     for policy in policies:
#         policy_id = policy
#         if not policy_id:
#             continue
            
#         try:
#             # 3. 调用删除接口
#             # (方法名可能是 delete_policy)
#             # 使用您上传时用的 'endpoint' ID
#             opa_client.delete_policy(endpoint=policy_id) 
#             print(f"  - 已删除策略: {policy_id}")
            
#         except Exception as e_del:
#             print(f"  - 删除策略 {policy_id} 失败: {e_del}")

#     print("清理完成。")

# except AttributeError as e:
#     print(f"错误: 您的 'opa_client' 实例上可能没有 '{e.name}' 方法。")
#     print("请检查您 opa_client 库的文档，找到 'list policies' 和 'delete policy' 的正确方法名。")
# except Exception as e:
#     print(f"连接 OPA 或列出策略失败: {e}")

# # 在清理完成后，您应该重新启动您的 Python 应用程序
# # 以确保它在干净的 OPA 上重新加载所有策略
# print("\n请重启您的 Python 应用程序，以确保缓存被清除并重新加载策略。")