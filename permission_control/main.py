from fastapi import FastAPI
from contextlib import asynccontextmanager

from data.policy_manager import PolicyManager
# (重要) 导入 PermissionController1.py 中的类
from data.permission_controller import PermissionController 

# (重要) 导入新的检查路由文件
# from permission_control.api import policy_routes
from opa_client import OpaClient
# (已移除) from services.llm_client import LLMClient
# (已移除) from api import management_routes, check_routes
# (已移除) from api import setup_routes 

# --- 全局单例 ---
services = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- 启动时 ---
    print("--- 服务启动，正在初始化服务... ---")
    
    # 1. 初始化基础客户端
    opa_instance = OpaClient(host="localhost", port=8181)
    
    class OpaClientWrapper(OpaClient):
        async def evaluate_policy(
            self,
            policy_id: str,
            input_data: dict,
            rego_policy: str,
            policy_data_path: str = "sqlopa.access.result",
        ) -> dict:
            # 1. 动态推送策略
            # print(f"rego策略:\n{rego_policy}\n")
            opa_instance.update_policy_from_string(
                new_policy = rego_policy,
                endpoint = policy_id
            )
            
            # print(input_data)
            
            # 2. 评估
            package_path, _, rule_name = policy_data_path.rpartition(".")
            package_path = package_path.replace(".", "/") if package_path else "sqlopa/access"

            result_full = opa_instance.query_rule(
                input_data=input_data,
                package_path=package_path,
                rule_name=rule_name or policy_data_path,
            )
            # 提取 'result' 部分
            return result_full.get("result", {})
    
    opa_client = OpaClientWrapper()
    
    # 2. 初始化核心服务
    policy_manager = PolicyManager(
        raw_data_path="data/policy_list"
    )
    
    permission_controller = PermissionController(
        policy_manager=policy_manager,
        opa_client=opa_client
    )
    
    # 存入字典以便路由使用
    services["policy_manager"] = policy_manager
    services["permission_controller"] = permission_controller
    
    print("--- 服务初始化完成 ---")
    
    yield
    
    # --- 关闭时 ---
    print("--- 服务正在关闭 ---")
    services.clear()

# 为了让路由能访问 services, 我们在路由文件中使用 Depends
def get_permission_controller():
    return services["permission_controller"]

def get_policy_manager():
    return services["policy_manager"]

# --- 创建 FastAPI 应用 ---
app = FastAPI(
    title="Permission Control Service",
    description="为AI智能体提供两阶段权限控制",
    version="1.0.0",
    lifespan=lifespan
)

# 导入路由文件
from api import policy_routes 
from api import check_routes

# --- 挂载 API 路由 ---
app.include_router(policy_routes.router, prefix="/api/v1", tags=["Policy Management"])
app.include_router(check_routes.router, prefix="/api/v1", tags=["Check"])

@app.get("/", tags=["Health"])
async def read_root():
    return {"status": "ok", "message": "Permission Control Service is running."}


#uvicorn main:app --port 8888 --reload