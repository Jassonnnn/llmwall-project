"""
SQL Access Control Main Program
Implements complete natural language query -> permission check -> query rewrite workflow
"""
import json
import logging
from typing import Dict, Any, Tuple
# 导入 os 和 file 相关的模块
import os 
import sys 
# 导入配置和parser、client
from .llm_parser import NLQueryParser 
from .opa_client import OPAClient
from .config_manager import config


REGO_POLICY_PATH = "opa/policies/sql_access_control.rego" 
POLICY_ID = "sql_access_control" 


class SQLAccessController:
    """SQL Access Controller"""
    
    def __init__(self, llm_model: str = None, opa_url: str = None):
        self.llm_parser = NLQueryParser(model=llm_model)
        self.opa_client = OPAClient(opa_url=opa_url)
        self.logger = logging.getLogger(__name__)
    
    def process_natural_query(self, natural_query: str, user_id: str, user_role: str) -> Dict[str, Any]:
        """
        处理自然语言查询的完整流程
        
        Args:
            natural_query: 自然语言查询
            user_id: 用户ID
            user_role: 用户角色
        
        Returns:
            处理结果
        """
        
        print(f"\n=== 处理查询 ===")
        print(f"用户: {user_id} ({user_role})")
        print(f"原始查询: {natural_query}")
        
        # 步骤1: LLM解析自然语言查询
        print(f"\n--- 步骤1: LLM解析查询 ---")
        parsed_query = self.llm_parser.parse_query(natural_query, user_id, conversation_history=[])
        print(f"解析结果: {json.dumps(parsed_query, ensure_ascii=False, indent=2)}")
        
        # 步骤2: OPA权限检查
        print(f"\n--- 步骤2: OPA权限检查 ---")
        user_info = {"id": user_id, "role": user_role}
        permission_result = self.opa_client.check_permissions(user_info, parsed_query)
        print(f"权限检查结果: {json.dumps(permission_result, ensure_ascii=False, indent=2)}")
        
        # 步骤3: 根据权限结果处理
        print(f"\n--- 步骤3: 处理结果 ---")
        final_result = self._handle_permission_result(
            natural_query, parsed_query, permission_result
        )
        
        return {
            "original_query": natural_query,
            "parsed_query": parsed_query,
            "permission_result": permission_result,
            "final_result": final_result
        }
    
    def _handle_permission_result(self, original_query: str, parsed_query: Dict[str, Any], 
                                 permission_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据权限检查结果处理查询
        
        Returns:
            最终处理结果
        """
        
        if not permission_result.get("allowed", False):
            # 完全无权限
            return {
                "status": "denied",
                "message": "无权限",
                "reason": permission_result.get("reason", "权限不足"),
                "final_query": None
            }
        
        # 检查是否需要改写查询
        allowed_columns = permission_result.get("allowed_columns", [])
        requested_columns = parsed_query.get("columns", [])
        row_constraints = permission_result.get("row_constraints", {})
        
        # 检查列权限
        filtered_columns = [col for col in requested_columns if col in allowed_columns]
        
        if not filtered_columns:
            return {
                "status": "denied",
                "message": "无权限访问请求的列",
                "reason": "请求的列不在允许范围内",
                "final_query": None
            }
        
        # 判断是否需要改写
        needs_rewrite = (
            len(filtered_columns) != len(requested_columns) or  # 列被过滤
            self._needs_row_constraint_rewrite(parsed_query, row_constraints)  # 需要行级约束改写
        )
        
        if not needs_rewrite:
            # 完全满足权限，直接返回原查询
            return {
                "status": "allowed",
                "message": "权限验证通过",
                "final_query": original_query,
                "rewritten": False
            }
        else:
            # 部分权限，需要改写查询
            print(f"需要改写查询 - 允许的列: {filtered_columns}, 行约束: {row_constraints}")
            rewritten_query = self.llm_parser.rewrite_query(
                original_query, filtered_columns, row_constraints
            )
            
            return {
                "status": "partial",
                "message": "部分权限，查询已改写",
                "final_query": rewritten_query,
                "rewritten": True,
                "original_columns": requested_columns,
                "allowed_columns": filtered_columns,
                "row_constraints": row_constraints
            }
    
    def _needs_row_constraint_rewrite(self, parsed_query: Dict[str, Any], row_constraints: Dict[str, Any]) -> bool:
        """
        检查是否需要因行约束而改写查询
        
        Args:
            parsed_query: 解析后的查询
            row_constraints: 行约束
            
        Returns:
            是否需要改写
        """
        
        # 如果没有行约束或者是deny类型，不需要改写（deny会在OPA层面拒绝）
        if not row_constraints or row_constraints.get("deny"):
            return False
        
        # 如果有ID约束
        if "id" in row_constraints:
            allowed_ids = row_constraints["id"]
            query_conditions = parsed_query.get("conditions", {})
            
            # 如果查询没有条件（查询所有员工），但有行级约束，需要改写
            if not query_conditions:
                return True
            
            # 检查查询条件中是否已经指定了符合约束的ID
            if "id" in query_conditions:
                # 注意：这里的逻辑简化，实际应处理多个ID或更复杂的查询
                query_id = query_conditions["id"]
                
                # 检查查询的ID是否在允许的ID列表中
                # 需要考虑 query_id 可能是字符串或列表
                if isinstance(query_id, str):
                    if query_id in allowed_ids:
                        return False
                
                # 简化逻辑：只要查询条件与允许列表不完全匹配，就视为需要改写
                return True
            
            # 如果有其他条件但没有ID条件，需要改写添加ID约束
            return True
        
        # 其他类型的行约束，暂时认为需要改写
        return True


def main():
    """主函数，演示各种场景"""
    
    # 初始化控制器
    controller = SQLAccessController()
    
    # 检查OPA服务状态
    if not controller.opa_client.health_check():
        print("❌ OPA服务未启动，正在尝试动态推送启动...")
        #  策略推送逻辑 
        if os.path.exists(REGO_POLICY_PATH):
            with open(REGO_POLICY_PATH, 'r', encoding='utf-8') as f:
                rego_content = f.read()
            
            # 尝试推送策略 (如果OPAClient.health_check()失败，这里会尝试连接并推送)
            if not controller.opa_client.push_policy(POLICY_ID, rego_content):
                 print("❌ 动态推送策略失败，服务无法启动。")
                 return
            
            # 策略推送成功，再次检查健康状态
            if not controller.opa_client.health_check():
                print("❌ 策略推送后 OPA 仍未健康。")
                return
        else:
             print(f"❌ 策略文件未找到: {REGO_POLICY_PATH}。无法进行动态推送。")
             return

        print("✅ OPA服务已恢复正常 (策略已推送)")
    else:
         print("✅ OPA服务正常")


    # 测试用例
    test_cases = [
        {
            "name": "普通员工查询自己工资",
            "query": "帮我查一下id为emp003的工资",
            "user_id": "emp003",
            "user_role": "employee"
        },
        {
            "name": "普通员工查询自己工资",
            "query": "帮我查一下我的工资",
            "user_id": "emp003",
            "user_role": "employee"
        },
        {
            "name": "普通员工查询所有员工信息",
            "query": "查询所有员工的姓名和工资",
            "user_id": "emp003", 
            "user_role": "employee"
        },
        {
            "name": "经理查询下属信息",
            "query": "查询我管理的员工的姓名和职位",
            "user_id": "emp002",
            "user_role": "manager"
        },
        {
            "name": "HR管理员查询所有员工",
            "query": "查询所有员工的完整信息",
            "user_id": "emp001",
            "user_role": "hr_admin"
        },
        {
            "name": "审计员查询员工信息",
            "query": "查询所有员工的姓名、职位和工资",
            "user_id": "emp005",
            "user_role": "auditor"
        },
        {
            "name": "实习生尝试查询",
            "query": "查询员工信息",
            "user_id": "emp006",
            "user_role": "intern"
        }
    ]
    
    # 执行测试用例
    print("\n" + "="*80)
    print("SQL访问控制演示")
    print("="*80)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*20} 测试用例 {i}: {test_case['name']} {'='*20}")
        
        result = controller.process_natural_query(
            test_case["query"],
            test_case["user_id"], 
            test_case["user_role"]
        )
        
        final_result = result["final_result"]
        print(f"\n🎯 最终结果:")
        print(f"   状态: {final_result['status']}")
        print(f"   消息: {final_result['message']}")
        
        if final_result.get("final_query"):
            print(f"   最终查询: {final_result['final_query']}")
            if final_result.get("rewritten"):
                print(f"   🔄 查询已改写")
                print(f"   原始列: {final_result.get('original_columns', [])}")
                print(f"   允许列: {final_result.get('allowed_columns', [])}")
        else:
            print(f"   ❌ 查询被拒绝: {final_result.get('reason', '')}")
        
        print("-" * 80)


if __name__ == "__main__":
    main()