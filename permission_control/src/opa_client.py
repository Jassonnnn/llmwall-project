"""
OPA Client Module
"""
import requests
import json
import logging
from typing import Dict, Any
from .config_manager import config 


class OPAClient:
    """OPAClient"""
    
    def __init__(self, opa_url: str = None):
        
        self.opa_url = opa_url or config.get_opa_url() 
        self.timeout = config.get_opa_timeout()
        self.logger = logging.getLogger(__name__)
        
    def check_permissions(self, user_info: Dict[str, Any], query_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        检查用户权限
        
        Args:
            user_info: 用户信息 {'id': 'emp001', 'role': 'employee'}
            query_request: 查询请求 {'tables': [...], 'columns': [...], 'conditions': {...}}
            
        Returns:
            权限检查结果
        """
        
        # 构建OPA输入
        opa_input = {
            "user": user_info,
            "query_request": query_request
        }
        
        try:
            # 调用OPA API
            response = requests.post(
                f"{self.opa_url}/v1/data/sqlopa/access/result",
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("result", {})
            else:
                print(f"OPA请求失败: {response.status_code}, {response.text}")
                return self._get_default_deny_result()
                
        except Exception as e:
            print(f"OPA连接失败: {e}")
            return self._get_default_deny_result()
    
    def _get_default_deny_result(self) -> Dict[str, Any]:
        """获取默认拒绝结果"""
        return {
            "allowed": False,
            "table_access": {},
            "allowed_columns": [],
            "row_constraints": {},
            "reason": "OPA服务不可用或权限检查失败"
        }
    
    def health_check(self) -> bool:
        """健康检查"""
        try:
            # 使用 OPA 的 /health API 进行检查
            response = requests.get(f"{self.opa_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False

    def push_policy(self, policy_id: str, rego_content: str) -> bool:
        """
        通过 Policy API (PUT /v1/policies/{policy_id}) 动态推送 Rego 策略
        
        Args:
            policy_id: 策略ID，例如 "sql_access_control"
            rego_content: Rego 策略文件的全部文本内容
            
        Returns:
            推送是否成功
        """
        try:
            response = requests.put(
                f"{self.opa_url}/v1/policies/{policy_id}",
                data=rego_content,
                headers={"Content-Type": "text/plain"},
                timeout=self.timeout
            )
            
            # OPA API 成功返回 200 (OK) 或 201 (Created/Updated)
            if response.status_code in (200, 201):
                
                print(f"成功推送 OPA 策略: {policy_id}") 
                return True
            else:
                print(f"推送 OPA 策略失败 ({policy_id}): {response.status_code}, {response.text}")
                return False
                
        except Exception as e:
            print(f"推送 OPA 策略连接失败: {e}")
            return False