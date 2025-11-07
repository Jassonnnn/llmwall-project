"""
LLM Natural Language Query Parser Module
"""
import json
import re
import logging
from typing import Dict, List, Optional, Any
from litellm import completion
from .config_manager import config

class NLQueryParser:
    """Natural language query parser"""
    
    def __init__(self, model: Optional[str] = None):
        llm_config = config.get_llm_config()
        self.model = model or llm_config.get("model", "ollama/qwen2.5:latest")
        self.temperature = llm_config.get("temperature", 0.1)
        self.max_tokens = llm_config.get("max_tokens", 1000)
        self.timeout = llm_config.get("timeout", 30)
        self.logger = logging.getLogger(__name__)

    def parse_query(self, natural_query: str, user_id: str, conversation_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        解析自然语言查询，提取表、列、条件信息
        
        Args:
            natural_query: 自然语言查询
            user_id: 用户ID
            
        Returns:
            解析后的查询结构
        """
        
        # 构建提示词
        prompt = f"""
你是一个专业的SQL查询解析专家，擅长理解自然语言和对话上下文，并将其转换为结构化的JSON查询。

数据库表结构：
- employees表包含列：id, name, department, gender, birth_date, marital_status, hire_date, social_activity_preference

用户查询："{natural_query}"
用户ID：{user_id}
历史对话：{conversation_history}

请返回JSON格式的解析结果，包含以下字段：
- tables: 涉及的表名列表
- columns: 需要查询的列名列表  
- conditions: 查询条件（键值对格式，仅当查询明确指定条件时才添加）
- query_type: 查询类型（select/update/delete等）

解析规则：
解析规则：
1.  **上下文理解**：优先分析`conversation_history`。如果当前查询是基于上一轮的结果进行筛选（例如使用“他们中”、“其中”、“并且”等词语），你必须将上一轮`parsed_json`中的`conditions`继承下来，并将条件与查询的结果与当前查询的新条件合并。
2.  **重置上下文**：如果当前查询是一个全新的、与历史无关的请求（例如“换个话题”、“重新查”或一个完整的新问题），你必须忽略`conversation_history`，仅根据当前`natural_query`生成查询。
3.  **识别查询列**：根据用户的提问，准确识别需要查询的`columns`。如果用户没有指定，通常默认查询核心信息（如`name`）。
4.  **个人化查询**：当用户查询包含“我的”、“我自己的”等词语时，必须在`conditions`中添加基于`user_id`的过滤条件。

示例1 - 查询自己信息：
用户查询："帮我查一下我的工资"
输出：{{"tables": ["employees"], "columns": ["salary"], "conditions": {{"id": "{user_id}"}}, "query_type": "select"}}

示例2 - 查询所有员工：
用户查询："查询所有员工的姓名和工资"
输出：{{"tables": ["employees"], "columns": ["name", "salary"], "conditions": {{}}, "query_type": "select"}}

示例3 - 多段对话查询：
历史记录："查询所有工龄大于5年的员工","好的，符合条件的员工有emp001, emp002, emp003","帮我查一下他们的工资"
输出：{{"tables": ["employees"], "columns": ["salary"], "conditions": {{"id": "emp001, emp002, emp003"}}, "query_type": "select"}}

只返回JSON，不要其他解释：
"""
        
        try:
            print(prompt)
            response = completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=self.timeout
            )
            
            # 提取JSON内容
            content = response.choices[0].message.content.strip()
            
            # 去除think部分输出
            content = self._remove_think_sections(content)
            
            # 尝试提取JSON
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                parsed = json.loads(json_str)
                
                # 验证必要字段
                required_fields = ['tables', 'columns', 'query_type']
                for field in required_fields:
                    if field not in parsed:
                        parsed[field] = self._get_default_value(field)
                
                # 如果没有条件，添加默认条件（查询自己的信息）
                if 'conditions' not in parsed or not parsed['conditions']:
                    parsed['conditions'] = {}
                
                return parsed
            else:
                raise ValueError("无法从LLM响应中提取JSON")
                
        except Exception as e:
            print(f"LLM解析失败: {e}")
            # 返回默认解析结果
            return self._get_fallback_parse(natural_query, user_id)
    
    def _get_default_value(self, field: str) -> Any:
        """获取字段默认值"""
        defaults = {
            'tables': ['employees'],
            'columns': ['id', 'name'],
            'query_type': 'select',
            'conditions': {}
        }
        return defaults.get(field, None)
    
    def _get_fallback_parse(self, query: str, user_id: str) -> Dict[str, Any]:
        """备用解析逻辑"""
        # 简单的关键词匹配
        columns = []
        if any(word in query.lower() for word in ['工资', 'salary', '薪水']):
            columns.append('salary')
        if any(word in query.lower() for word in ['姓名', 'name', '名字']):
            columns.append('name')
        if any(word in query.lower() for word in ['职位', 'position']):
            columns.append('position')
        if any(word in query.lower() for word in ['邮箱', 'email']):
            columns.append('contact_email')
        
        if not columns:
            columns = ['id', 'name']  # 默认查询
            
        return {
            'tables': ['employees'],
            'columns': columns,
            'conditions': {},
            'query_type': 'select'
        }

    def rewrite_query(self, original_query: str, allowed_columns: List[str], 
                     row_constraints: Dict[str, Any]) -> str:
        """
        根据权限约束重写自然语言查询
        
        Args:
            original_query: 原始查询
            allowed_columns: 允许的列
            row_constraints: 行约束
            
        Returns:
            重写后的查询
        """
        
        prompt = f"""
你是一个查询重写专家。用户的原始查询由于权限限制需要修改。

原始查询："{original_query}"
允许查询的列：{allowed_columns}
行级约束：{row_constraints}

请重写查询，使其符合权限约束。重写规则：
1. 只保留允许的列
2. 添加必要的行级过滤条件
3. 保持自然语言的表达方式

只返回重写后的自然语言查询，不要其他解释：
"""
        
        try:
            response = completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=min(self.max_tokens, 200)  # Use smaller token limit for rewrite
            )
            
            rewritten = response.choices[0].message.content.strip()
            
            # 去除think部分输出
            rewritten = self._remove_think_sections(rewritten)
            
            # 清理可能的引号
            rewritten = rewritten.strip('"\'')
            
            # 如果清理后内容为空，使用备用逻辑
            if not rewritten:
                rewritten = self._get_fallback_rewrite(original_query, allowed_columns, row_constraints)
            
            return rewritten
            
        except Exception as e:
            print(f"查询重写失败: {e}")
            # 简单的备用重写逻辑
            if row_constraints.get('id'):
                return f"查询我的{', '.join(allowed_columns)}信息"
            else:
                return f"查询所有员工的{', '.join(allowed_columns)}信息"
    
    def _remove_think_sections(self, content: str) -> str:
        """
        去除LLM输出中的think部分
        
        Args:
            content: 原始LLM输出内容
            
        Returns:
            清理后的内容
        """
        
        # 去除<think>...</think>标签及其内容（完整标签）
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # 去除<thinking>...</thinking>标签及其内容（完整标签）
        content = re.sub(r'<thinking>.*?</thinking>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # 去除不完整的<think>开始标签到文本结尾的所有内容
        content = re.sub(r'<think>.*$', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # 去除不完整的<thinking>开始标签到文本结尾的所有内容
        content = re.sub(r'<thinking>.*$', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # 去除思考过程相关的文本模式
        content = re.sub(r'我来.*?分析.*?[：:]', '', content, flags=re.DOTALL)
        content = re.sub(r'让我.*?思考.*?[：:]', '', content, flags=re.DOTALL)
        content = re.sub(r'首先.*?分析.*?[：:]', '', content, flags=re.DOTALL)
        content = re.sub(r'首先，.*?$', '', content, flags=re.DOTALL)
        
        # 去除"原始查询是"等分析性文本
        content = re.sub(r'原始查询是.*?$', '', content, flags=re.DOTALL)
        content = re.sub(r'允许.*?列.*?$', '', content, flags=re.DOTALL)
        content = re.sub(r'行级约束.*?$', '', content, flags=re.DOTALL)
        content = re.sub(r'重写规则.*?$', '', content, flags=re.DOTALL)
        
        # 去除多余的换行和空格
        content = re.sub(r'\n\s*\n', '\n', content)
        content = content.strip()
        
        # 如果清理后内容为空或只包含符号，返回备用内容
        if not content or len(content.strip()) < 5:
            return ""
        
        return content
    
    def _get_fallback_rewrite(self, original_query: str, allowed_columns: List[str], 
                            row_constraints: Dict[str, Any]) -> str:
        """
        备用查询重写逻辑
        
        Args:
            original_query: 原始查询
            allowed_columns: 允许的列
            row_constraints: 行约束
            
        Returns:
            重写后的查询
        """
        
        # 构建列名的中文描述
        column_names = {
            'id': 'ID',
            'name': '姓名', 
            'position': '职位',
            'salary': '工资',
            'contact_email': '邮箱',
            'manager_id': '经理ID'
        }
        
        # 转换允许的列为中文描述
        allowed_desc = [column_names.get(col, col) for col in allowed_columns]
        
        # 处理行约束
        if row_constraints.get('id'):
            # 有具体的ID约束
            allowed_ids = row_constraints['id']
            if len(allowed_ids) == 1:
                return f"查询我的{', '.join(allowed_desc)}信息"
            else:
                return f"查询指定员工的{', '.join(allowed_desc)}信息"
        else:
            # 无行约束，可以查询所有
            return f"查询所有员工的{', '.join(allowed_desc)}信息"

if __name__ == "__main__":
    # 示例用法
    parser = NLQueryParser()
    query = "帮我查询一下部门女性的工号"
    user_id = "12345"
    conversation_history = [{"user":"帮我查询一下部门女性的工号"},{"assistant":"好的，部门中女性的工号分别是emp001,emp003,emp007"},{"user":"帮我查询一下这些人的工资"}]  # 假设没有历史对话
    parsed_query = parser.parse_query(query, user_id, conversation_history)
    print(json.dumps(parsed_query, indent=2, ensure_ascii=False))
    
    # rewritten_query = parser.rewrite_query(query, ['salary'], {'id': [user_id]})
    # print(f"重写后的查询: {rewritten_query}")