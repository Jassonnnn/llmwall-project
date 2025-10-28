# -*- coding: utf-8 -*-
from guardrails import OnFailAction
from hub import (
    DetectJailbreak,
    CompetitorCheck,
    RegexMatch,
    LlamaGuard,
    BanList,
    PromptGuard,
    PIIGuard,
    # 在这里导入所有需要使用的验证器
)

# 1. 创建一个从字符串名称到 Validator 类的“注册表”或“映射”
# 这是整个动态配置机制的核心。
VALIDATOR_MAP = {
    # 输入检查器
    "detect_jailbreak": DetectJailbreak,
    "competitor_check": CompetitorCheck,
    "regex_match": RegexMatch,
    "llama_guard": LlamaGuard,
    "ban_list": BanList,
    "prompt_guard": PromptGuard,
    "pii_guard": PIIGuard,
    # 输出检查器
    
    # 未来可以在这里轻松添加更多验证器
    # "pii_detection": PIIDetection,
}

# 2. 创建一个从字符串到 OnFailAction 的映射，以便在 JSON 中灵活配置失败处理方式
ON_FAIL_MAP = {
    "exception": OnFailAction.EXCEPTION,
    "fix": OnFailAction.FIX,
    "noop": OnFailAction.NOOP,
}
