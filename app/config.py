from pathlib import Path
from typing import Dict, Any

# --- 全局配置 (默认值为空，等待前端传入) ---
GLOBAL_SETTINGS = {
    "api": {
        "name": "Remote API",
        "model": "openrouter/deepseek/deepseek-chat",
        "api_base": "https://openrouter.ai/api/v1",
        "api_key": "",
        "temperature": 0.7
    },
    "local": {
        "name": "Local Model",
        "model": "qwen2.5:latest",
        "api_base": "http://localhost:11434/v1",
        "api_key": "ollama",
        "temperature": 0.0
    }
}

# 批量评估任务存储
BATCH_TASKS: Dict[str, Dict[str, Any]] = {}

# --- 数据集配置 ---
DATASETS_PATH = Path(__file__).parent.parent / "datasets"

AVAILABLE_DATASETS = {
    "harmbench_text_all": {
        "name": "HarmBench (完整版)",
        "description": "HarmBench完整文本行为数据集",
        "path": "HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv",
        "prompt_column": "Behavior",
        "count": None
    },
    "harmbench_text_test": {
        "name": "HarmBench (测试集)",
        "description": "HarmBench测试集分割",
        "path": "HarmBench/data/behavior_datasets/harmbench_behaviors_text_test.csv",
        "prompt_column": "Behavior",
        "count": None
    },
    "advbench_harmful": {
        "name": "AdvBench (有害行为)",
        "description": "520个有害行为提示词",
        "path": "llm-attacks/data/advbench/harmful_behaviors.csv",
        "prompt_column": "goal",
        "count": None
    },
    "toxicchat_toxic": {
        "name": "ToxicChat (有毒内容)",
        "description": "真实用户有毒对话数据",
        "path": "toxicchat/toxicchat_toxic.csv",
        "prompt_column": "user_input",
        "count": None
    },
    "saferlhf_unsafe": {
        "name": "SafeRLHF (不安全)",
        "description": "PKU安全RLHF不安全提示词",
        "path": "saferlhf/saferlhf_unsafe.csv",
        "prompt_column": "prompt",
        "count": None
    }
}