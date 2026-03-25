import os
from pathlib import Path
from typing import Any, Dict


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return default
    return max(minimum, value)

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

# --- 服务安全配置 ---
JB_DEMO_SERVICE_TOKEN = os.getenv("JB_DEMO_SERVICE_TOKEN", "").strip()
JB_DEMO_REQUIRE_AUTH = _env_bool("JB_DEMO_REQUIRE_AUTH", True)
JB_DEMO_ALLOW_LOCAL_BYPASS = _env_bool("JB_DEMO_ALLOW_LOCAL_BYPASS", True)
JB_DEMO_MAX_CONCURRENT_BATCH_TASKS = _env_int("JB_DEMO_MAX_CONCURRENT_BATCH_TASKS", 1, minimum=1)

# --- 数据集配置 ---
DATASETS_PATH = Path(__file__).parent.parent / "datasets"
DATASET_INDEX_DIR = DATASETS_PATH / "index"
ATTACK_CATEGORY_INDEX_PREFERRED_VERSION = "v2"
ATTACK_CATEGORY_INDEX_FALLBACK_VERSION = "v1"
ATTACK_CATEGORY_INDEX_VERSION = ATTACK_CATEGORY_INDEX_PREFERRED_VERSION
ATTACK_CATEGORY_INDEX_FILE = DATASET_INDEX_DIR / f"attack_category_index_{ATTACK_CATEGORY_INDEX_PREFERRED_VERSION}.jsonl"
ATTACK_CATEGORY_INDEX_FALLBACK_FILE = DATASET_INDEX_DIR / f"attack_category_index_{ATTACK_CATEGORY_INDEX_FALLBACK_VERSION}.jsonl"
ATTACK_CATEGORY_QUALITY_REPORT_FILE = DATASET_INDEX_DIR / f"attack_category_quality_report_{ATTACK_CATEGORY_INDEX_PREFERRED_VERSION}.json"
# M2: 默认强制使用 v2；仅在应急场景通过环境变量临时允许回退到 v1
ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK = _env_bool("ATTACK_CATEGORY_INDEX_ALLOW_FALLBACK", False)

ATTACK_CATEGORIES = [
    {
        "id": "mixed_all",
        "name": "混合（全部）",
        "description": "不筛选攻击类型，使用该数据集全部样本",
    },
    {
        "id": "direct_request",
        "name": "直接请求",
        "description": "无明显越狱技巧，直接提出有害请求",
    },
    {
        "id": "roleplay_persona",
        "name": "角色扮演",
        "description": "通过角色设定、DAN、人设切换等绕过约束",
    },
    {
        "id": "obfuscation_encoding",
        "name": "编码混淆",
        "description": "Base64/ROT13/拆分字符/同义替换等混淆方式",
    },
    {
        "id": "contextual_injection",
        "name": "上下文注入",
        "description": "多轮上下文、伪系统指令、样例注入等策略",
    },
    {
        "id": "multilingual_transformation",
        "name": "多语言绕过",
        "description": "通过翻译、夹杂外语等方式规避安全规则",
    },
    {
        "id": "compositional_hybrid",
        "name": "组合攻击",
        "description": "多种越狱技巧叠加形成复合攻击模式",
    },
]

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
