from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


TargetSingle = Literal["api", "local"]
TargetBatch = Literal["api", "local", "all"]
EvaluatorSingle = Literal["keyword", "llm_judge"]
EvaluatorBatch = Literal["keyword", "llm_judge", "all"]
AttackCategory = Literal[
    "mixed_all",
    "direct_request",
    "roleplay_persona",
    "obfuscation_encoding",
    "contextual_injection",
    "multilingual_transformation",
    "compositional_hybrid",
]
AttackMethod = Literal[
    "basic_jailbreak",
    "encoding",
    "translation",
    "roleplay",
    "hypothetical",
    "PAIR",
    "TAP",
    "AutoDAN",
    "GPTFuzz",
    "ReNeLLM",
    "ICA",
    "JailBroken",
    "Cipher",
    "DeepInception",
    "MultiLingual",
    "CodeChameleon",
    "GCG",
]


class AttackRequest(BaseModel):
    prompt: str


class ConfigUpdateRequest(BaseModel):
    target: TargetSingle
    name: Optional[str] = None
    model: Optional[str] = None
    api_base: Optional[str] = None
    api_key: Optional[str] = None
    clear_api_key: bool = False


class AttackResponse(BaseModel):
    target_type: TargetSingle
    eval_type: EvaluatorSingle
    response_content: str
    is_success: bool
    latency: float
    reasoning_trace: str
    model_name: str
    status: Literal["ok", "error"] = "ok"
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class BatchEvalRequest(BaseModel):
    dataset_id: str
    target: TargetBatch
    evaluator: EvaluatorBatch
    attack_category: AttackCategory = "mixed_all"
    sample_count: Optional[int] = Field(default=None, ge=1)  # None表示全部


class EvaluationCreateRequest(BaseModel):
    dataset_id: str
    target: TargetBatch = "api"
    evaluator: EvaluatorBatch = "keyword"
    attack_category: AttackCategory = "mixed_all"
    sample_count: Optional[int] = Field(default=None, ge=1)
    attack_methods: List[AttackMethod] = Field(default_factory=list)
    generated_prompt_count_per_seed: int = Field(default=1, ge=1, le=10)
    include_guardrail: bool = False
    guardrail_target: Optional[TargetSingle] = None
    guardrail_evaluator: Optional[EvaluatorSingle] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# 攻击生成相关模型
class AttackGenRequest(BaseModel):
    seed_prompt: str
    method: AttackMethod
    count: int = Field(default=5, ge=1, le=50)
    target: Optional[TargetSingle] = "api"
    evaluator: Optional[EvaluatorSingle] = "keyword"


class BatchAttackGenRequest(BaseModel):
    seed_prompts: List[str] = Field(min_length=1)
    method: AttackMethod
    count_per_prompt: int = Field(default=3, ge=1, le=50)
    target: Optional[TargetSingle] = "api"


class GeneratedPrompt(BaseModel):
    id: int
    prompt: str
    technique: str


class AttackGenResponse(BaseModel):
    success: bool
    method: AttackMethod
    seed_prompt: str
    generated_count: int
    prompts: List[Dict[str, Any]]
    generation_mode: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    note: Optional[str] = None
