from typing import Callable, List, Optional, Union, Any
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)


@register_validator(name="xd810/llamaguard", data_type="string")
class LlamaGuard(Validator):
    MODEL_PATH = "/root/.cache/modelscope/hub/models/LLM-Research/Llama-Guard-3-8B"
    # HAZARD_DESC = {
    #     "S1": "Violent Crimes",
    #     "S2": "Non-Violent Crimes",
    #     "S3": "Sex-Related Crimes",
    #     "S4": "Child Sexual Exploitation",
    #     "S5": "Defamation",
    #     "S6": "Specialized Advice",
    #     "S7": "Privacy",
    #     "S8": "Intellectual Property",
    #     "S9": "Indiscriminate Weapons",
    #     "S10": "Hate",
    #     "S11": "Suicide & Self-Harm",
    #     "S12": "Sexual Content",
    #     "S13": "Elections",
    #     "S14": "Code Interpreter Abuse",
    # }
    
    HAZARD_DESC = {
        "S1": "暴力犯罪",
        "S2": "非暴力犯罪",
        "S3": "性相关犯罪",
        "S4": "儿童性剥削",
        "S5": "诽谤",
        "S6": "专业建议",
        "S7": "隐私",
        "S8": "知识产权",
        "S9": "无差别武器",
        "S10": "仇恨",
        "S11": "自杀与自残",
        "S12": "色情内容",
        "S13": "选举",
        "S14": "代码解释器滥用",
    }

    def __init__(
        self,
        device: str = "cuda",
        on_fail: Optional[Callable] = None,
        **kwargs,
    ):
        super().__init__(on_fail=on_fail, **kwargs)
        self.device = device
        self.tokenizer = AutoTokenizer.from_pretrained(LlamaGuard.MODEL_PATH)
        self.model = AutoModelForCausalLM.from_pretrained(
            LlamaGuard.MODEL_PATH, torch_dtype=torch.bfloat16, device_map=device
        )

    def _detect(self, prompt: str) -> str:
        """
        使用 vLLM 引擎检测单个提示中的不安全内容。
        """
        # 1. 根据 LlamaGuard 的要求格式化输入
        chat_formatted = [{"role": "user", "content": prompt}]
        # `apply_chat_template` 会自动添加指令和角色标签
        formatted_prompt = self.tokenizer.apply_chat_template(
            chat_formatted, tokenize=False, add_generation_prompt=True
        )
        print(f"检测输入: {formatted_prompt}")

        # 2. 使用 vLLM 引擎进行推理
        # vllm.generate 期望一个 prompt 列表
        outputs = self.llm.generate([formatted_prompt], self.sampling_params)
        
        # 3. 提取生成的文本
        # vLLM 返回一个 RequestOutput 对象列表
        result_text = outputs[0].outputs[0].text.strip()
        print(f"LlamaGuard VLLM 输出: {result_text}")
        return result_text

    def _parse_result(self, result: str) -> Optional[str]:
        """
        解析 LlamaGuard 的输出。如果安全，则返回 None；否则，返回格式化的风险类别。
        """
        lines = result.strip().split("\n")
        if not lines or lines[0] == "safe":
            return None  # 输入是安全的

        if lines[0] == "unsafe" and len(lines) > 1:
            violated_categories = lines[1].split(",")
            parsed_result = [
                f"{category.strip()}: {self.HAZARD_DESC.get(category.strip(), 'Unknown')}"
                for category in violated_categories
            ]
            return ", ".join(parsed_result)

        # 如果输出格式不符合预期，抛出一个错误
        raise ValueError(f"来自 LlamaGuard 的无效结果格式: {result}")

    def validate(
        self,
        value: Union[str, List[str]],
        metadata: Optional[dict] = None,
    ) -> ValidationResult:
        result = self._detect(value)
        parsed_result = self._parse_result(result)
        if parsed_result is None:
            return PassResult(value=value, metadata=metadata)
        else:
            return FailResult(
                error_message="LlamaGuard检测到文本违反安全问题."+parsed_result,
            )