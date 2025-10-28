from vllm import LLM, SamplingParams
from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)
from typing import List, Optional, Union


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
        model: Optional[LLM] = None,
        on_fail: Optional[callable] = None,
        **kwargs,
    ):
        super().__init__(on_fail=on_fail, **kwargs)
        if model is None:
            raise ValueError("必须传入 vLLM LLM 模型实例")
        self.model = model

    def _detect(self, prompts: Union[str, List[str]]) -> str:
        """
        使用vLLM进行推理，返回生成的文本结果字符串。
        """
        if isinstance(prompts, str):
            prompts = [prompts]

        tokenizer = self.model.tokenizer
        formatted_prompts = tokenizer.apply_chat_template(
            [{"role": "user", "content": prompt} for prompt in prompts],
            return_tensors="pt"
        )

        sampling_params = SamplingParams(temperature=0.0, max_tokens=100)
        outputs = self.model.generate(formatted_prompts, sampling_params)

        # 访问vLLM生成结果，取第一个生成文本
        result_texts = [output.outputs[0].text for output in outputs]

        # 拼接所有结果，方便后续解析
        combined_result = "\n".join(result_texts)
        
        print(result_texts)
        print("检测结果:", combined_result)
        
        return combined_result

    def _parse_result(self, result: str) -> Optional[str]:
        """
        解析模型生成的结果，判断是否安全，返回违规类别描述或None。
        """
        lines = result.strip().split("\n")
        if not lines or lines[0].lower() == "safe":
            return None

        if lines[0].lower() == "unsafe" and len(lines) > 1:
            violated_categories = lines[1].split(",")
            parsed_result = [
                f"{cat}: {self.HAZARD_DESC.get(cat, '未知')}"
                for cat in violated_categories
            ]
            return ", ".join(parsed_result)

        raise ValueError("无效的结果格式")

    def validate(
        self,
        value: Union[str, List[str]],
        metadata: Optional[dict] = None,
    ) -> ValidationResult:
        try:
            result = self._detect(value)
            parsed_result = self._parse_result(result)
            if parsed_result is None:
                return PassResult(value=value, metadata=metadata)
            else:
                return FailResult(
                    error_message="LlamaGuard检测到文本违反安全问题: " + parsed_result,
                )
        except Exception as e:
            return FailResult(error_message=f"LlamaGuard推理异常: {str(e)}")