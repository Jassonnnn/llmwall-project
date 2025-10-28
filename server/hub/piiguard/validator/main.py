from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)
from typing import Callable, List, Optional, Union, Any, Dict
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer import RecognizerResult
from gliner import (
    GLiNER,
)  # Ensure GLiNER is installed: pip install git+https://github.com/ltg-uio/GLiNER.git


@register_validator(name="xd810/piiguard_gliner", data_type="string")
class PIIGuard(Validator):
    """
    使用 GLiNER 检测和屏蔽中文/英文敏感实体。
    """

    # Presidio实体与GLiNER标签映射
    ENTITY_MAP = {
        "NAME": "name",
        "ID_NUMBER": "id_number",
        "PHONE_NUMBER": "phone_number",
        "EMAIL": "email",
        "ADDRESS": "address",
        "BANK_CARD_NUMBER": "bank_card_number",
        "PASSWORD": "password",
        "DATE_OF_BIRTH": "date_of_birth",
        "DRIVER_LICENSE_NUMBER": "driver_license_number",
        "SOCIAL_SECURITY_NUMBER": "social_security_number",
        "MEDICAL_RECORD_NUMBER": "medical_record_number",
        "COMPANY_NAME": "company_name",
        "JOB_TITLE": "job_title",
    }


    def __init__(
        self,
        device: str = "cuda",
        model_name: str = "/data/ljc/llmwall/model/gliner-x-base",
        on_fail: Optional[Callable] = None,
        entities: Optional[List[str]] = None,
        model: Optional[GLiNER] = None,
        **kwargs,
    ):
        super().__init__(on_fail=on_fail, **kwargs)
        self.device = device
        self.model = model if model is not None else GLiNER.from_pretrained(model_name,device_map="auto")
        # 配置检测实体标签（GLiNER实际标签）
        self.entities = (
            entities
            if entities is not None
            else [
                "name",
                "id_number",
                "phone_number",
                "email",
                "address",
                "bank_card_number",
                "password",
                "date_of_birth",
                "driver_license_number",
                "social_security_number",
                "medical_record_number",
                "company_name",
                "job_title",
            ]
        )
        self.anonymizer = AnonymizerEngine()

    def validate(
        self,
        value: Union[str, List[str]],
        metadata: Optional[dict] = None,
    ) -> ValidationResult:
        if metadata is None:
            metadata = {}

        entities = metadata.get("entities", self.entities)
        if isinstance(value, list):
            value = "\n".join(value)

        anonymized_text, error_spans, results = self.anonymize(
            text=value, entities=entities
        )

        if len(error_spans) == 0:
            return PassResult(value=value, metadata=metadata)
        else:
            pii_details = []
            for result in results:
                entity_text = value[result.start : result.end]
                pii_details.append(
                    f"{result.entity_type}: '{entity_text}' (confidence: {result.score:.2f})"
                )

            error_message = (
                f"PII detected in text. Found {len(error_spans)} sensitive entity(ies):\n"
                + "\n".join(pii_details)
            )

            return FailResult(
                error_message=error_message,
                fix_value=anonymized_text,
                error_spans=error_spans,
            )

    def _analyze_text(self, text: str, entities: List[str]) -> List[RecognizerResult]:
        """
        使用GLiNER检测文本实体，返回Presidio风格的RecognizerResult列表。
        """
        # 配置GLiNER的标签
        gliner_labels = entities

        print("Using GLiNER labels:", gliner_labels)

        results = []
        if not gliner_labels:
            return []

        gliner_entities = self.model.predict_entities(text, gliner_labels)
        pres_entity_map: Dict[str, str] = {v: k for k, v in self.ENTITY_MAP.items()}

        for ent in gliner_entities:
            label = ent["label"]
            presidio_entity = pres_entity_map.get(label)
            print(label, presidio_entity)
            if presidio_entity:
                results.append(
                    RecognizerResult(
                        entity_type=presidio_entity,
                        start=ent["start"],
                        end=ent["end"],
                        score=ent.get("score", 0.95),
                    )
                )
        return results

    def _create_anonymize_operators(self) -> dict:
        """创建GLiNER输出的Presidio风格匿名化操作配置，按隐私分类对应替换效果"""
        return {
            "NAME": OperatorConfig("replace", {"new_value": "[姓名]"}),
            "ID_NUMBER": OperatorConfig("replace", {"new_value": "[身份证号]"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[手机号]"}),
            "EMAIL": OperatorConfig("replace", {"new_value": "[邮箱]"}),
            "ADDRESS": OperatorConfig("replace", {"new_value": "[地址]"}),
            "BANK_CARD_NUMBER": OperatorConfig("replace", {"new_value": "[银行卡号]"}),
            "PASSWORD": OperatorConfig("replace", {"new_value": "[密码]"}),
            "DATE_OF_BIRTH": OperatorConfig("replace", {"new_value": "[出生日期]"}),
            "DRIVER_LICENSE_NUMBER": OperatorConfig(
                "replace", {"new_value": "[驾驶证号]"}
            ),
            "SOCIAL_SECURITY_NUMBER": OperatorConfig(
                "replace", {"new_value": "[社保号]"}
            ),
            "MEDICAL_RECORD_NUMBER": OperatorConfig(
                "replace", {"new_value": "[病历号]"}
            ),
            "COMPANY_NAME": OperatorConfig("replace", {"new_value": "[公司名称]"}),
            "JOB_TITLE": OperatorConfig("replace", {"new_value": "[职位]"}),
        }

    def anonymize(self, text: str, entities: List[str]) -> tuple:
        results = self._analyze_text(text, entities)
        error_spans = []
        for result in results:
            error_spans.append(
                {
                    "start": result.start,
                    "end": result.end,
                    "reason": f"Detected {result.entity_type} with confidence {result.score:.2f}",
                }
            )

        if not results:
            return text, error_spans, results

        operators = self._create_anonymize_operators()
        anonymized_result = self.anonymizer.anonymize(
            text=text, analyzer_results=results, operators=operators
        )

        return anonymized_result.text, error_spans, results
