from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer import EntityRecognizer, RecognizerResult
# 中国手机号码识别器
cn_phone_pattern = Pattern(
    name="chinese_phone", 
    regex=r"1[3-9]\d{9}",
    score=0.9
)
cn_phone_recognizer = PatternRecognizer(
    supported_entity="CN_PHONE_NUMBER",
    patterns=[cn_phone_pattern],
    supported_language="zh"
)

# 中国身份证号码识别器
cn_id_card_pattern = Pattern(
    name="chinese_id_card",
    regex=r"[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]",
    score=0.95
)
cn_id_card_recognizer = PatternRecognizer(
    supported_entity="CN_ID_CARD",
    patterns=[cn_id_card_pattern],
    supported_language="zh"
)

# 邮箱识别器（增强版）
cn_email_pattern = Pattern(
    name="email_enhanced",
    regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    score=0.9
)
cn_email_recognizer = PatternRecognizer(
    supported_entity="CN_EMAIL_ADDRESS",
    patterns=[cn_email_pattern],
    supported_language="zh"
)


# 地址识别器（基于省市区关键词）
address_keywords = [
    "省", "市", "区", "县", "镇", "乡", "街道", "路", "街", "巷", "弄", "栋", "单元", "室"
]
cn_address_pattern = Pattern(
    name="chinese_address",
    regex=f"[\\u4e00-\\u9fff]*({'|'.join(address_keywords)})[\\u4e00-\\u9fff\\d]*",
    score=0.6
)
cn_address_recognizer = PatternRecognizer(
    supported_entity="CN_ADDRESS",
    patterns=[cn_address_pattern],
    supported_language="zh"
)

class LTPAddressRecognizer(EntityRecognizer):
    def __init__(self, supported_entities=None, device='cpu'):
        super().__init__(supported_entities=supported_entities or ["CN_ADDRESS", "PERSON", "LOCATION"], supported_language="zh")
        from ltp import LTP
        self.ltp = LTP(pretrained_model_name_or_path="/root/guardrails/server/server/hub/piiguard/model/base")

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        seg, hidden = self.ltp.seg([list(text)])
        ner = self.ltp.ner(hidden)
        # ner返回格式: [[('S-Ns', 3, 5), ...]]
        for tag, start, end in ner[0]:
            entity_text = "".join(seg[0][start:end + 1])
            start_pos = len("".join(seg[0][:start]))
            end_pos = len("".join(seg[0][:end + 1]))
            # 中文地址类型 LTP 用S-Ns表示地名、S-Ni为机构、S-Nr为人名
            if tag == 'S-Ns' and "CN_ADDRESS" in entities:
                results.append(RecognizerResult(entity_type="CN_ADDRESS",
                                                start=start_pos,
                                                end=end_pos,
                                                score=0.85))
            elif tag == 'S-Nr' and "PERSON" in entities:
                results.append(RecognizerResult(entity_type="PERSON",
                                                start=start_pos,
                                                end=end_pos,
                                                score=0.85))
            elif tag == 'S-Ni' and "ORGANIZATION" in entities:
                results.append(RecognizerResult(entity_type="ORGANIZATION",
                                                start=start_pos,
                                                end=end_pos,
                                                score=0.85))
        return results