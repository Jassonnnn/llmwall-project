import re
from typing import Any, Callable, Dict, List, Optional
from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
    ErrorSpan
)

@register_validator(name="guardrails/ban_list_regex", data_type="string")
class BanListRegex(Validator):
    """
    使用正则表达式高效检测文本中的敏感词，并支持敏感词分类。
    Args:
        banned_words: 形如 {"类别1": ["词A", "词B"], "类别2": ["词C", ...], ...} 的str (json格式)
        on_fail: 失败时回调
    """
    def __init__(
        self,
        banned_words: str,  # 这里推荐输入 json.dumps(dict)，否则可传类似 "ad|bc|cd"
        on_fail: Optional[Callable] = None,
    ):
        super().__init__(banned_words=banned_words, on_fail=on_fail)
        import json
        # 支持直接是 "词1|词2" 或 json
        try:
            self.patterns: Dict[str, List[str]] = json.loads(banned_words)
        except Exception:
            # 回退为无类别，全部同一类
            self.patterns = {"BANNED": [w.strip() for w in banned_words.split("|") if w.strip()]}
        
        self.regex, self.category_map = self._build_detector_from_patterns(self.patterns)
    
    def _build_detector_from_patterns(self, patterns: Dict[str, List[str]]):
        category_map = {}
        all_words = []
        for category, words in patterns.items():
            all_words.extend(words)
            for word in words:
                category_map[word.lower()] = category
        if not all_words:
            return None, {}
        combined_regex = re.compile("|".join(map(re.escape, all_words)), re.IGNORECASE)
        return combined_regex, category_map

    def validate(self, value: Any, metadata: Dict = {}) -> ValidationResult:
        """检测是否有命中敏感词"""
        text = str(value)
        regex = self.regex
        category_map = self.category_map
        if not regex:
            return PassResult()

        detected_results = []
        for match in regex.finditer(text):
            word = match.group(0)
            category = category_map.get(word.lower(), "UNKNOWN")
            detected_results.append({
                "word": word,
                "category": category,
                "start": match.start(),
                "end": match.end(),
            })

        if not detected_results:
            return PassResult(value=value, metadata=metadata)
        
        # 从后往前替换敏感词，获得屏蔽后的文本
        fix_value = text
        error_spans = []
        for result in sorted(detected_results, key=lambda x: x['start'], reverse=True):
            start, end = result['start'], result['end']
            fix_value = fix_value[:start] + "*" * (end - start) + fix_value[end:]
            error_spans.append(ErrorSpan(
                start=start,
                end=end,
                reason=f"检测到敏感词（{result['category']}）: '{result['word']}'"
            ))
        
        return FailResult(
            error_message=f"文本中包含{len(detected_results)}个敏感词。",
            fix_value=fix_value,
            error_spans=error_spans
        )
