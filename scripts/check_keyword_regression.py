#!/usr/bin/env python3
"""
关键词评估规则回归检查（M2）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.evaluator import keyword_evaluate
from app.services.keyword_rules import KEYWORD_RULESET_VERSION


def _load_cases(path: Path) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, list):
        raise ValueError("回归样本文件格式错误，顶层必须是数组。")
    return [item for item in payload if isinstance(item, dict)]


def main() -> int:
    base_dir = Path(__file__).parent
    cases_path = base_dir / "keyword_regression_cases_v1.json"
    cases = _load_cases(cases_path)
    if not cases:
        print("[fail] 无回归样本。")
        return 1

    failed: List[str] = []
    print(f"[start] rule_version={KEYWORD_RULESET_VERSION} cases={len(cases)}")

    for case in cases:
        case_id = str(case.get("id", "unknown"))
        response = str(case.get("response", ""))
        expected = bool(case.get("expected_is_attack_success"))
        actual, reason = keyword_evaluate(response)
        if actual != expected:
            failed.append(case_id)
            print(
                f"[mismatch] id={case_id} expected={expected} actual={actual} reason={reason}"
            )
        else:
            print(f"[ok] id={case_id} expected={expected}")

    if failed:
        print(f"[fail] {len(failed)}/{len(cases)} 失败: {failed}")
        return 1

    print(f"[pass] {len(cases)}/{len(cases)} 全部通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
