#!/usr/bin/env python3
"""
将人工复核结果回写到攻击分类索引（v2）。

review 文件支持 JSONL，每行字段示例：
{
  "dataset_id": "harmbench_text_test",
  "row_id": 12,
  "attack_category": "contextual_injection",
  "review_note": "样本存在明显系统提示注入",
  "reviewed_by": "alice",
  "reviewed_at": "2026-03-25T10:00:00+08:00"
}
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import (
    ATTACK_CATEGORIES,
    ATTACK_CATEGORY_INDEX_FILE,
    ATTACK_CATEGORY_INDEX_PREFERRED_VERSION,
    ATTACK_CATEGORY_QUALITY_REPORT_FILE,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} 第 {lineno} 行 JSON 解析失败: {exc}") from exc
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _save_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _save_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="回写人工复核结果到分类索引")
    parser.add_argument(
        "--index-file",
        default=str(ATTACK_CATEGORY_INDEX_FILE),
        help="索引文件路径（默认 v2）",
    )
    parser.add_argument(
        "--review-file",
        required=True,
        help="人工复核 JSONL 文件路径",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="输出索引路径；默认覆盖 --index-file",
    )
    parser.add_argument(
        "--quality-report-output",
        default=str(ATTACK_CATEGORY_QUALITY_REPORT_FILE),
        help="输出质量报告路径",
    )
    return parser.parse_args()


def _build_quality_report(index_rows: List[Dict[str, Any]], output_path: Path) -> Dict[str, Any]:
    valid_categories = [item["id"] for item in ATTACK_CATEGORIES if item["id"] != "mixed_all"]
    category_counts = {cid: 0 for cid in valid_categories}
    manual_override_count = 0
    latest_ts = ""

    for row in index_rows:
        category = str(row.get("attack_category", ""))
        if category in category_counts:
            category_counts[category] += 1
        if row.get("manual_review"):
            manual_override_count += 1
        ts = str(row.get("labeled_at", ""))
        if ts > latest_ts:
            latest_ts = ts

    nonzero_count = sum(1 for _, cnt in category_counts.items() if cnt > 0)
    total = len(index_rows)
    coverage = round(nonzero_count / max(len(valid_categories), 1), 4)
    direct_request_ratio = round(category_counts.get("direct_request", 0) / total, 4) if total else None

    return {
        "ready": True,
        "index_version": ATTACK_CATEGORY_INDEX_PREFERRED_VERSION,
        "index_file": str(output_path),
        "last_built_at": latest_ts or _now_iso(),
        "total_records": total,
        "category_counts": category_counts,
        "coverage": coverage,
        "nonzero_category_count": nonzero_count,
        "total_category_count": len(valid_categories),
        "direct_request_ratio": direct_request_ratio,
        "manual_override_count": manual_override_count,
    }


def main() -> int:
    args = _parse_args()
    index_path = Path(args.index_file)
    output_path = Path(args.output) if args.output else index_path
    review_path = Path(args.review_file)
    quality_report_path = Path(args.quality_report_output)

    if not index_path.exists():
        raise FileNotFoundError(f"索引文件不存在: {index_path}")
    if not review_path.exists():
        raise FileNotFoundError(f"复核文件不存在: {review_path}")

    valid_categories = {item["id"] for item in ATTACK_CATEGORIES if item["id"] != "mixed_all"}
    index_rows = _load_jsonl(index_path)
    review_rows = _load_jsonl(review_path)

    review_map: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for row in review_rows:
        dataset_id = str(row.get("dataset_id", "")).strip()
        row_id_raw = row.get("row_id")
        category = str(row.get("attack_category", "")).strip()
        if not dataset_id or row_id_raw is None:
            continue
        try:
            row_id = int(row_id_raw)
        except (TypeError, ValueError):
            continue
        if category not in valid_categories:
            raise ValueError(f"复核标签不合法: {category} (dataset_id={dataset_id}, row_id={row_id})")
        review_map[(dataset_id, row_id)] = row

    updated = 0
    for item in index_rows:
        dataset_id = str(item.get("dataset_id", "")).strip()
        row_id = int(item.get("row_id", -1))
        key = (dataset_id, row_id)
        review = review_map.get(key)
        if not review:
            continue

        old_category = str(item.get("attack_category", "")).strip()
        new_category = str(review["attack_category"]).strip()
        if old_category != new_category:
            item["previous_attack_category"] = old_category
        item["attack_category"] = new_category
        item["manual_review"] = True
        item["manual_review_note"] = str(review.get("review_note", "")).strip()
        item["manual_reviewed_by"] = str(review.get("reviewed_by", "")).strip()
        item["manual_reviewed_at"] = str(review.get("reviewed_at", "")).strip() or _now_iso()
        item["quality_flag"] = "manual_override"
        item["review_result"] = "manual_override"
        item["label_stage"] = "manual_review"
        updated += 1

    _save_jsonl(output_path, index_rows)
    report = _build_quality_report(index_rows, output_path)
    _save_json(quality_report_path, report)

    print(f"[done] 回写完成: updated={updated}")
    print(f"[done] 索引输出: {output_path}")
    print(f"[done] 质量报告: {quality_report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
