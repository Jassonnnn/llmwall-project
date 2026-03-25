import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from app.config import (
    ATTACK_CATEGORIES,
    ATTACK_CATEGORY_INDEX_FILE,
    ATTACK_CATEGORY_INDEX_FALLBACK_FILE,
    ATTACK_CATEGORY_INDEX_FALLBACK_VERSION,
    ATTACK_CATEGORY_INDEX_PREFERRED_VERSION,
    ATTACK_CATEGORY_QUALITY_REPORT_FILE,
    AVAILABLE_DATASETS,
    DATASETS_PATH,
)


class CategoryIndexMissingError(Exception):
    """分类索引不存在或不可用。"""


def _category_ids(include_mixed: bool = True) -> List[str]:
    ids = [item["id"] for item in ATTACK_CATEGORIES]
    if include_mixed:
        return ids
    return [cid for cid in ids if cid != "mixed_all"]


def _get_prompt_column(df: pd.DataFrame, expected_col: str) -> str:
    if expected_col in df.columns:
        return expected_col
    lowered = expected_col.lower()
    if lowered in df.columns:
        return lowered
    raise ValueError(f"找不到提示词列: {expected_col}")


def load_dataset_records(dataset_id: str) -> List[Dict[str, Any]]:
    """
    加载数据集记录，返回包含 row_id 和 prompt 的列表。
    row_id 使用原始 CSV 的行号，便于与 sidecar 索引关联。
    """
    if dataset_id not in AVAILABLE_DATASETS:
        raise ValueError(f"未知数据集: {dataset_id}")

    ds_config = AVAILABLE_DATASETS[dataset_id]
    file_path = DATASETS_PATH / ds_config["path"]

    if not file_path.exists():
        raise FileNotFoundError(f"数据集文件不存在: {file_path}")

    df = pd.read_csv(file_path)
    prompt_col = _get_prompt_column(df, ds_config["prompt_column"])

    records: List[Dict[str, Any]] = []
    for row_id, prompt in df[prompt_col].items():
        if pd.isna(prompt):
            continue
        text = str(prompt).strip()
        if not text:
            continue
        records.append({"row_id": int(row_id), "prompt": text})
    return records


def _load_category_index_from_path(index_path: Path, expected_version: str) -> Dict[str, Dict[str, set]]:
    """
    读取分类索引文件，返回结构:
    {
      dataset_id: {
        attack_category: {row_id1, row_id2, ...}
      }
    }
    """
    if not index_path.exists():
        raise CategoryIndexMissingError(f"分类索引不存在: {index_path}")

    allowed_categories = set(_category_ids(include_mixed=False))
    index_map: Dict[str, Dict[str, set]] = {}

    with open(index_path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"分类索引 JSON 解析失败（第 {lineno} 行）: {exc}") from exc

            dataset_id = item.get("dataset_id")
            category = item.get("attack_category")
            row_id = item.get("row_id")
            version = item.get("label_version")

            if dataset_id not in AVAILABLE_DATASETS:
                continue
            if category not in allowed_categories:
                continue
            if row_id is None:
                continue

            # v2 要求严格版本；v1 允许历史数据缺失 label_version
            if expected_version == ATTACK_CATEGORY_INDEX_PREFERRED_VERSION:
                if version != expected_version:
                    continue
            else:
                if version and version != expected_version:
                    continue

            index_map.setdefault(dataset_id, {}).setdefault(category, set()).add(int(row_id))

    return index_map


def _resolve_category_index() -> Dict[str, Any]:
    """
    按优先级加载索引：
    1) v2（preferred）
    2) v1（fallback）
    """
    preferred_error = ""
    fallback_error = ""

    try:
        preferred_map = _load_category_index_from_path(
            ATTACK_CATEGORY_INDEX_FILE, ATTACK_CATEGORY_INDEX_PREFERRED_VERSION
        )
        if preferred_map:
            return {
                "ready": True,
                "index_map": preferred_map,
                "index_version": ATTACK_CATEGORY_INDEX_PREFERRED_VERSION,
                "index_file": str(ATTACK_CATEGORY_INDEX_FILE),
                "is_fallback": False,
                "warning": "",
                "error": "",
            }
        preferred_error = f"{ATTACK_CATEGORY_INDEX_FILE} 无有效 {ATTACK_CATEGORY_INDEX_PREFERRED_VERSION} 记录"
    except Exception as exc:  # noqa: BLE001
        preferred_error = str(exc)

    try:
        fallback_map = _load_category_index_from_path(
            ATTACK_CATEGORY_INDEX_FALLBACK_FILE, ATTACK_CATEGORY_INDEX_FALLBACK_VERSION
        )
        if fallback_map:
            return {
                "ready": True,
                "index_map": fallback_map,
                "index_version": ATTACK_CATEGORY_INDEX_FALLBACK_VERSION,
                "index_file": str(ATTACK_CATEGORY_INDEX_FALLBACK_FILE),
                "is_fallback": True,
                "warning": (
                    f"当前使用回退索引 {ATTACK_CATEGORY_INDEX_FALLBACK_VERSION}，"
                    f"建议重建 {ATTACK_CATEGORY_INDEX_PREFERRED_VERSION} 提升分类质量。"
                ),
                "error": "",
            }
        fallback_error = (
            f"{ATTACK_CATEGORY_INDEX_FALLBACK_FILE} 无有效 {ATTACK_CATEGORY_INDEX_FALLBACK_VERSION} 记录"
        )
    except Exception as exc:  # noqa: BLE001
        fallback_error = str(exc)

    return {
        "ready": False,
        "index_map": {},
        "index_version": "",
        "index_file": "",
        "is_fallback": False,
        "warning": "",
        "error": (
            "分类索引不可用。"
            f" preferred_error={preferred_error}; fallback_error={fallback_error}。"
            "请先运行 scripts/build_attack_category_index.py 构建 v2 索引。"
        ),
    }


def _load_quality_report(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except Exception:  # noqa: BLE001
        return {}
    return {}


def _build_runtime_quality_summary(
    *,
    index_map: Dict[str, Dict[str, set]],
    datasets: List[Dict[str, Any]],
    index_version: str,
) -> Dict[str, Any]:
    category_ids = _category_ids(include_mixed=False)
    nonzero_categories = set()
    total_labeled = 0
    direct_request_total = 0

    for ds in datasets:
        ds_id = ds["id"]
        for cid in category_ids:
            cnt = len(index_map.get(ds_id, {}).get(cid, set()))
            total_labeled += cnt
            if cnt > 0:
                nonzero_categories.add(cid)
            if cid == "direct_request":
                direct_request_total += cnt

    direct_request_ratio = (
        round(direct_request_total / total_labeled, 4) if total_labeled > 0 else None
    )
    coverage = round(len(nonzero_categories) / max(len(category_ids), 1), 4)

    return {
        "index_version": index_version,
        "ready": True,
        "coverage": coverage,
        "nonzero_category_count": len(nonzero_categories),
        "total_category_count": len(category_ids),
        "direct_request_ratio": direct_request_ratio,
        "conflict_rate": None,
        "last_built_at": None,
    }


def _try_load_category_index() -> Tuple[bool, Dict[str, Dict[str, set]], str]:
    resolved = _resolve_category_index()
    return resolved["ready"], resolved["index_map"], resolved["error"]


def load_dataset(
    dataset_id: str,
    sample_count: Optional[int] = None,
    attack_category: str = "mixed_all",
) -> List[str]:
    """加载数据集并返回提示词列表，可按攻击类别过滤。"""
    records = load_dataset_records(dataset_id)

    if attack_category == "mixed_all":
        prompts = [r["prompt"] for r in records]
    else:
        valid_categories = set(_category_ids(include_mixed=False))
        if attack_category not in valid_categories:
            raise ValueError(f"未知攻击分类: {attack_category}")

        resolved = _resolve_category_index()
        if not resolved["ready"]:
            raise CategoryIndexMissingError(resolved["error"])
        index_map = resolved["index_map"]
        row_ids = index_map.get(dataset_id, {}).get(attack_category, set())
        prompts = [r["prompt"] for r in records if r["row_id"] in row_ids]

    if sample_count and sample_count < len(prompts):
        prompts = prompts[:sample_count]

    return prompts


def get_dataset_info() -> Dict[str, Any]:
    """获取数据集信息以及攻击分类统计。"""
    resolved = _resolve_category_index()
    index_ready = resolved["ready"]
    index_map = resolved["index_map"]
    index_error = resolved["error"]
    category_ids = _category_ids(include_mixed=False)

    datasets: List[Dict[str, Any]] = []
    for ds_id, ds_config in AVAILABLE_DATASETS.items():
        count = 0
        available = False
        category_counts = {cid: None for cid in category_ids}
        category_counts["mixed_all"] = 0

        try:
            records = load_dataset_records(ds_id)
            count = len(records)
            available = True
            category_counts["mixed_all"] = count
            if index_ready:
                for cid in category_ids:
                    category_counts[cid] = len(index_map.get(ds_id, {}).get(cid, set()))
        except Exception:
            pass

        datasets.append(
            {
                "id": ds_id,
                "name": ds_config["name"],
                "description": ds_config["description"],
                "count": count,
                "available": available,
                "category_counts": category_counts,
            }
        )

    runtime_quality = _build_runtime_quality_summary(
        index_map=index_map,
        datasets=datasets,
        index_version=resolved["index_version"] or "none",
    )
    report_quality = _load_quality_report(ATTACK_CATEGORY_QUALITY_REPORT_FILE)
    index_quality = {**runtime_quality, **report_quality} if report_quality else runtime_quality

    return {
        "datasets": datasets,
        "attack_categories": ATTACK_CATEGORIES,
        "index_ready": index_ready,
        "index_error": index_error,
        "index_file": resolved["index_file"] or str(ATTACK_CATEGORY_INDEX_FILE),
        "index_version": resolved["index_version"] or ATTACK_CATEGORY_INDEX_PREFERRED_VERSION,
        "index_warning": resolved["warning"],
        "index_quality": index_quality,
    }
