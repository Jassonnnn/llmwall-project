import json
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from app.config import (
    ATTACK_CATEGORIES,
    ATTACK_CATEGORY_INDEX_FILE,
    ATTACK_CATEGORY_INDEX_VERSION,
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


def _load_category_index() -> Dict[str, Dict[str, set]]:
    """
    读取分类索引文件，返回结构:
    {
      dataset_id: {
        attack_category: {row_id1, row_id2, ...}
      }
    }
    """
    index_path = ATTACK_CATEGORY_INDEX_FILE
    if not index_path.exists():
        raise CategoryIndexMissingError(
            f"分类索引不存在: {index_path}。请先运行 scripts/build_attack_category_index.py 构建索引。"
        )

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
            if version and version != ATTACK_CATEGORY_INDEX_VERSION:
                continue
            if row_id is None:
                continue

            index_map.setdefault(dataset_id, {}).setdefault(category, set()).add(int(row_id))

    return index_map


def _try_load_category_index() -> Tuple[bool, Dict[str, Dict[str, set]], str]:
    try:
        return True, _load_category_index(), ""
    except Exception as exc:  # noqa: BLE001
        return False, {}, str(exc)


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

        index_map = _load_category_index()
        row_ids = index_map.get(dataset_id, {}).get(attack_category, set())
        prompts = [r["prompt"] for r in records if r["row_id"] in row_ids]

    if sample_count and sample_count < len(prompts):
        prompts = prompts[:sample_count]

    return prompts


def get_dataset_info() -> Dict[str, Any]:
    """获取数据集信息以及攻击分类统计。"""
    index_ready, index_map, index_error = _try_load_category_index()
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

    return {
        "datasets": datasets,
        "attack_categories": ATTACK_CATEGORIES,
        "index_ready": index_ready,
        "index_error": index_error,
        "index_file": str(ATTACK_CATEGORY_INDEX_FILE),
        "index_version": ATTACK_CATEGORY_INDEX_VERSION,
    }
