from typing import List, Dict, Optional
import pandas as pd

from app.config import DATASETS_PATH, AVAILABLE_DATASETS


def load_dataset(dataset_id: str, sample_count: Optional[int] = None) -> List[str]:
    """加载数据集并返回提示词列表"""
    if dataset_id not in AVAILABLE_DATASETS:
        raise ValueError(f"未知数据集: {dataset_id}")

    ds_config = AVAILABLE_DATASETS[dataset_id]
    file_path = DATASETS_PATH / ds_config["path"]

    if not file_path.exists():
        raise FileNotFoundError(f"数据集文件不存在: {file_path}")

    df = pd.read_csv(file_path)
    prompt_col = ds_config["prompt_column"]

    if prompt_col not in df.columns:
        # 尝试小写
        prompt_col = prompt_col.lower()
        if prompt_col not in df.columns:
            raise ValueError(f"找不到提示词列: {ds_config['prompt_column']}")

    prompts = df[prompt_col].dropna().tolist()

    if sample_count and sample_count < len(prompts):
        prompts = prompts[:sample_count]

    return prompts


def get_dataset_info() -> List[Dict]:
    """获取所有可用数据集的信息"""
    result = []
    for ds_id, ds_config in AVAILABLE_DATASETS.items():
        file_path = DATASETS_PATH / ds_config["path"]
        count = 0
        available = False

        if file_path.exists():
            try:
                df = pd.read_csv(file_path)
                prompt_col = ds_config["prompt_column"]
                if prompt_col not in df.columns:
                    prompt_col = prompt_col.lower()
                if prompt_col in df.columns:
                    count = len(df[prompt_col].dropna())
                    available = True
            except Exception:
                pass

        result.append({
            "id": ds_id,
            "name": ds_config["name"],
            "description": ds_config["description"],
            "count": count,
            "available": available
        })

    return result
