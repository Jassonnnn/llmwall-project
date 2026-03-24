#!/usr/bin/env python3
"""
Helper script to load and explore downloaded red team datasets
"""

import pandas as pd
import json
from pathlib import Path

class DatasetLoader:
    def __init__(self, base_path="./"):
        self.base_path = Path(base_path)

    def load_harmbench_text_all(self):
        """Load complete HarmBench text behaviors"""
        path = self.base_path / "HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv"
        return pd.read_csv(path)

    def load_harmbench_text_test(self):
        """Load HarmBench test split"""
        path = self.base_path / "HarmBench/data/behavior_datasets/harmbench_behaviors_text_test.csv"
        return pd.read_csv(path)

    def load_harmbench_text_val(self):
        """Load HarmBench validation split"""
        path = self.base_path / "HarmBench/data/behavior_datasets/harmbench_behaviors_text_val.csv"
        return pd.read_csv(path)

    def load_harmbench_multimodal(self):
        """Load HarmBench multimodal behaviors"""
        path = self.base_path / "HarmBench/data/behavior_datasets/harmbench_behaviors_multimodal_all.csv"
        return pd.read_csv(path)

    def load_advbench_harmful_behaviors(self):
        """Load AdvBench harmful behaviors (520 prompts)"""
        path = self.base_path / "llm-attacks/data/advbench/harmful_behaviors.csv"
        return pd.read_csv(path)

    def load_advbench_harmful_strings(self):
        """Load AdvBench target harmful strings"""
        path = self.base_path / "llm-attacks/data/advbench/harmful_strings.csv"
        return pd.read_csv(path)

    def load_jailbreakbench_prompts(self, model="vicuna"):
        """Load JailbreakBench prompts for specific model"""
        path = self.base_path / f"jailbreakbench/examples/prompts/{model}.json"
        with open(path, 'r') as f:
            return json.load(f)

    def get_dataset_stats(self):
        """Get statistics for all available datasets"""
        stats = {}

        try:
            df = self.load_harmbench_text_all()
            stats['HarmBench Text (All)'] = {
                'count': len(df),
                'columns': list(df.columns)
            }
        except Exception as e:
            stats['HarmBench Text (All)'] = f"Error: {e}"

        try:
            df = self.load_harmbench_text_test()
            stats['HarmBench Text (Test)'] = {
                'count': len(df),
                'columns': list(df.columns)
            }
        except Exception as e:
            stats['HarmBench Text (Test)'] = f"Error: {e}"

        try:
            df = self.load_advbench_harmful_behaviors()
            stats['AdvBench Harmful Behaviors'] = {
                'count': len(df),
                'columns': list(df.columns)
            }
        except Exception as e:
            stats['AdvBench Harmful Behaviors'] = f"Error: {e}"

        return stats


def main():
    """Example usage"""
    loader = DatasetLoader()

    print("=" * 60)
    print("Dataset Statistics")
    print("=" * 60)

    stats = loader.get_dataset_stats()
    for name, info in stats.items():
        print(f"\n{name}:")
        if isinstance(info, dict):
            print(f"  Count: {info['count']}")
            print(f"  Columns: {', '.join(info['columns'])}")
        else:
            print(f"  {info}")

    print("\n" + "=" * 60)
    print("Loading HarmBench Text (All) - First 5 rows")
    print("=" * 60)

    try:
        df = loader.load_harmbench_text_all()
        print(df.head())

        print("\n" + "=" * 60)
        print("Sample Behavior:")
        print("=" * 60)
        if 'Behavior' in df.columns:
            print(df['Behavior'].iloc[0])
        elif 'behavior' in df.columns:
            print(df['behavior'].iloc[0])
    except Exception as e:
        print(f"Error loading HarmBench: {e}")

    print("\n" + "=" * 60)
    print("Loading AdvBench Harmful Behaviors - First 5 rows")
    print("=" * 60)

    try:
        df = loader.load_advbench_harmful_behaviors()
        print(df.head())
    except Exception as e:
        print(f"Error loading AdvBench: {e}")


if __name__ == "__main__":
    main()
