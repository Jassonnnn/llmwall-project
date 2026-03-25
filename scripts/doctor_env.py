#!/usr/bin/env python3
"""
jb_demo 环境自检脚本。
用于确认当前 Python/依赖是否来自目标 conda 环境，并检查关键包版本。
"""

from __future__ import annotations

import importlib
import importlib.metadata as md
import os
import site
import sys
from pathlib import Path


EXPECTED_PREFIX_HINT = "/data/jb_demo"
CHECK_PKGS = [
    "fastapi",
    "uvicorn",
    "litellm",
    "openai",
    "httpx",
    "pydantic",
    "starlette",
    "pandas",
    "jinja2",
]


def _pkg_version(name: str) -> str:
    try:
        return md.version(name)
    except Exception:  # noqa: BLE001
        return "MISSING"


def _pkg_file(name: str) -> str:
    try:
        mod = importlib.import_module(name)
        return str(Path(mod.__file__).resolve()) if getattr(mod, "__file__", None) else "<builtin>"
    except Exception:  # noqa: BLE001
        return "N/A"


def main() -> int:
    print("=== jb_demo env doctor ===")
    print(f"python_executable: {sys.executable}")
    print(f"python_version: {sys.version.splitlines()[0]}")
    print(f"sys.prefix: {sys.prefix}")
    print(f"PYTHONNOUSERSITE: {os.getenv('PYTHONNOUSERSITE', '')}")
    print(f"ENABLE_USER_SITE: {site.ENABLE_USER_SITE}")
    print(f"user_site: {site.getusersitepackages()}")
    print()

    if EXPECTED_PREFIX_HINT not in sys.prefix:
        print("[WARN] 当前 Python 可能不是 /data/jb_demo 环境。")

    if os.getenv("PYTHONNOUSERSITE", "") != "1":
        print("[WARN] 建议设置 PYTHONNOUSERSITE=1，避免混入 ~/.local 包。")

    print("\n=== package versions ===")
    for pkg in CHECK_PKGS:
        print(f"{pkg:10s} {_pkg_version(pkg):>10s}  {_pkg_file(pkg)}")

    print("\n=== recommendation ===")
    print("1) conda activate jb_demo")
    print("2) export PYTHONNOUSERSITE=1")
    print("3) python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
