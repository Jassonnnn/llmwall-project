#!/bin/bash
# 一键启动 jb_demo 项目
# 用法: bash start.sh [--reload]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 激活 conda 环境
eval "$(conda shell.bash hook)"
conda activate jb_demo

if [ "$1" = "--reload" ]; then
    echo "以开发模式启动 (热重载)..."
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
else
    echo "以生产模式启动..."
    python main.py
fi
