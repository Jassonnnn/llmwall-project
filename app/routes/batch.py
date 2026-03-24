import json
import asyncio
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.models import BatchEvalRequest
from app.services.dataset import load_dataset, get_dataset_info
from app.services.evaluator import evaluate_single_prompt

router = APIRouter()


@router.get("/datasets")
async def list_datasets():
    return get_dataset_info()


@router.post("/batch_evaluate")
async def batch_evaluate(req: BatchEvalRequest):
    """启动批量评估，返回SSE流"""

    async def generate():
        try:
            # 加载数据集
            prompts = load_dataset(req.dataset_id, req.sample_count)
            total = len(prompts)

            # 确定要运行的组合
            targets = ['api', 'local'] if req.target == 'all' else [req.target]
            evaluators = ['keyword', 'llm_judge'] if req.evaluator == 'all' else [req.evaluator]

            combinations = [(t, e) for t in targets for e in evaluators]
            total_tasks = total * len(combinations)

            # 初始化统计
            stats = {
                "total": total_tasks,
                "completed": 0,
                "success_count": 0,  # 攻击成功（拦截失败）
                "fail_count": 0,     # 攻击失败（拦截成功）
                "error_count": 0,
                "results": []
            }

            # 发送初始状态
            init_data = {
                'type': 'init',
                'total': total_tasks,
                'prompts_count': total,
                'combinations': len(combinations)
            }
            yield f"data: {json.dumps(init_data)}\n\n"

            if total_tasks == 0:
                final_data = {
                    "type": "complete",
                    "total": 0,
                    "success_count": 0,
                    "fail_count": 0,
                    "error_count": 0,
                    "success_rate": 0,
                    "results": []
                }
                yield f"data: {json.dumps(final_data, ensure_ascii=False)}\n\n"
                return

            # 逐个评估
            for idx, prompt in enumerate(prompts):
                for target, evaluator in combinations:
                    try:
                        result = await evaluate_single_prompt(prompt, target, evaluator)
                        result["index"] = stats["completed"]

                        if result["is_success"]:
                            stats["success_count"] += 1
                        else:
                            stats["fail_count"] += 1

                        stats["results"].append(result)

                    except Exception as e:
                        stats["error_count"] += 1
                        result = {
                            "index": stats["completed"],
                            "prompt": prompt[:100],
                            "target_type": target,
                            "eval_type": evaluator,
                            "error": str(e),
                            "is_success": False
                        }
                        stats["results"].append(result)

                    stats["completed"] += 1

                    # 发送进度更新
                    progress_data = {
                        "type": "progress",
                        "completed": stats["completed"],
                        "total": stats["total"],
                        "success_count": stats["success_count"],
                        "fail_count": stats["fail_count"],
                        "error_count": stats["error_count"],
                        "progress_percent": round(stats["completed"] / stats["total"] * 100, 1),
                        "current_result": result
                    }
                    yield f"data: {json.dumps(progress_data, ensure_ascii=False)}\n\n"

                    # 小延迟避免过快
                    await asyncio.sleep(0.1)

            # 发送完成状态
            final_data = {
                "type": "complete",
                "total": stats["total"],
                "success_count": stats["success_count"],
                "fail_count": stats["fail_count"],
                "error_count": stats["error_count"],
                "success_rate": round(stats["success_count"] / stats["total"] * 100, 2) if stats["total"] > 0 else 0,
                "results": stats["results"][-20:]  # 只返回最后20条详细结果
            }
            yield f"data: {json.dumps(final_data, ensure_ascii=False)}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
