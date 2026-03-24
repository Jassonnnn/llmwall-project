import time
from fastapi import APIRouter

from app.config import GLOBAL_SETTINGS
from app.models import AttackRequest, AttackResponse, EvaluatorSingle, TargetSingle
from app.services.llm import call_llm_model
from app.services.evaluator import keyword_evaluate, llm_judge_evaluate

router = APIRouter()


@router.post("/test_scenario")
async def test_scenario(req: AttackRequest, target: TargetSingle, evaluator: EvaluatorSingle):
    start_time = time.time()

    llm_result = await call_llm_model(target, req.prompt)
    model_output = llm_result.get("content", "") if llm_result.get("ok") else llm_result.get("error_message", "")

    if not llm_result.get("ok"):
        is_attack_success = False
        reasoning = llm_result.get("error_message", "模型调用失败")
    else:
        if evaluator == 'llm_judge':
            is_attack_success, reasoning = await llm_judge_evaluate(req.prompt, model_output)
        else:
            is_attack_success, reasoning = keyword_evaluate(model_output)

    latency = round(time.time() - start_time, 2)

    return AttackResponse(
        target_type=target,
        eval_type=evaluator,
        response_content=model_output,
        is_success=is_attack_success,
        latency=latency,
        reasoning_trace=reasoning,
        model_name=GLOBAL_SETTINGS[target]["name"],
        status=llm_result.get("status", "ok"),
        error_code=llm_result.get("error_code"),
        error_message=llm_result.get("error_message"),
    )
