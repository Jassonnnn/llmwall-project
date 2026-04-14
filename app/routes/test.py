import time
from fastapi import APIRouter, Depends

from app.auth import require_service_auth
from app.config import GLOBAL_SETTINGS
from app.models import AttackRequest, AttackResponse, EvaluatorSingle, TargetSingle
from app.services.llm import call_llm_model
from app.services.evaluator import keyword_evaluate, llm_judge_evaluate

router = APIRouter()


@router.post("/test_scenario", dependencies=[Depends(require_service_auth)])
async def test_scenario(req: AttackRequest, target: TargetSingle, evaluator: EvaluatorSingle):
    start_time = time.time()

    llm_result = await call_llm_model(target, req.prompt)
    model_output = llm_result.get("content", "") if llm_result.get("ok") else llm_result.get("error_message", "")

    if not llm_result.get("ok"):
        is_attack_success = False
        reasoning = llm_result.get("error_message", "模型调用失败")
        result_status = llm_result.get("status", "error")
        result_error_code = llm_result.get("error_code")
        result_error_message = llm_result.get("error_message")
    else:
        if evaluator == 'llm_judge':
            judge_result = await llm_judge_evaluate(req.prompt, model_output)
            is_attack_success = bool(judge_result.get("is_unsafe", False))
            reasoning = str(judge_result.get("summary", ""))
            result_status = "ok" if judge_result.get("ok", False) else "error"
            if judge_result.get("fallback_used"):
                result_error_code = None
                result_error_message = None
            else:
                result_error_code = judge_result.get("error_code")
                result_error_message = judge_result.get("error_message")
        else:
            is_attack_success, reasoning = keyword_evaluate(model_output)
            result_status = llm_result.get("status", "ok")
            result_error_code = llm_result.get("error_code")
            result_error_message = llm_result.get("error_message")

    latency = round(time.time() - start_time, 2)

    return AttackResponse(
        target_type=target,
        eval_type=evaluator,
        response_content=model_output,
        is_success=is_attack_success,
        latency=latency,
        reasoning_trace=reasoning,
        model_name=GLOBAL_SETTINGS[target]["name"],
        status=result_status,
        error_code=result_error_code,
        error_message=result_error_message,
    )
