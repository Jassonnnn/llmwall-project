from fastapi import APIRouter, Depends

from app.auth import require_service_auth
from app.models import AttackGenRequest, AttackGenResponse, BatchAttackGenRequest
from app.services.attack_generator import (
    get_available_attack_methods,
    generate_adversarial_prompts,
    run_attack_evaluation,
    check_easyjailbreak_dependency,
)
from app.config import GLOBAL_SETTINGS
from app.errors import AppError

router = APIRouter()


ERROR_STATUS_MAP = {
    "MISSING_ATTACK_MODEL_CONFIG": 400,
    "MISSING_WHITEBOX_MODEL_CONFIG": 400,
    "AUTODAN_NLTK_RESOURCE_MISSING": 400,
    "DEPENDENCY_MISSING": 503,
    "REAL_ATTACK_EMPTY_RESULT": 502,
    "REAL_ATTACK_EXECUTION_FAILED": 500,
    "REAL_ATTACKER_NOT_IMPLEMENTED": 501,
    "UNKNOWN_METHOD": 400,
}


@router.get("/attack_methods")
async def list_attack_methods():
    """获取所有可用的攻击方法列表"""
    methods = get_available_attack_methods()
    dependency = check_easyjailbreak_dependency()
    return {
        "methods": methods,
        "count": len(methods),
        "easyjailbreak_available": dependency["available"],
        "dependency_reason": dependency["reason"] if not dependency["available"] else "",
    }


@router.post("/generate_attacks", response_model=AttackGenResponse, dependencies=[Depends(require_service_auth)])
async def generate_attacks(req: AttackGenRequest):
    """
    生成对抗性提示词

    使用指定的攻击方法基于种子提示词生成对��性越狱提示词
    """
    # Week-1 安全基线：攻击模型配置统一从服务端读取，不接受前端覆盖 key/model/base
    api_config = GLOBAL_SETTINGS.get("api", {})
    api_key = api_config.get("api_key", "")
    model_name = api_config.get("model", "gpt-4")
    api_base = api_config.get("api_base", "https://api.openai.com/v1")

    # 生成对抗性提示词
    result = await generate_adversarial_prompts(
        seed_prompt=req.seed_prompt,
        method=req.method,
        count=req.count,
        api_key=api_key,
        model_name=model_name,
        api_base=api_base,
    )

    if not result["success"]:
        error_code = result.get("error_code") or "ATTACK_GENERATION_FAILED"
        raise AppError(
            code=str(error_code),
            message=str(result.get("error", "攻击提示词生成失败。")),
            status_code=ERROR_STATUS_MAP.get(str(error_code), 400),
            details={
                "method": req.method,
                "generation_mode": result.get("generation_mode"),
                "note": result.get("note"),
            },
        )

    return AttackGenResponse(
        success=True,
        method=result["method"],
        seed_prompt=result["seed_prompt"],
        generated_count=result["generated_count"],
        prompts=result["prompts"],
        generation_mode=result.get("generation_mode"),
        error_code=result.get("error_code"),
        note=result.get("note"),
    )


@router.post("/attack_and_evaluate", dependencies=[Depends(require_service_auth)])
async def attack_and_evaluate(req: AttackGenRequest):
    """
    生成对抗性提示词并立即评估
    
    生成提示词后，使用指定的目标模型和评估器进行测试
    """
    # 首先生成对抗性提示词
    gen_result = await generate_attacks(req)
    
    # 提取生成的提示词
    prompts = [p["prompt"] for p in gen_result.prompts]
    
    # 进行评估
    try:
        eval_results = await run_attack_evaluation(
            prompts=prompts,
            target=req.target or "api",
            evaluator=req.evaluator or "keyword",
            eval_config={},
        )
    except Exception as exc:  # noqa: BLE001
        raise AppError(
            code="ATTACK_EVALUATION_FAILED",
            message=f"攻击评估失败: {exc}",
            status_code=500,
            details={"method": req.method},
        ) from exc
    
    return {
        "success": True,
        "generation_result": gen_result,
        "evaluation_results": eval_results,
        "summary": {
            "total": len(eval_results),
            "attack_success": sum(1 for r in eval_results if r.get("is_success", False)),
            "attack_failed": sum(1 for r in eval_results if not r.get("is_success", False)),
        },
    }


@router.post("/batch_generate_attacks", dependencies=[Depends(require_service_auth)])
async def batch_generate_attacks(req: BatchAttackGenRequest):
    """
    批量生成对抗性提示词
    
    对多个种子提示词批量生成对抗性提示词
    """
    api_config = GLOBAL_SETTINGS.get("api", {})
    api_key = api_config.get("api_key", "")
    model_name = api_config.get("model", "gpt-4")
    api_base = api_config.get("api_base", "https://api.openai.com/v1")
    
    all_results = []
    
    for seed in req.seed_prompts:
        result = await generate_adversarial_prompts(
            seed_prompt=seed,
            method=req.method,
            count=req.count_per_prompt,
            api_key=api_key,
            model_name=model_name,
            api_base=api_base,
        )
        all_results.append(result)
    
    # 汇总所有生成的提示词
    all_prompts = []
    for result in all_results:
        if result["success"]:
            all_prompts.extend([p["prompt"] for p in result["prompts"]])
    
    return {
        "success": True,
        "method": req.method,
        "total_seeds": len(req.seed_prompts),
        "total_generated": len(all_prompts),
        "results": all_results,
        "all_prompts": all_prompts,
    }
