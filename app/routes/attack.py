from fastapi import APIRouter

from app.models import AttackGenRequest, AttackGenResponse, BatchAttackGenRequest
from app.services.attack_generator import (
    get_available_attack_methods,
    generate_adversarial_prompts,
    run_attack_evaluation,
    check_easyjailbreak_dependency,
)
from app.config import GLOBAL_SETTINGS

router = APIRouter()


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


@router.post("/generate_attacks", response_model=AttackGenResponse)
async def generate_attacks(req: AttackGenRequest):
    """
    生成对抗性提示词

    使用指定的攻击方法基于种子提示词生成对��性越狱提示词
    """
    # 优先使用请求中的配置，否则使用全局配置
    api_config = GLOBAL_SETTINGS.get("api", {})
    api_key = req.api_key or api_config.get("api_key", "")
    model_name = req.model_name or api_config.get("model", "gpt-4")
    api_base = req.api_base or api_config.get("api_base", "https://api.openai.com/v1")

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
        return AttackGenResponse(
            success=False,
            method=req.method,
            seed_prompt=req.seed_prompt,
            generated_count=0,
            prompts=[],
            error=result.get("error", "生成失败"),
            error_code=result.get("error_code"),
            note=result.get("note"),
        )

    return AttackGenResponse(
        success=True,
        method=result["method"],
        seed_prompt=result["seed_prompt"],
        generated_count=result["generated_count"],
        prompts=result["prompts"],
        error_code=result.get("error_code"),
        note=result.get("note"),
    )


@router.post("/attack_and_evaluate")
async def attack_and_evaluate(req: AttackGenRequest):
    """
    生成对抗性提示词并立即评估
    
    生成提示词后，使用指定的目标模型和评估器进行测试
    """
    # 首先生成对抗性提示词
    gen_result = await generate_attacks(req)
    
    if not gen_result.success:
        return {
            "success": False,
            "error": gen_result.error,
            "error_code": gen_result.error_code,
            "generation_result": gen_result,
            "evaluation_results": [],
        }
    
    # 提取生成的提示词
    prompts = [p["prompt"] for p in gen_result.prompts]
    
    # 进行评估
    eval_results = await run_attack_evaluation(
        prompts=prompts,
        target=req.target or "api",
        evaluator=req.evaluator or "keyword",
        eval_config={},
    )
    
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


@router.post("/batch_generate_attacks")
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
