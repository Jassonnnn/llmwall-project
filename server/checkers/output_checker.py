# -*- coding: utf-8 -*-
from typing import List, Dict, Any, Tuple
from guardrails import Guard

# 从注册表模块导入映射
from registry.validators import VALIDATOR_MAP, ON_FAIL_MAP

def output_check(text_to_check: str, checks: List[str], params: Dict[str, Dict[str, Any]], models: Dict[str, Any], tokenizers: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    使用 guardrails 动态配置并对输出文本执行一系列指定的检查和处理。

    :param text_to_check: (str) 需要进行检查和处理的文本。
    :param checks: (List[str]) 需要执行的检查模块名称列表。
    :param params: (Dict[str, Dict[str, Any]]) 一个字典，存放每个模块各自的参数。
    :return: (Tuple[bool, str, str]) 一个元组，包含三个值：
             - is_problematic (bool): 如果检测到问题，则为 True。
             - processed_text (str): 经过处理（例如，替换）后的文本。
             - message (str): 描述检查结果或错误的信息。
    """
    print(f"开始输出审核，待查文本: '{text_to_check[:50]}...'")
    print(f"请求的审核模块: {checks}")

    guard = Guard()
    
    try:
        # 自动化配置 Guard
        for check_name in checks:
            validator_class = VALIDATOR_MAP.get(check_name)
            if not validator_class:
                print(f"警告: 未找到名为 '{check_name}' 的检查模块，已跳过。")
                continue

            check_params = params.get(check_name, {}).copy()
            on_fail_str = check_params.pop("on_fail", "exception")
            on_fail_action = ON_FAIL_MAP.get(on_fail_str.lower())
            
            if not on_fail_action:
                print(f"警告: '{on_fail_str}' 是无效的 on_fail 动作，将使用默认的 'exception'。")
                on_fail_action = ON_FAIL_MAP["exception"]
            
            check_params['on_fail'] = on_fail_action
            
            # 如果模型存在，注入模型实例
            if check_name in models:
                check_params['model'] = models[check_name]
            print(f"配置检查: {check_name}，参数: {check_params}")
        
            validator_instance = validator_class(**check_params)
            guard.use(validator_instance)

        if guard.validators:
            # [MODIFIED] 为 validate 调用添加专门的异常捕获块
            try:
                outcome = guard.validate(text_to_check)
                print(f"验证结果: {outcome}")

                if outcome.validation_passed:
                    if len(outcome.validation_summaries) == 0:
                        print("Guardrails 输出验证通过，没有发现问题。")
                        return 1, "验证通过", text_to_check
                    else:
                        # 说明此时即使文本有问题也应用了fix
                        return 2, "检测到风险输入，已修正", outcome.validated_output
                else:
                    # 全部为noop时的操作
                    error_info=""
                    print(f"Guardrails 输入验证失败: {outcome.error}")
                    for validation in outcome.validation_summaries:
                        error_info += f"{validation.failure_reason}\n"
                        
                    print(error_info)
                    return 0, error_info, text_to_check
            
            except Exception as validation_error:
                # 此 except 块专门捕获因 on_fail='exception' 而抛出的验证失败异常
                print(f"Guardrails 验证在 'exception' 模式下失败: {validation_error}")
                return 3, f"{str(validation_error)}", text_to_check
        else:
            print("没有配置有效的检查器，跳过验证。")

    except Exception as e:
        print(f"Guardrails 执行期间发生意外错误: {e}")
        # [MODIFIED] 在发生异常时，返回原始文本
        return 3, f"输入检查时发生意外错误: {str(e)}", text_to_check
    
    finally:
        del guard
