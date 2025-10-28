# -*- coding: utf-8 -*-
from typing import Iterator, Dict, Any, List
# 导入您现有的、处理完整文本块的检查函数
from .output_checker import output_check

def stream_output_check(
    stream: Iterator[str], 
    checks: List[str], 
    params: Dict[str, Dict[str, Any]],
    models: Dict[str, Any],      # [MODIFIED] 新增 models 参数
    tokenizers: Dict[str, Any]   # [MODIFIED] 新增 tokenizers 参数
) -> Iterator[str]:
    """
    一个生成器函数，它接收一个文本流，在内部进行缓冲和分块检查，
    然后逐块地产生（yield）一个经过安全处理的文本流。
    此版本已更新，以匹配新的 output_checker 逻辑。
    """
    
    buffer = ""
    delimiters = (".", "!", "?", "\n", "。", "！", "？")

    for chunk in stream:
        buffer += chunk
        
        while any(d in buffer for d in delimiters):
            split_point = -1
            for d in delimiters:
                pos = buffer.find(d)
                if pos != -1 and (split_point == -1 or pos < split_point):
                    split_point = pos

            if split_point != -1:
                sentence_to_check = buffer[:split_point + 1]
                buffer = buffer[split_point + 1:]

                # [MODIFIED] 调用更新后的 output_check 函数，并传递模型参数
                status_code, message, processed_text = output_check(
                    text_to_check=sentence_to_check,
                    checks=checks,
                    params=params,
                    models=models,
                    tokenizers=tokenizers
                )

                # [MODIFIED] 根据新的返回逻辑处理结果
                # status_code 为 0 (noop fail) 或 True (exception) 时，记录问题
                if status_code == 0 or status_code is True:
                     print(f"流式检测发现问题: {message}")

                # 无论结果如何，都产生（yield）返回的文本块，
                # 因为 output_check 已经被设计为在所有情况下都返回正确的文本。
                yield processed_text
            else:
                break

    # 处理缓冲区中可能剩余的最后一部分文本
    if buffer:
        status_code, message, processed_text = output_check(
            text_to_check=buffer,
            checks=checks,
            params=params,
            models=models,
            tokenizers=tokenizers
        )
        if status_code == 0 or status_code is True:
            print(f"流式检测发现问题 (末尾部分): {message}")
            
        yield processed_text
