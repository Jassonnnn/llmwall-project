guardrails

```bash
pip install guardrails-ai
```

fastapi

```base
pip install "fastapi[all]"
```

vllm 

```bash
export VLLM_WORKER_MULTIPROC_METHOD=spawn
python your_run_script.py
```

GLiNER模型的依赖库中CMake构建过程中**需要Boost 相关的头文件和库文件**。

```bash
pip install gliner[tokenizers] -U

sudo apt-get update
sudo apt-get install libboost-all-dev
```

llama_guard的main.py里面有个模型路径要修改

| 功能名称        | 方案1                                                        | 方案2                                                        |
| --------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 越狱/提示词注入 | Prompt-Guard-86M                                             |                                                              |
| 有害内容        | Llama-Guard-3-8B(支持约10种有害类型、占用16G左右显存)        |                                                              |
| 隐私泄露        | presidio框架+spacy的模型（对中文的支持较差)                  | GLiNER模型（支持多语言同时处理、效果很好、占用约2G显存）     |
| 敏感词/违规内容 | fuzzysearch模糊匹配（可发现错别字/分隔/拼写变体、词表大的情况下速度很慢） | 基于正则表达式的算法（只支持完全匹配，但是有很快的响应速度） |