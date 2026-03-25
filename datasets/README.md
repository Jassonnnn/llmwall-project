# 红队测试数据集集合

## 概述
本目录包含用于AI安全、红队测试和对抗性测试研究的开源数据集。

## 攻击分类索引（本项目新增）

为支持前端“按攻击类型筛选评测”，本项目采用 sidecar 索引文件，不修改原始 CSV。

- 索引目录：`datasets/index/`
- 默认索引文件：`datasets/index/attack_category_index_v1.jsonl`
- 构建脚本：`scripts/build_attack_category_index.py`

构建示例：

```bash
conda run -n jb_demo python scripts/build_attack_category_index.py \
  --api-key <YOUR_API_KEY> \
  --model openrouter/deepseek/deepseek-chat \
  --max-concurrency 8
```

只标注一个数据集（调试）：

```bash
conda run -n jb_demo python scripts/build_attack_category_index.py \
  --dataset-id harmbench_text_test \
  --limit 20 \
  --api-key <YOUR_API_KEY>
```

分类标签包括：
- `direct_request`
- `roleplay_persona`
- `obfuscation_encoding`
- `contextual_injection`
- `multilingual_transformation`
- `compositional_hybrid`
- `mixed_all`（前端“全部”聚合选项）

## 已下载的数据集

### 1. HarmBench
**位置:** `HarmBench/`
**仓库:** https://github.com/centerforaisafety/HarmBench
**描述:** 用于自动化红队测试和对抗性鲁棒性测试的标准化评估框架。

**关键文件:**
- `data/behavior_datasets/harmbench_behaviors_text_all.csv` - 完整的文本行为数据集
- `data/behavior_datasets/harmbench_behaviors_text_test.csv` - 测试集
- `data/behavior_datasets/harmbench_behaviors_text_val.csv` - 验证集
- `data/behavior_datasets/harmbench_behaviors_multimodal_all.csv` - 多模态行为数据
- `data/behavior_datasets/extra_behavior_datasets/advbench_behaviors.csv` - AdvBench行为数据

**使用方法:**
```bash
cd HarmBench
pip install -r requirements.txt
python generate_test_cases.py --help
```

### 2. LLM-Attacks (AdvBench/GCG)
**位置:** `llm-attacks/`
**仓库:** https://github.com/llm-attacks/llm-attacks
**描述:** 贪婪坐标梯度（GCG）攻击的实现和AdvBench数据集。

**关键文件:**
- `data/advbench/harmful_behaviors.csv` - 520个有害行为提示词
- `data/advbench/harmful_strings.csv` - 目标有害字符串
- `data/transfer_expriment_behaviors.csv` - 迁移实验数据

**使用方法:**
```bash
cd llm-attacks
# 按照他们的README进行设置
```

### 3. JailbreakBench
**位置:** `jailbreakbench/`
**仓库:** https://github.com/JailbreakBench/jailbreakbench
**描述:** 用于评估LLM越狱攻击的基准测试。

**关键文件:**
- `examples/prompts/vicuna.json` - Vicuna模型提示词
- `examples/prompts/llama2.json` - Llama2模型提示词

**使用方法:**
```bash
cd jailbreakbench
pip install jailbreakbench
```

### 4. ToxicChat (已下载)
**位置:** `toxicchat/`
**来源:** https://huggingface.co/datasets/lmsys/toxic-chat
**描述:** 来自真实用户-聊天机器人交互的有毒内容数据。

**关键文件:**
- `toxicchat_toxic.csv` - 384条有毒对话数据

**提示词列:** `user_input`

### 5. SafeRLHF (已下载)
**位置:** `saferlhf/`
**来源:** https://huggingface.co/datasets/PKU-Alignment/PKU-SafeRLHF
**描述:** 北京大学安全RLHF数据集，包含不安全提示词和响应。

**关键文件:**
- `saferlhf_unsafe.csv` - 500条不安全提示词数据

**提示词列:** `prompt`

## 其他推荐数据集（未下载）

### 6. WildJailbreak (需申请访问)
**HuggingFace:** https://huggingface.co/datasets/allenai/wildjailbreak
**描述:** 野外越狱尝试和对抗性提示词（需要在HuggingFace申请访问权限）

### 7. Anthropic红队数据集
**HuggingFace:** https://huggingface.co/datasets/Anthropic/hh-rlhf
**描述:** 包含红队尝试的人类偏好数据
**下载:**
```python
from datasets import load_dataset
dataset = load_dataset("Anthropic/hh-rlhf")
```

### 8. LMSYS-Chat-1M
**HuggingFace:** https://huggingface.co/datasets/lmsys/lmsys-chat-1m
**描述:** 与25个LLM的100万真实对话
**下载:**
```python
from datasets import load_dataset
dataset = load_dataset("lmsys/lmsys-chat-1m")
```

## 快速开始示例

### 加载HarmBench行为数据:
```python
import pandas as pd

# 加载所有文本行为
df = pd.read_csv('HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv')
print(f"总行为数: {len(df)}")
print(df.head())
```

### 加载AdvBench有害行为:
```python
import pandas as pd

df = pd.read_csv('llm-attacks/data/advbench/harmful_behaviors.csv')
print(f"总有害行为数: {len(df)}")
print(df.head())
```

## 注意事项
- 所有数据集仅用于研究和教育目的
- 请遵循每个数据集的许可证和使用指南
- 确保对使用这些数据集的任何实验进行适当的伦理审查
- 某些数据集可能需要额外的API密钥或身份验证

## 安装要求

跨数据集的常见依赖项:
```bash
pip install pandas numpy torch transformers datasets huggingface_hub
```

有关特定数据集的要求，请参阅其各自的README文件。
