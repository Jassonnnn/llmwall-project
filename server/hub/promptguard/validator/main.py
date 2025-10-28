from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)

from typing import Callable, List, Optional, Union, Any
import torch
from torch.nn.functional import softmax
from transformers import AutoTokenizer, AutoModelForSequenceClassification

@register_validator(name="xd810/promptguard",data_type="string")
class PromptGuard(Validator):
    MODEL_ID="/data/ljc/llmwall/model/Llama-Prompt-Guard-2-86M"
    # THRESHOLD=0.8
    
    def __init__(
        self,
        device: str = "cuda",
        on_fail: Optional[Callable] = None,
        model: Optional[AutoModelForSequenceClassification] = None,
        tokenizer: Optional[AutoTokenizer] = None,
        **kwargs,
    ):
        super().__init__(on_fail=on_fail, **kwargs)
        self.device = device
        self.tokenizer = tokenizer if tokenizer else AutoTokenizer.from_pretrained(PromptGuard.MODEL_ID)
        self.model = model if model else AutoModelForSequenceClassification.from_pretrained(PromptGuard.MODEL_ID,device_map="auto")
        # self.model = self.model.to(self.device)
    
    def validate(
        self,
        value: Union[str, List[str]],
        metadata: Optional[dict] = None,
    ) -> ValidationResult:
        # threshold = PromptGuard.THRESHOLD
        
        inputs = self.tokenizer(value, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        predicted_class_id = logits.argmax().item()
        result = self.model.config.id2label[predicted_class_id]

        
        if result == "benign":
            return PassResult(value=value, metadata=metadata)
        else:
            return FailResult(
                error_message="PromptGuard检测到越狱攻击/提示注入",
            )


    def _detect(
        self,
        prompts: Union[str, List[str]],
        threshold
    ) -> str:
        if isinstance(prompts, list):
            # print(f"WARN: PromptGuard._detect should be called with a string.")
            prompt = "".join(prompts)
        else:
            prompt = prompts
        probabilities=self._get_class_probabilities(text=prompt)
        
        # Evaluate the probability that a given string contains malicious jailbreak or prompt injection.
        # Appropriate for filtering dialogue between a user and an LLM.
        jailbreak_score=probabilities[0, 2].item()
        
        # Evaluate the probability that a given string contains any embedded instructions (malicious or benign).
        # Appropriate for filtering third party inputs (e.g., web searches, tool outputs) into an LLM.
        injection_score=probabilities[0, 1].item()
        
        result=""
        if jailbreak_score> threshold:
            result+=" JAILBREAK"
            print("JAILBREAK",jailbreak_score)
        
        if injection_score> threshold:
            result+=" INJECTION"
            print("INJECTION",injection_score)
        
        return result
            
            
            
    def _get_class_probabilities(self, text, temperature=1.0):
        """
        Evaluate the model on the given text with temperature-adjusted softmax.
        Note, as this is a DeBERTa model, the input text should have a maximum length of 512.
        
        Args:
            text (str): The input text to classify.
            temperature (float): The temperature for the softmax function. Default is 1.0.
            
        Returns:
            torch.Tensor: The probability of each class adjusted by the temperature.
        """
        # Encode the text
        inputs = self.tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
        # Get logits from the model
        with torch.no_grad():
            logits = self.model(**inputs).logits
        # Apply temperature scaling
        scaled_logits = logits / temperature
        # Apply softmax to get probabilities
        probabilities = softmax(scaled_logits, dim=-1)
        return probabilities