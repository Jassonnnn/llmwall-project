"""
Configuration Management Module
"""
import yaml
import logging
import os
from typing import Dict, Any, Optional

class ConfigManager:
    """Configuration manager for the SQL Access Control system"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self._setup_logging()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as file:
                    config = yaml.safe_load(file)
                    return config or {}
            else:
                print(f"Warning: Config file {self.config_path} not found, using defaults")
                return self._get_default_config()
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "llm": {
                "model": "ollama/qwen2.5:latest",
                "temperature": 0.1,
                "max_tokens": 500,
                "timeout": 30
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }
    
    def _setup_logging(self):
        """Setup logging based on configuration"""
        log_config = self.config.get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO").upper())
        log_format = log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler()
            ]
        )
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration"""
        return self.config.get("llm", {
            "model": "ollama/qwen2.5:latest",
            "temperature": 0.1,
            "max_tokens": 500,
            "timeout": 30
        })
    
    def get_opa_url(self) -> str:
        """Get OPA URL"""
        return self.config.get("opa", {}).get("url", "http://localhost:8181")
    
    def get_opa_timeout(self) -> int:
        """Get OPA timeout"""
        return self.config.get("opa", {}).get("timeout", 10)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def update_config(self, updates: Dict[str, Any]):
        """Update configuration values"""
        self.config.update(updates)
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file, default_flow_style=False, allow_unicode=True)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

# Global config instance
config = ConfigManager()
