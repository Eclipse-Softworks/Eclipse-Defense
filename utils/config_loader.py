import json
import os
from pathlib import Path


class ConfigLoader:    
    _cache = {}
    _config_dir = None
    
    @classmethod
    def _get_config_dir(cls):
        if cls._config_dir is None:
            # Get the parent directory of the scanner module
            scanner_dir = Path(__file__).parent.parent
            cls._config_dir = scanner_dir / "config"
        return cls._config_dir
    
    @classmethod
    def load_config(cls, config_name):
        if config_name in cls._cache:
            return cls._cache[config_name]
        
        config_path = cls._get_config_dir() / f"{config_name}.json"
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            cls._cache[config_name] = config_data
            return config_data
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {config_path}: {e}")
    
    @classmethod
    def get_value(cls, config_name, *keys):
        config_data = cls.load_config(config_name)
        
        current = config_data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        
        return current
    
    @classmethod
    def clear_cache(cls):
        cls._cache.clear()


# Convenience functions for specific config modules
def load_server_config():
    return ConfigLoader.load_config("server_config")


def load_filter_config():
    return ConfigLoader.load_config("filter_config")


def load_rce_config():
    return ConfigLoader.load_config("rce_config")


def load_file_config():
    return ConfigLoader.load_config("file_config")


def load_tls_config():
    return ConfigLoader.load_config("tls_config")
