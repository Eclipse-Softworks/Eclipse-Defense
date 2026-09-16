import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("eclipse.config")


class ConfigLoader:
    _cache: Dict[str, Any] = {}
    _config_dir: Optional[Path] = None

    @classmethod
    def _get_config_dir(cls) -> Path:
        if cls._config_dir is None:
            # Get the parent directory of the scanner module
            scanner_dir = Path(__file__).parent.parent
            cls._config_dir = scanner_dir / "config"
        return cls._config_dir

    @classmethod
    def load_config(cls, config_name: str) -> Any:
        """Load and cache a named JSON configuration file from ``config/``.

        Invalid or missing configuration is deliberately surfaced to callers so a
        scan does not continue with an incomplete set of detection rules.
        """
        if config_name in cls._cache:
            logger.debug("Using cached config: %s", config_name)
            return cls._cache[config_name]

        config_path = cls._get_config_dir() / f"{config_name}.json"

        if not config_path.exists():
            logger.error("Configuration file not found: %s", config_path)
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            cls._cache[config_name] = config_data
            logger.debug("Loaded config: %s", config_name)
            return config_data
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in %s: %s", config_path, e)
            raise ValueError(f"Invalid JSON in {config_path}: {e}")

    @classmethod
    def get_value(cls, config_name: str, *keys: str) -> Any:
        """Return a nested configuration value, or ``None`` when its path is absent."""
        config_data = cls.load_config(config_name)

        current: Any = config_data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None

        return current

    @classmethod
    def clear_cache(cls) -> None:
        """Discard cached configurations, primarily for tests or config reloads."""
        cls._cache.clear()


# Convenience functions for specific config modules
def load_server_config() -> Any:
    return ConfigLoader.load_config("server_config")


def load_filter_config() -> Any:
    return ConfigLoader.load_config("filter_config")


def load_rce_config() -> Any:
    return ConfigLoader.load_config("rce_config")


def load_file_config() -> Any:
    return ConfigLoader.load_config("file_config")


def load_tls_config() -> Any:
    return ConfigLoader.load_config("tls_config")


def load_rate_limit_config() -> Any:
    return ConfigLoader.load_config("rate_limit_config")
