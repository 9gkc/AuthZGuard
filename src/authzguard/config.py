from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigurationError


def load_document(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise ConfigurationError(f"Configuration file not found: {file_path}")
    try:
        raw = file_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw) if file_path.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise ConfigurationError(f"Cannot read {file_path}: {error}") from error
    if not isinstance(parsed, dict):
        raise ConfigurationError(f"{file_path} must contain an object at its root.")
    return parsed


def require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{name} must be a non-empty string.")
    return value.strip()

