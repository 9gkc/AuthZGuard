from __future__ import annotations

from .errors import ConfigurationError
from .models import Check


def validate_checks_against_openapi(document: dict, checks: tuple[Check, ...]) -> None:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ConfigurationError("OpenAPI document must contain a paths object.")
    for check in checks:
        operations = paths.get(check.path)
        if not isinstance(operations, dict) or check.method.lower() not in operations:
            raise ConfigurationError(f"Check {check.identifier} is not declared by the supplied OpenAPI document: {check.method} {check.path}")

