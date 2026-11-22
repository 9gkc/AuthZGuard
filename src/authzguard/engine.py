from __future__ import annotations

import os
import re
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import require_string
from .errors import ConfigurationError
from .models import Check, CheckResult
from .policy import Scope, enforce_request_policy

MAX_RESPONSE_BYTES = 65_536
REQUEST_TIMEOUT_SECONDS = 10


def parse_checks(document: dict) -> tuple[dict[str, str | None], tuple[Check, ...]]:
    identities_raw = document.get("identities", {})
    if not isinstance(identities_raw, dict):
        raise ConfigurationError("matrix.identities must be an object.")
    identities: dict[str, str | None] = {}
    for name, token_env in identities_raw.items():
        if not isinstance(name, str):
            raise ConfigurationError("Identity names must be strings.")
        if token_env is not None and not isinstance(token_env, str):
            raise ConfigurationError(f"matrix.identities.{name} must name an environment variable or be null.")
        if token_env is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env):
            raise ConfigurationError(
                f"matrix.identities.{name} must be a valid environment-variable name; inline tokens are prohibited."
            )
        identities[name] = token_env
    raw_checks = document.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        raise ConfigurationError("matrix.checks must contain at least one check.")
    checks: list[Check] = []
    for index, raw in enumerate(raw_checks):
        if not isinstance(raw, dict):
            raise ConfigurationError(f"matrix.checks[{index}] must be an object.")
        statuses = raw.get("expected_statuses")
        if not isinstance(statuses, list) or not statuses or not all(isinstance(item, int) for item in statuses):
            raise ConfigurationError(f"matrix.checks[{index}].expected_statuses must be a non-empty list of HTTP codes.")
        identity = require_string(raw.get("identity"), f"matrix.checks[{index}].identity")
        if identity not in identities:
            raise ConfigurationError(f"matrix.checks[{index}] references undefined identity: {identity}")
        checks.append(
            Check(
                identifier=require_string(raw.get("id"), f"matrix.checks[{index}].id"),
                target=require_string(raw.get("target"), f"matrix.checks[{index}].target").rstrip("/"),
                method=require_string(raw.get("method"), f"matrix.checks[{index}].method").upper(),
                path=require_string(raw.get("path"), f"matrix.checks[{index}].path"),
                identity=identity,
                expected_statuses=tuple(statuses),
                rationale=require_string(raw.get("rationale"), f"matrix.checks[{index}].rationale"),
            )
        )
    return identities, tuple(checks)


def _drain_limited(response) -> None:
    """Read and discard a bounded amount of response body to avoid unbounded memory use."""
    remaining = MAX_RESPONSE_BYTES
    while remaining > 0:
        chunk = response.read(min(4_096, remaining))
        if not chunk:
            break
        remaining -= len(chunk)


def verify(
    scope: Scope,
    matrix: dict,
    permit_authorized_public_targets: bool,
    transport: Callable = urlopen,
) -> list[CheckResult]:
    identities, checks = parse_checks(matrix)
    results: list[CheckResult] = []
    previous_request_at: float | None = None
    for check in checks:
        enforce_request_policy(scope, check.url, check.method, permit_authorized_public_targets)
        if previous_request_at is not None:
            remaining = (scope.minimum_interval_ms / 1000) - (time.monotonic() - previous_request_at)
            if remaining > 0:
                time.sleep(remaining)
        headers = {"User-Agent": "AuthZGuard/0.2 authorized-regression-check"}
        token_env = identities[check.identity]
        if token_env:
            token = os.environ.get(token_env)
            if not token:
                results.append(
                    CheckResult(
                        check.identifier,
                        check.url,
                        check.method,
                        check.identity,
                        check.expected_statuses,
                        None,
                        False,
                        f"Credential environment variable is unset: {token_env}",
                    )
                )
                continue
            headers["Authorization"] = f"Bearer {token}"
        request = Request(check.url, method=check.method, headers=headers)
        previous_request_at = time.monotonic()
        observed: int | None = None
        content_type: str | None = None
        note = ""
        try:
            with transport(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                observed = int(response.status)
                content_type = response.headers.get("Content-Type")
                _drain_limited(response)
        except HTTPError as error:
            observed = int(error.code)
            content_type = error.headers.get("Content-Type") if error.headers else None
            try:
                _drain_limited(error)
            except Exception:
                pass
        except URLError as error:
            note = f"Network error: {error.reason}"
        expected = ", ".join(str(code) for code in check.expected_statuses)
        passed = observed in check.expected_statuses
        if not note:
            if passed:
                note = f"Expected authorization boundary observed (HTTP {observed}; expected {expected})."
            else:
                note = (
                    f"Unexpected authorization response (HTTP {observed}; expected {expected}). "
                    "Review the route, role, and remediation evidence."
                )
        results.append(
            CheckResult(
                check.identifier,
                check.url,
                check.method,
                check.identity,
                check.expected_statuses,
                observed,
                passed,
                note,
                content_type,
            )
        )
    return results
