from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import require_string
from .errors import ConfigurationError, ScopeViolation

ATTESTATION = "I_HAVE_WRITTEN_AUTHORIZATION"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class TargetRule:
    base_url: str
    allow_private_network: bool
    allow_authorized_public_target: bool


@dataclass(frozen=True)
class Scope:
    reference: str
    targets: tuple[TargetRule, ...]
    minimum_interval_ms: int

    def rule_for(self, url: str) -> TargetRule:
        for rule in self.targets:
            if within_base_url(url, rule.base_url):
                return rule
        raise ScopeViolation(f"Target is not listed in the approved scope: {url}")


def normalise_base_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError(f"Invalid target URL: {url}")
    return url.rstrip("/")


def within_base_url(candidate: str, base_url: str) -> bool:
    candidate_parts = urlparse(candidate)
    base_parts = urlparse(base_url)
    if (candidate_parts.scheme, candidate_parts.netloc) != (base_parts.scheme, base_parts.netloc):
        return False
    base_path = base_parts.path.rstrip("/")
    return not base_path or candidate_parts.path == base_path or candidate_parts.path.startswith(base_path + "/")


def parse_scope(document: dict) -> Scope:
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise ConfigurationError("scope.authorization must be an object.")
    if authorization.get("attestation") != ATTESTATION:
        raise ConfigurationError(f"scope.authorization.attestation must equal {ATTESTATION}.")
    reference = require_string(authorization.get("reference"), "scope.authorization.reference")
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ConfigurationError("scope.targets must contain at least one approved target.")
    rules: list[TargetRule] = []
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            raise ConfigurationError(f"scope.targets[{index}] must be an object.")
        rules.append(
            TargetRule(
                base_url=normalise_base_url(require_string(target.get("base_url"), f"scope.targets[{index}].base_url")),
                allow_private_network=bool(target.get("allow_private_network", False)),
                allow_authorized_public_target=bool(target.get("allow_authorized_public_target", False)),
            )
        )
    request_policy = document.get("request_policy", {})
    if not isinstance(request_policy, dict):
        raise ConfigurationError("scope.request_policy must be an object when supplied.")
    minimum_interval_ms = request_policy.get("minimum_interval_ms", 250)
    if not isinstance(minimum_interval_ms, int) or not 100 <= minimum_interval_ms <= 60_000:
        raise ConfigurationError("scope.request_policy.minimum_interval_ms must be an integer from 100 to 60000.")
    return Scope(reference=reference, targets=tuple(rules), minimum_interval_ms=minimum_interval_ms)


def host_resolves_to_private_address(host: str) -> bool:
    """Block DNS rebinding toward loopback, private, or link-local addresses."""
    try:
        addresses = {record[4][0] for record in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ScopeViolation(f"Cannot resolve target host: {host}") from error
    for address in addresses:
        candidate = ipaddress.ip_address(address)
        if candidate.is_loopback or candidate.is_private or candidate.is_link_local:
            return True
    return False


def enforce_request_policy(scope: Scope, url: str, method: str, permit_authorized_public_targets: bool) -> TargetRule:
    method = method.upper()
    if method not in SAFE_METHODS:
        raise ScopeViolation(f"{method} is blocked. AuthZGuard only permits {', '.join(sorted(SAFE_METHODS))} requests.")
    rule = scope.rule_for(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_local = host.lower() == "localhost"
    try:
        address = ipaddress.ip_address(host)
        is_local = address.is_loopback
        is_private = address.is_private or address.is_link_local
    except ValueError:
        is_private = host_resolves_to_private_address(host)
    if parsed.scheme != "https" and not is_local:
        raise ScopeViolation("Only HTTPS is allowed for non-local targets.")
    if is_private and not is_local and not rule.allow_private_network:
        raise ScopeViolation("Private or link-local targets require allow_private_network: true in the approved scope.")
    if not is_local and not is_private:
        if not (rule.allow_authorized_public_target and permit_authorized_public_targets):
            raise ScopeViolation("Public targets require both scope approval and --permit-authorized-public-targets.")
    return rule
