import unittest
from unittest.mock import patch

from authzguard.errors import ScopeViolation
from authzguard.policy import ATTESTATION, enforce_request_policy, parse_scope


def scope_for(target: dict) -> object:
    return parse_scope({"authorization": {"attestation": ATTESTATION, "reference": "ENG-2026-001"}, "targets": [target]})


class PolicyTests(unittest.TestCase):
    def test_localhost_is_permitted_with_explicit_scope(self):
        scope = scope_for({"base_url": "http://localhost:8080", "allow_private_network": False})
        enforce_request_policy(scope, "http://localhost:8080/v1/profile", "GET", False)

    def test_non_safe_method_is_blocked(self):
        scope = scope_for({"base_url": "http://localhost:8080"})
        with self.assertRaises(ScopeViolation):
            enforce_request_policy(scope, "http://localhost:8080/v1/profile", "POST", False)

    def test_unlisted_target_is_blocked(self):
        scope = scope_for({"base_url": "http://localhost:8080"})
        with self.assertRaises(ScopeViolation):
            enforce_request_policy(scope, "http://localhost:9090/v1/profile", "GET", False)

    def test_public_target_requires_two_explicit_permissions(self):
        scope = scope_for({"base_url": "https://8.8.8.8", "allow_authorized_public_target": True})
        with self.assertRaises(ScopeViolation):
            enforce_request_policy(scope, "https://8.8.8.8/v1/profile", "GET", False)
        enforce_request_policy(scope, "https://8.8.8.8/v1/profile", "GET", True)

    def test_dns_resolution_to_private_address_is_blocked_without_scope_approval(self):
        scope = scope_for({"base_url": "https://approved.internal", "allow_private_network": False})
        resolution = [(None, None, None, None, ("10.20.30.40", 0))]
        with patch("authzguard.policy.socket.getaddrinfo", return_value=resolution):
            with self.assertRaises(ScopeViolation):
                enforce_request_policy(scope, "https://approved.internal/v1/profile", "GET", False)
