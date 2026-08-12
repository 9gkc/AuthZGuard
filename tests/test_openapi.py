import unittest

from authzguard.engine import parse_checks
from authzguard.errors import ConfigurationError
from authzguard.openapi import validate_checks_against_openapi


class OpenApiTests(unittest.TestCase):
    def test_matrix_path_must_be_declared(self):
        matrix = {"identities": {"member": None}, "checks": [{"id": "admin", "target": "http://localhost:8080", "method": "GET", "path": "/v1/admin", "identity": "member", "expected_statuses": [403], "rationale": "restricted"}]}
        _, checks = parse_checks(matrix)
        validate_checks_against_openapi({"paths": {"/v1/admin": {"get": {}}}}, checks)
        with self.assertRaises(ConfigurationError):
            validate_checks_against_openapi({"paths": {"/v1/profile": {"get": {}}}}, checks)

