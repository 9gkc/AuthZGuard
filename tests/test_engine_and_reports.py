import tempfile
import unittest
from pathlib import Path

from authzguard.engine import verify
from authzguard.engine import parse_checks
from authzguard.errors import ConfigurationError
from authzguard.policy import ATTESTATION, parse_scope
from authzguard.reports import write_json, write_junit, write_markdown, write_sarif


class FakeResponse:
    status = 403
    headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def fake_transport(*_, **__):
    return FakeResponse()


class EngineAndReportTests(unittest.TestCase):
    def test_inline_credential_values_are_rejected(self):
        with self.assertRaises(ConfigurationError):
            parse_checks({"identities": {"analyst": "Bearer should-not-be-here"}, "checks": []})

    def test_declared_check_generates_non_body_evidence_reports(self):
        scope = parse_scope({"authorization": {"attestation": ATTESTATION, "reference": "ENG-2026-001"}, "targets": [{"base_url": "http://localhost:8080"}]})
        matrix = {"identities": {"member": None}, "checks": [{"id": "member-cannot-read-admin", "target": "http://localhost:8080", "method": "GET", "path": "/v1/admin", "identity": "member", "expected_statuses": [401, 403], "rationale": "Administrative data must remain restricted."}]}
        results = verify(scope, matrix, False, transport=fake_transport)
        self.assertTrue(results[0].passed)
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            write_json(results, directory / "report.json")
            write_markdown(results, directory / "report.md")
            write_junit(results, directory / "report.xml")
            write_sarif(results, directory / "report.sarif")
            self.assertIn("member-cannot-read-admin", (directory / "report.md").read_text())
            self.assertNotIn("response body", (directory / "report.json").read_text().lower())
            self.assertTrue((directory / "report.sarif").is_file())
