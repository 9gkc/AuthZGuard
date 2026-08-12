from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from .models import CheckResult


def summary(results: list[CheckResult]) -> dict:
    return {"total": len(results), "passed": sum(item.passed for item in results), "failed": sum(not item.passed for item in results)}


def write_json(results: list[CheckResult], path: str | Path) -> None:
    Path(path).write_text(json.dumps({"generated_at": datetime.now(UTC).isoformat(), "summary": summary(results), "results": [item.to_dict() for item in results]}, indent=2), encoding="utf-8")


def write_markdown(results: list[CheckResult], path: str | Path) -> None:
    totals = summary(results)
    lines = ["# AuthZGuard verification report", "", f"Generated: {datetime.now(UTC).isoformat()}", "", f"**Passed:** {totals['passed']}/{totals['total']}", "", "| Check | Identity | Expected | Observed | Result |", "|---|---|---:|---:|---|"]
    for item in results:
        observed = str(item.observed_status) if item.observed_status is not None else "network error"
        result = "PASS" if item.passed else "REVIEW"
        lines.append(f"| `{item.identifier}` | `{item.identity}` | `{', '.join(map(str, item.expected_statuses))}` | {observed} | {result} |")
    lines.extend(["", "## Evidence policy", "AuthZGuard records only request metadata, status codes, and response content type. It intentionally does not capture response bodies, tokens, or secrets."])
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_junit(results: list[CheckResult], path: str | Path) -> None:
    suite = Element("testsuite", name="authzguard", tests=str(len(results)), failures=str(sum(not item.passed for item in results)))
    for item in results:
        test_case = SubElement(suite, "testcase", name=item.identifier, classname="authorization")
        if not item.passed:
            failure = SubElement(test_case, "failure", message=item.note)
            failure.text = f"Expected {item.expected_statuses}; observed {item.observed_status}."
    Path(path).write_bytes(tostring(suite, encoding="utf-8", xml_declaration=True))


def write_sarif(results: list[CheckResult], path: str | Path) -> None:
    findings = []
    for item in results:
        if not item.passed:
            findings.append({"ruleId": "AUTHZGUARD001", "level": "warning", "message": {"text": item.note}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.url}}}], "properties": {"check": item.identifier, "observed_status": item.observed_status, "expected_statuses": list(item.expected_statuses)}})
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "AuthZGuard", "rules": [{"id": "AUTHZGUARD001", "shortDescription": {"text": "Authorization boundary did not match the declared policy."}}]}}, "results": findings}]}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

