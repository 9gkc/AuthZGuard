from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_document
from .engine import parse_checks, verify
from .errors import AuthZGuardError
from .openapi import validate_checks_against_openapi
from .policy import ATTESTATION, parse_scope
from .reports import summary, write_json, write_junit, write_markdown, write_sarif


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="authzguard", description="Low-impact authorization regression testing for permitted APIs only.")
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate scope and matrix documents without sending requests.")
    validate.add_argument("--scope", required=True)
    validate.add_argument("--matrix", required=True)
    validate.add_argument("--openapi")
    verify_command = commands.add_parser("verify", help="Run declared safe checks against an explicitly approved target.")
    verify_command.add_argument("--scope", required=True)
    verify_command.add_argument("--matrix", required=True)
    verify_command.add_argument("--openapi")
    verify_command.add_argument("--attest", required=True, help=f"Must exactly equal {ATTESTATION}.")
    verify_command.add_argument("--permit-authorized-public-targets", action="store_true")
    verify_command.add_argument("--out", default="reports")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        scope = parse_scope(load_document(args.scope))
        matrix = load_document(args.matrix)
        _, checks = parse_checks(matrix)
        if args.openapi:
            validate_checks_against_openapi(load_document(args.openapi), checks)
        if args.command == "validate":
            print("Configuration is valid. No network request was sent.")
            return 0
        if args.attest != ATTESTATION:
            raise AuthZGuardError(f"--attest must exactly equal {ATTESTATION}.")
        results = verify(scope, matrix, args.permit_authorized_public_targets)
        output = Path(args.out)
        output.mkdir(parents=True, exist_ok=True)
        write_json(results, output / "authzguard.json")
        write_markdown(results, output / "authzguard.md")
        write_junit(results, output / "authzguard.junit.xml")
        write_sarif(results, output / "authzguard.sarif")
        totals = summary(results)
        print(f"Completed {totals['total']} declared checks: {totals['passed']} passed, {totals['failed']} need review.")
        return 0 if totals["failed"] == 0 else 2
    except AuthZGuardError as error:
        print(f"AuthZGuard blocked the operation: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
