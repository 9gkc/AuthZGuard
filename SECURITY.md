# Security Policy

## Supported Version

The `main` branch is the supported development version while AuthZGuard is pre-1.0.

## Responsible Use

AuthZGuard is intended for **authorization regression testing** against APIs and environments that you own or have explicit permission to test. Always respect scope, rate limits, and data-handling policies of the target system.

## Reporting a Vulnerability

Please **do not** file public issues containing a proof of concept, tokens, target details, or vulnerability evidence.

1. Prefer GitHub’s private vulnerability-reporting channel for this repository when available.
2. Otherwise contact the repository owner through the account profile at https://github.com/9gkc.

Include:
- A concise description of the issue
- Reproduction steps against a local or synthetic sample
- Potential impact
- A proposed fix if known

The project treats the following as security-sensitive areas:
- Safe defaults
- Scope enforcement
- Credential handling
- Report sanitization
- CI safety

Reports are reviewed in good faith and handled as quickly as practical.
