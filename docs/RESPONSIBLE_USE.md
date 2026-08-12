# Responsible Use

AuthZGuard is designed for **defensive authorization regression testing**. Its controls reduce risk; they do not replace legal authorization, a written statement of work, a vulnerability-disclosure policy, or the judgment of the operator.

## Required before any network verification

| Requirement | Minimum evidence |
|---|---|
| System-owner authorization | A written approval or documented program rule that covers the target and the planned checks. |
| Scope reference | A change ticket, engagement ID, or authorization reference in the scope file. |
| Test identities | Accounts or tokens intentionally supplied for the engagement; never harvested credentials. |
| Safe target | A local, staging, sandbox, or otherwise explicitly approved environment. |
| Contact path | An agreed incident or remediation contact for unexpected results. |

The required command attestation is a deliberate friction point. It confirms that the human operator, not the program, accepts responsibility for ensuring authorization is in place.

## Prohibited use

Do not use AuthZGuard to identify targets, enumerate accounts, bypass authentication, access data beyond a declared test response, alter data, persist access, evade logging, or test a public target without written authorization. Do not use live customer or production data as an example dataset.

## Evidence and escalation

AuthZGuard reports route metadata and HTTP status outcomes only. If a result does not match the declared expectation, stop at that evidence threshold and follow the agreed disclosure or escalation process. A suitable report states the authorization reference, affected route, tested role label, expected boundary, observed status, business impact assessed by the owner, and a recommended corrective control.

## Safe implementation practices

Use dedicated test accounts with least privilege, keep tokens in secret stores or environment variables, set conservative rate limits at the network boundary, preserve audit logs, and rerun the same matrix after remediation. If a target cannot safely satisfy these conditions, do not run a network verification.

