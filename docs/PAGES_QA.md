# AuthZGuard Pages — Local Verification Notes

## Verified state

The static project site was visually reviewed locally on 12 August 2026 before publication. The first viewport preserves readable contrast, a responsive primary navigation, direct links to the repository and responsible-use policy, and an explicit statement that the page does not execute remote scans.

The presentation-only configuration panel matches the published scope schema, including the required `I_HAVE_WRITTEN_AUTHORIZATION` attestation. The command preview uses `authzguard verify` with its real `--scope`, `--matrix`, `--attest`, and `--out` arguments. No external API calls, credentials, request execution, or server-side processing are included in the page.

GitHub's branch-based Pages settings for this repository offer only the repository root and `/docs` as publishing folders. The final publication layout therefore uses the verified static files in `/docs`; the original `/site` source folder remains as the focused development source.

## Publication checks still required

The GitHub Actions Pages workflow must complete successfully after the commit is pushed, and `https://9gkc.github.io/AuthZGuard/` must return the published page before the profile README link is considered final.
