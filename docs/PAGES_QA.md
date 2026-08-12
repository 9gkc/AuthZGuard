# AuthZGuard Pages — Local Verification Notes

## Verified state

The static project site was visually reviewed locally on 12 August 2026 before publication. The first viewport preserves readable contrast, a responsive primary navigation, direct links to the repository and responsible-use policy, and an explicit statement that the page does not execute remote scans.

The presentation-only configuration panel matches the published scope schema, including the required `I_HAVE_WRITTEN_AUTHORIZATION` attestation. The command preview uses `authzguard verify` with its real `--scope`, `--matrix`, `--attest`, and `--out` arguments. No external API calls, credentials, request execution, or server-side processing are included in the page.

GitHub's branch-based Pages settings for this repository offer only the repository root and `/docs` as publishing folders. The final publication layout therefore uses the verified static files in `/docs`; the original `/site` source folder remains as the focused development source.

On 12 August 2026, the repository settings confirmed that Pages was disabled and offered `Deploy from a branch`. The approved final selection is `main` with `/docs`; the settings were opened from `https://github.com/9gkc/AuthZGuard/settings/pages` for final activation.

The source selection was saved successfully. GitHub now reports that the project site is being built from `/docs` on `main`, with HTTPS enforced for the default `9gkc.github.io` domain. The public URL must be checked after the build becomes available.

## Publication result

The GitHub Pages build completed successfully, and `https://9gkc.github.io/AuthZGuard/` was opened and reviewed on 12 August 2026. It loads the verified static guide over HTTPS and retains the no-remote-scan notice, authorized-use boundary, local-installation link, configuration preview, and remediation-report preview.

## Publication checks still required

The GitHub Actions Pages workflow must complete successfully after the commit is pushed, and `https://9gkc.github.io/AuthZGuard/` must return the published page before the profile README link is considered final.
