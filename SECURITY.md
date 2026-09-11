# Security policy

Attest handles compliance evidence, audit trails and the credentials that fetch them. Weaknesses in it are worth reporting, and we would rather hear about them privately first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository: **Security → Report a vulnerability**. It opens a private advisory that only the maintainers can see. Please do not open a public issue or pull request for anything you believe is exploitable.

You can expect an acknowledgement within three business days, a severity assessment and a fix plan within ten, and credit in the advisory and [CHANGELOG.md](CHANGELOG.md) if you want it. We ask for a reasonable embargo — up to 90 days, less once a fix ships — before public disclosure.

## What to include

- the version (`pip show attest`, the image tag, or the commit) and the mode (`production` / `sandbox`);
- how the installation is reached: direct, behind a proxy, which identity provider;
- steps to reproduce, ideally as `curl` commands or a pytest case against `create_app()`;
- what an attacker gains: which role or grant they start with and what they end up able to read, change or sign;
- any log or audit rows involved (redact secrets and real evidence).

## Supported versions

| Version | Status |
|---|---|
| `main` / 0.3.x | supported — fixes land here first |
| 0.2.x | security fixes only, for issues rated high or critical |
| 0.1.x (proof of concept, JSONL stores) | not supported |

## In scope

Anything that lets a caller act beyond their grants, read above their classification ceiling, alter or hide evidence or audit rows without breaking the chain, forge or re-attribute a signed decision, bypass a guardrail with a document or a prompt, or obtain a secret from the process, the config or a log. The MCP server, the collectors' handling of credentials, and the release pipeline (image, wheel, SBOM) are in scope too.

## Out of scope

Behaviour that is documented as a limit in [docs/security.md](docs/security.md) — per-process rate limits, no MFA on local password login, TLS terminated at your proxy — unless you have a way around the documented mitigation. Findings that require an already-compromised admin, database or host, or that only affect the sandbox's deliberately breakable demo, are not vulnerabilities in Attest.

## Hardening you can verify

Every release publishes a CycloneDX SBOM and passes `pip-audit --strict`; CI runs the audit on every push. The evidence and audit tables have no update path and are hash-chained; `GET /api/health` reports `chain_intact` and the sandbox's *Tamper* button shows what a broken chain looks like.
