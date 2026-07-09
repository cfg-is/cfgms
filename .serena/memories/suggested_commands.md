# Suggested Commands

Run from repo root. Make is the entrypoint for nearly everything.

## Core dev loop
- `make test` — pre-flight validation; MUST pass before any commit/push (`go build` alone is NOT enough).
- `make build` — all binaries for current platform (steward, launcher, controller, cli, cert-manager, stdlib-modules).
- `make test-commit` — pre-commit gate = test + lint + lint-log-injection + check-license-headers + security-precommit + check-architecture + security-scan.
- `make test-complete` — story-completion gate; matches ALL required CI checks (adds cross-platform compile, Docker integration, E2E). Gap: native Windows/macOS builds are CI-only.

## Targeted
- `make test-unit`, `make test-integration`, `make test-fast`
- `make test-e2e-ci` (alias: `test-e2e-transport`), `test-e2e-controller`, `test-e2e-scenarios`, `test-e2e-fleet`
- `make lint`, `make lint-log-injection`
- `make security-scan` — trivy + deps(nancy) + gosec + staticcheck; blocking on critical/high.
- `make check-architecture` — central-provider violation detection.
- `make check-license-headers`, `make validate-providers`
- `make proto` — regen protobuf.

## Agent mode
- `make test-agent-complete` — Phase-2 validation when `CFGMS_AGENT_MODE=true`.

## Git hooks
- `./scripts/install-git-hooks.sh` — installs pre-commit (artifact detection) + pre-push (`make test`). Bypass `--no-verify` emergencies only.

## Env
- `CFGMS_TRANSPORT_USE_CERT_MANAGER=true` — never disable.

System: Linux; standard GNU coreutils (`grep`, `ls`, `find`, `sed` behave as on standard unix). `gh` CLI for all GitHub ops.
