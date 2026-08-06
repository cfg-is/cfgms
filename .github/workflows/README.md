# GitHub Actions Workflows

This directory contains automated CI/CD workflows for CFGMS. All workflows are active for the public repository.

## Required Status Checks (develop ruleset)

These are the exact context names configured as required checks in the develop
branch ruleset. All ten must pass (or be satisfied by a stub) before a PR can
merge. Verify this list against the ruleset rather than trusting it:

```bash
gh api repos/cfg-is/cfgms/rulesets/11647684 \
  --jq '.rules[]|select(.type=="required_status_checks").parameters.required_status_checks[].context'
```

| Context name | Source workflow |
|---|---|
| `unit-tests` | `test-suite.yml` (PR/merge_group) or `documentation.yml` stub |
| `integration-tests` | `test-suite.yml` (PR/merge_group) or `documentation.yml` stub |
| `Build Gate` | `cross-platform-build.yml` or `documentation.yml` stub |
| `security-deployment-gate` | `production-gates.yml` or `documentation.yml` stub |
| `Controller Integration Tests (Linux)` | `production-gates.yml` or `documentation.yml` stub |
| `zizmor` | `zizmor.yml` — no stub |
| `CLA signature check` | `cla-check.yml` — no stub |
| `frontend-checks` | `frontend-ci.yml` — no stub |
| `trivy-scan` | `security-scan.yml` or `documentation.yml` stub |
| `CodeQL` | `codeql-analysis.yml` or `codeql-stub.yml` |

Docs-only PRs are served by stub jobs in `documentation.yml` (paths-filtered to
`docs/**`, `*.md`, `.claude/**`) for the seven contexts that have one. The other
three — `zizmor`, `CLA signature check` and `frontend-checks` — carry no path
filter and no stub: their real job runs on every `pull_request` and every
`merge_group`. `frontend-ci.yml` deliberately has no workflow-level paths filter
and detects `web/**` changes inside the job instead, because a required check
that never creates a check run blocks the merge queue indefinitely.

---

## Active Workflows

### Build & Test

#### `test-suite.yml` — Test Suite Validation

**Triggers**: Pull Requests to main/develop, Merge Group, push to main, Manual dispatch

**Jobs**:
- `unit-tests` — `make check-stdlib-completeness` (ADR-016 clause 6 gate) then `make test` with `CFGMS_TEST_INTEGRATION=0`; every PR; emits the `unit-tests` required context
- `integration-tests` — `make test-production-critical` on self-hosted Linux (hermetic container); needs `unit-tests`; emits the `integration-tests` required context
- `cross-feature-tests` / `production-readiness` / `synthetic-monitoring` — workflow_dispatch `all`/`full` level only

**Runtime**: unit-tests ~5 min; integration-tests ~10–15 min (self-hosted)

---

#### `cross-platform-build.yml` — Cross-Platform Build Validation

**Triggers**: Pull Requests to main/develop, Merge Group, Manual dispatch

**Jobs**:
- `cross-compile-check` — `make build-cross-validate` for all targets (Linux/macOS/Windows AMD64+ARM64)
- `native-builds` — matrix: Linux (ubuntu-latest), macOS (macos-latest), Windows (windows-latest); each runs `make build` + unit tests with `-race` on Linux/macOS; emits `Controller Integration Tests (Linux)` context via the Linux leg
- `integration-tests` — Docker-infrastructure integration tests; Linux only

**Coverage note**: the Linux `native-builds` leg (`go test -race -short ./pkg/... ./features/...`) is the only per-PR Linux race-detector sweep of the full module tree. Do not remove it.

**Runtime**: ~11–15 min (measured 2026-07-13; dominated by native-builds matrix)

---

#### `fleet-e2e.yml` — Fleet E2E Tests

**Triggers**: Merge Group only (not pull_request — moved off PR per #2550 audit)

**Jobs**: `fleet-e2e-tests` — runs fleet end-to-end scenario tests; emits the `fleet-e2e-tests` context (required check in develop ruleset via `documentation.yml` stub on docs PRs)

**Runtime**: ~10–20 min

---

### Security

#### `security-scan.yml` — Security Scanning Workflow

**Triggers**: Pull Requests, Merge Group, push to main/develop, Daily schedule (3 AM UTC)

**What it does**:
- Trivy filesystem scan (emits `trivy-scan` required context)
- gosec — Go security static analysis
- staticcheck — advanced Go static analysis
- nancy — Go dependency vulnerability checking
- Uploads SARIF to GitHub Security tab
- Emits `security-deployment-gate` context

**Runtime**: ~2–5 min (measured 2026-07-13: ~2.5 min)

---

#### `codeql-analysis.yml` — CodeQL Security Analysis

**Triggers**: Pull Requests (Go/CodeQL/web paths), Merge Group, push to main/develop, Weekly schedule

**What it does**:
- Semantic code analysis for Go (with `cfg-is/cfgms-go-extensions` data-extension pack) and `javascript-typescript` (web SPA)
- Uploads findings to GitHub Security tab
- Emits the `CodeQL` required context for Go and web PRs

**Runtime**: ~5–10 min

---

#### `codeql-stub.yml` — CodeQL Stub

**Triggers**: Pull Requests that touch no Go code, CodeQL config, or web sources (exact complement of `codeql-analysis.yml`'s path filter)

**What it does**: Emits `CodeQL` as success for docs-only / scripts-only / yaml-only PRs so the required check is satisfied without running the full analysis. Does NOT trigger on `merge_group` (the real analysis is authoritative there).

**Runtime**: <1 min

---

#### `codeql-pack-publish.yml` — Publish CodeQL Extension Pack

**Triggers**: push to main/develop touching `.github/codeql/extensions/**`, Manual dispatch

**What it does**: Publishes the `cfg-is/cfgms-go-extensions` CodeQL data-extension pack to ghcr.io. Required because `codeql-action`'s `packs:` input rejects local-path references; the pack must be registry-published for `codeql-analysis.yml` to consume it. Idempotent: re-publishing the same version is a no-op.

---

#### `dast-scan.yml` — OWASP ZAP DAST Scan

**Triggers**: Manual dispatch (`workflow_dispatch`), Weekly schedule (Sunday 03:00 UTC)

**What it does**: Builds the controller image, starts it with flatfile storage (no external DB), production auth posture (no `CFGMS_ENABLE_TEST_ENDPOINTS`/`CFGMS_SEED_TEST_TOKENS`), and runs an OWASP ZAP baseline scan (spider + passive rules) against `https://localhost:8080` — the single listener serving both the REST API and the embedded SPA. Results uploaded as the `zap-dast-report` artifact. Advisory only, not a required check.

**Rules file**: `.zap/rules.tsv` — add IGNORE entries only for confirmed false positives; see `docs/development/security-workflow-guide.md` §6.

**Runtime**: ~15–25 min (dominated by Docker build + ZAP spider)

---

#### `docker-security.yml` — Docker Security Scanning

**Triggers**: Pull Requests, push to main/develop, Manual dispatch

**What it does**: Scans container images for vulnerabilities, validates Dockerfile best practices, generates SBOM.

**Runtime**: ~3–5 min

---

#### `zizmor.yml` — zizmor

**Triggers**: Pull Requests to main/develop, Merge Group, Manual dispatch

**What it does**: Runs [zizmor](https://github.com/zizmorcore/zizmor) GitHub Actions security audit. Emits the `zizmor` required context. `continue-on-error: true` on the scan step so findings are uploaded as SARIF without blocking; the required-check gate is the enforcing mechanism.

**Runtime**: <1 min (measured 2026-07-13: ~20 s)

---

#### `scorecard.yml` — OpenSSF Scorecard

**Triggers**: push to `develop`, Weekly schedule (Saturday 05:41 UTC), Manual dispatch

**What it does**: Runs the [OpenSSF Scorecard](https://github.com/ossf/scorecard) supply-chain
security analysis against the `develop` branch. Measures 18 checks (token permissions, branch
protection, code review, dependency pinning, SAST, fuzzing, signed releases, and more). Publishes
results to the OSSF public dashboard (`publish_results: true`) and uploads SARIF to the GitHub
Security tab. Uses the default `GITHUB_TOKEN`; Branch-Protection under-reports without a
founder-provisioned `SCORECARD_READ_TOKEN` fine-grained PAT (accepted gap — see
`docs/development/security-workflow-guide.md §7`). NOT a required PR check.

**Baseline score**: 6.3/10 (2026-07-24, commit fa292575, Scorecard CLI v5.5.0 — see §7 of the
security workflow guide for the full per-check gap list).

**Runtime**: ~5–10 min

---

#### `dependency-pin-check.yml` — Dependency Pin Freshness Check

**Triggers**: Weekly schedule (Wednesday 09:00 UTC), Manual dispatch, Pull Requests touching Dockerfiles/workflows/Makefile

**Jobs**:
- `denylist-check` — hard-fails any PR that pins a known-compromised Trivy version (CVE-2026-33634)
- `check-tool-versions` — schedule/manual only; checks gosec, staticcheck, gitleaks, nancy, trufflehog, trivy, go-licenses, golangci-lint, and Go toolchain against latest releases; opens a GitHub issue if outdated

---

### Compliance & Quality

#### `production-gates.yml` — Production Risk Gates

**Triggers**: Pull Requests, Merge Group, push to main/develop, Manual dispatch

**What it does**:
- Emits `Build Gate` and `security-deployment-gate` required contexts
- Cross-platform integration tests and production readiness verification

---

#### `license-check.yml` — License Compliance

**Triggers**: Pull Requests, push to main/develop

**What it does**: Validates all dependencies have compatible licenses; generates license report and SBOM.

**Runtime**: ~2–3 min

---

#### `cla-check.yml` — CLA Check

**Triggers**: `pull_request_target` (opened/synchronize/reopened/ready_for_review), Merge Group

**What it does**: Verifies the PR author has signed the CFGMS CLA v2.0 by appearing in `CONTRIBUTORS.md`. Posts a sign-in comment on unsigned PRs. Bot accounts and maintainers (`jrdnr`, `cfg-agent`) are bypassed. Merge Group trigger is a no-op pass-through (authorship was verified at PR time). Emits `CLA signature check` required context.

**Runtime**: <1 min

---

#### `label-decommission-gate.yml` — Label Decommission Gate

**Triggers**: Pull Requests to main/develop

**What it does**: Asserts that no executable code paths reference decommissioned `pipeline:*` or `agent:*` labels (all work-queue state is now in GitHub Projects V2). Also asserts no raw `gh issue create` calls outside the sanctioned `pipeline-helper.sh` paths.

**Runtime**: <1 min

---

### Documentation

#### `documentation.yml` — Documentation Validation

**Triggers**: Pull Requests touching `docs/**`, `*.md`, `.claude/**` (and a few other non-code paths); push to main (same paths); Merge Group; Manual dispatch

**Jobs**:
- `validate-claude-md` — verifies CLAUDE.md contains required structural concepts and that all internal file references resolve; runs on `pull_request` and `push` (blocking)
- `validate-roadmap` — checks `docs/product/roadmap.md` format; runs on `pull_request` and `push`
- `documentation-summary` — step summary aggregating both jobs
- Stub jobs: `unit-tests`, `integration-tests`, `Build Gate`, `security-deployment-gate`, `Controller Integration Tests (Linux)`, `fleet-e2e-tests`, `trivy-scan` — satisfy all required check contexts for docs-only PRs

**Runtime**: <1 min per job

---

### Monitoring

#### `develop-sanity.yml` — Develop Branch Sanity

**Triggers**: push to develop only

**What it does**: Runs `go build ./...` after every merge to develop. On failure, opens a `pipeline:incident`-labeled issue with the build output so regressions are immediately visible. Not a PR gate — fires post-merge.

**Runtime**: ~1 min

---

## Workflow Trigger Matrix

| Workflow | push main/develop | pull_request | merge_group | Schedule | Manual |
|---|---|---|---|---|---|
| `test-suite.yml` | push main only | ✅ | ✅ | ❌ | ✅ |
| `cross-platform-build.yml` | ❌ | ✅ | ✅ | ❌ | ✅ |
| `fleet-e2e.yml` | ❌ | ❌ | ✅ | ❌ | ❌ |
| `security-scan.yml` | ✅ | ✅ | ✅ | Daily 3 AM UTC | ❌ |
| `codeql-analysis.yml` | ✅ | ✅ (Go/CodeQL/web paths) | ✅ | Weekly | ❌ |
| `codeql-stub.yml` | ❌ | ✅ (non-Go/non-web) | ❌ | ❌ | ❌ |
| `codeql-pack-publish.yml` | ✅ (extensions path) | ❌ | ❌ | ❌ | ✅ |
| `dast-scan.yml` | ❌ | ❌ | ❌ | Weekly Sun | ✅ |
| `docker-security.yml` | ✅ | ✅ | ❌ | ❌ | ✅ |
| `zizmor.yml` | ❌ | ✅ | ✅ | ❌ | ✅ |
| `scorecard.yml` | push develop only | ❌ | ❌ | Weekly Sat | ✅ |
| `dependency-pin-check.yml` | ❌ | ✅ (path-filtered) | ❌ | Weekly Wed | ✅ |
| `production-gates.yml` | ✅ | ✅ | ✅ | ❌ | ✅ |
| `license-check.yml` | ✅ | ✅ | ❌ | ❌ | ❌ |
| `cla-check.yml` | ❌ | pull_request_target | ✅ | ❌ | ❌ |
| `label-decommission-gate.yml` | ❌ | ✅ | ❌ | ❌ | ❌ |
| `documentation.yml` | push main (paths) | ✅ (paths) | ✅ | ❌ | ✅ |
| `develop-sanity.yml` | push develop only | ❌ | ❌ | ❌ | ❌ |
| `frontend-ci.yml` | ❌ | ✅ | ✅ | ❌ | ✅ |

---

## Running Workflows Locally

```bash
# Fast unit tests (same as test-suite.yml unit-tests job)
make test

# Pre-commit validation (tests + security + lint)
make test-commit

# Complete CI validation — matches all required checks
make test-complete

# Security scans
make security-scan

# Architecture constraint check
make check-architecture
```

---

## Troubleshooting

**Security scan blocking merge**: check the GitHub Security tab, run `make security-scan` locally. For CodeQL findings, genuine bugs → fix the code; false positives → extend `.github/codeql/extensions/` (see `docs/development/security-workflow-guide.md`).

**Cross-platform build failures**: verify code compiles on the target platform; check platform-specific build tags; review `Makefile` cross-compilation targets.

**CLA check failing**: add your name to `CONTRIBUTORS.md` in the format shown in the bot comment. The check re-runs on the next push.

**CodeQL pack publish failing** with "already exists": expected — bump `version:` in `.github/codeql/extensions/qlpack.yml` only when changing the model.

---

## References

- [Commit & PR Standards](../../docs/development/commit-and-pr-standards.md)
- [Security Workflow Guide](../../docs/development/security-workflow-guide.md)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
