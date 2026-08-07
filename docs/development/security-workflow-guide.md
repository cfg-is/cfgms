# CFGMS Security Workflow Guide

## Overview

This guide provides comprehensive documentation for the CFGMS security workflow, covering the complete pipeline from local development to production deployment. The security workflow ensures that no critical vulnerabilities reach production while providing automated remediation guidance and emergency override capabilities.

## Table of Contents

1. [Security Tools Overview](#security-tools-overview)
2. [Local Development Workflow](#local-development-workflow)
3. [GitHub Actions Integration](#github-actions-integration)
4. [Production Deployment Gates](#production-deployment-gates)
5. [Emergency Override Process](#emergency-override-process)
6. [Automated Remediation](#automated-remediation)
7. [Troubleshooting](#troubleshooting)
8. [Performance Optimization](#performance-optimization)
9. [Metrics and Monitoring](#metrics-and-monitoring)

## Security Tools Overview

The CFGMS security workflow integrates four complementary security scanning tools:

### 1. Trivy - Vulnerability Scanning

- **Purpose**: Scans filesystem for known vulnerabilities in dependencies and infrastructure
- **Scope**: Critical/High CVEs, secrets, misconfigurations
- **Blocking**: Yes — two enforcement points: (1) `trivy-scan` is a required PR/merge-queue context that exits 1 on findings; (2) `security-deployment-gate` in `production-gates.yml` also runs Trivy with `--exit-code 1`
- **SARIF Support**: Yes (GitHub Security tab integration; uploaded with `if: always()` so findings land in the Security tab even when the job fails)

### 2. Nancy - Go Dependency Scanning

- **Purpose**: Specialized Go module vulnerability scanning
- **Scope**: Go dependencies and transitive dependencies
- **Blocking**: No (informational, but tracked)
- **SARIF Support**: No (custom integration)

### 3. gosec - Go Security Patterns

- **Purpose**: Static analysis for Go security anti-patterns
- **Scope**: 127+ security checks for common Go vulnerabilities
- **Blocking**: No (informational, but tracked)
- **SARIF Support**: Yes (GitHub Security tab integration)

### 4. staticcheck - Advanced Static Analysis

- **Purpose**: Advanced Go code quality and correctness analysis
- **Scope**: 47 categories of code quality issues
- **Blocking**: No (code quality focus)
- **SARIF Support**: Limited (JSON output converted)

### 5. CodeQL - Semantic Code Analysis

- **Purpose**: Deep semantic / data-flow analysis (taint tracking) for vulnerability classes like path-injection (CWE-22), log-injection (CWE-117), and clear-text logging (CWE-312)
- **Scope**: Whole-program data flow, run in GitHub Actions (`codeql-analysis.yml`)
- **Blocking**: Findings post as PR review threads; main's ruleset requires thread resolution, so they gate release PRs in practice
- **SARIF Support**: Native (results land in the Security → Code scanning tab)

#### Custom models & false positives (IMPORTANT)

CodeQL cannot see our runtime validators, so it raises false positives where a value is actually sanitized. We correct this with a **CodeQL data-extension pack**, not by editing the upstream `github/codeql` repo:

- **Pack source**: `.github/codeql/extensions/` — `qlpack.yml` (`cfg-is/cfgms-go-extensions`) plus `models/*.model.yml`.
- **Publish requirement**: the pack is referenced *by name* from `.github/codeql/codeql-config.yml` (`packs:`) and **must be published to the ghcr.io CodeQL pack registry** by `.github/workflows/codeql-pack-publish.yml`. **Local-path pack references are not supported by the codeql-action** — a model file on disk does nothing until the pack is republished.
- **Bump the version (REQUIRED for every model change)**: editing a `models/*.yml` does nothing on its own. `codeql pack publish` refuses to overwrite an existing `<name>@<version>` and no-ops (`"already exists"`); the publish workflow treats that as a green no-op. You **must bump `version:` in `.github/codeql/extensions/qlpack.yml`** in the same change, or the registry keeps serving the old pack and your model stays inert (it will still *bundle* fine, masking the problem).
- **Already modeled**: `safeJoin` (path-injection), `ValidateAndCleanPath` (path-injection), `SanitizeLogValue` + `RedactedID` (log-injection / clear-text-logging).

Decision path for a CodeQL alert:

1. **Genuine bug** → fix the code (e.g. wrap operator-supplied values in `logging.SanitizeLogValue`).
2. **False positive with a real, value-returning sanitizer** (e.g. `safeJoin`, `ValidateAndCleanPath`) → add/extend a model. Use **both** `barrierModel` (kind = the sink kind, e.g. `path-injection`; CodeQL ≥ 2.25.2) **and** `summaryModel(kind=value)` together — neither is reliable alone across all taint-flow paths (json.Decode field-selection flows bypass barrierModel in some CodeQL versions; summaryModel can miss other paths). Also prefer refactoring the call site to *use the sanitizer's return value* (e.g. `cleanedBase := ValidateAndCleanPath(...)`) rather than discarding it — a code-level taint barrier is more robust than any model. Verify the exact `barrierModel` tuple format against `github/codeql:go/ql/lib/ext/` — the format is finicky and CI is the only reliable verification (CodeQL can't be modeled-and-tested purely locally).
3. **False positive from a guard-style validator** (returns only `error`, e.g. blobstore `validateKey`/`validateKeyComponent`) or a **heuristic source** (CodeQL flagging a variable *named* `*SecretKey` that holds a SecretStore key *reference*, not a value) → data extensions can't cleanly model these; **dismiss the alert with justification** (or refactor to a value-returning sanitizer that *can* be modeled).
4. **False positive from struct field-insensitivity** (CodeQL traces taint through a whole struct because one field is a secret — e.g. `APIKey.Key` — even though only non-secret fields are logged) → these **cannot** be fixed by extension-pack models (no field-access barrier primitive exists). Dismiss with justification; confirm via grep that no secret/credential field value is passed to the logger at the flagged site.
5. **Heuristic source you control the name of** → **rename the identifier**. This is strictly better than dismissal: it clears the alert permanently and stops it re-firing at every new sink the value reaches. See the exact regexes below before choosing a replacement name.

##### The sensitive-name heuristic, exactly

`clear-text-logging` classifies a source by **identifier name alone**, regardless of type — a `bool` named `PasswordSet` is a "secret". The matcher lives in the CodeQL Go pack at `semmle/go/security/SensitiveActions.qll` (module `HeuristicNames`) and consults **no** data extension, so the pack cannot suppress it. There are exactly three source patterns:

| Classification | Regex |
|---|---|
| secret | `(?is).*((?<!is)secret\|(?<!un\|is)trusted).*` |
| account info | `(?is).*(puid\|username\|userid).*` |
| password | `(?is).*pass(wd\|word\|code\|phrase)(?!.*question).*` and `(?is).*(auth(entication\|ori[sz]ation)?\|api\|secret)key.*` |

A name matching any of them is a source **unless** it also matches the suppressor `(?is).*(test|redact|censor|obfuscate|hash|md5|(?<!un)mask|sha|((?<!un)(en))?(crypt|code)).*`. That suppressor is also what makes a *call* a barrier (`ObfuscatorCall`) — which is why `logging.RedactedID` blocks clear-text-logging flow but `logging.SanitizeLogValue` does not.

Notably **`credential` is not a trigger word** — it appears in no regex in the Go pack. `HasCredential`, `credentialRef`, `userStoreRef` and `passStoreRef` are all clean; `userSecretKey`, `passSecretKey`, `passwdFile`, `PasswordSet` and `secretKey` were not. Test a candidate name against the table above before committing to it, and read the local pack copy (`~/.codeql/packages/codeql/go-all/<version>/semmle/go/security/SensitiveActions.qll`) rather than trusting this table if the two disagree.

#### Model inventory and dismissal log (most recent first)

| Pack version | Alert IDs | Kind | Resolution | Notes |
|---|---|---|---|---|
| 0.0.11 | #1240, #1241 | zipslip | Model | `features/modules/extended/github_runner.safeJoin` added as `summaryModel` + `barrierModel(path-injection)`. A second, independent `safeJoin` from the flatfile one already modelled — it rejects any `..` segment and re-verifies containment with `filepath.Rel` before returning the extraction target. |
| 0.0.11 | #1289, #1284, #1285, #1116–#1121, #1126–#1130, #1138, #1139 | clear-text-logging | Rename | Name-heuristic FPs, fixed at the source by renaming the five identifiers that were classified as secrets by name: `PasswordSet`→`HasCredential` (a bool; also renames the module yaml key `password_set`→`has_credential`), `userSecretKey`/`passSecretKey`→`userStoreRef`/`passStoreRef` (hyperv — SecretStore *lookup keys*, not values), `passwdFile`→`userDBPath` (the path `/etc/passwd`), `secretKey`→`credentialRef` (api — a store lookup path). See "The sensitive-name heuristic, exactly" above for why these names matched and why the replacements do not. |
| 0.0.11 | #1232 | log-injection | Dismiss | `handlers_ip_trust.go:78` — the flagged argument is `req.PreSeeded`, a `bool`. CodeQL is field-insensitive over the JSON-decoded request struct and does not type-filter the `slog` variadic `...any`, so a boolean is reported as a log-injection sink argument. A bool cannot carry CR/LF; there is nothing to sanitize. |
| 0.0.11 | #530 | path-injection | Dismiss | `pkg/security/fileaccess.go:189` — the `os.Stat(parent)` existence probe inside `ValidateAndCleanPath`'s deepest-existing-ancestor walk. The sink is *inside the sanitizer itself*, after the pre-resolution containment check at lines 160–164 has already proven the path is inside the base, so the pack's `barrierModel` on the function's return value cannot apply. Read-only probe; no path outside the base is ever touched. |
| 0.0.10 | #1101 | clear-text-logging | Dismiss | Map field-insensitivity FP: `PasswordSet bool` in `stdlib/user/interface.go ToMap()` taints the generic `configMap` used by the hyperv executor; CodeQL propagates taint to `configMap["vhd_path"]` → `cfg.VHDPath` → `seedVHDPath()` → `mediaPath` in `vm_provision.go:876`. `mediaPath` is a filesystem path, not a credential; `PasswordSet` is a boolean flag. No secret value is logged at that site (grep-confirmed). Cannot be modeled (no map-key/field-access barrier primitive). |
| 0.0.7 | #745, #746 | path-injection | Code fix + model | `git_store.go`: use `cleanedBase` (return value of `ValidateAndCleanPath`) instead of raw `tenantID` in `filepath.Join`. `ValidateAndCleanPath` added as `summaryModel` + `barrierModel` in `path-injection-sanitizers.model.yml`. |
| 0.0.7 | #669, #713, #714, #715, #722 | log-injection | Model + dismiss | `SanitizeLogValue` `summaryModel(kind=value)` added as belt-and-suspenders over existing `barrierModel` (json.Decode field-selection flows bypass barrierModel alone). Alerts dismissed as FP: all sites already wrap input in `SanitizeLogValue`; the barrierModel is correct but insufficiently reliable. |
| 0.0.7 | #774, #777 | clear-text-logging | Dismiss | Struct field-insensitivity FP: `keyInfo.ID`/`keyInfo.TenantID` (middleware.go) and `deviceID` (controller_service.go) are non-secret fields; the struct's `Key`/`Token` field is never logged. Cannot be modeled (no field-access barrier primitive). |
| 0.0.6 | #747–#751 | log-injection | Dismiss | handlers_registration_refresh.go — json.Decode field-selection sources; all sites use `SanitizeLogValue`. Same heuristic-source class as #669–#722. |
| 0.0.5 | safeJoin | path-injection | Model | `summaryModel` + `barrierModel` for `pkg/storage/providers/flatfile.safeJoin`. |

### 6. Go Native Fuzzing

- **Purpose**: Finds panics and unexpected crashes in parse/decode boundaries under adversarial input — the threat-model-relevant surfaces a compromised steward or malicious config push would hit
- **Scope**: CFGMS-owned parse surfaces (does NOT fuzz `crypto/x509`, `google.golang.org/protobuf`, or any vendored library's own internals)
- **Blocking**: **NOT a PR gate** — time-boxed fuzzing is flaky as a required check. Runs nightly via `.github/workflows/fuzz-nightly.yml`
- **Discovery**: `scripts/fuzz-all.sh` auto-discovers all `Fuzz*` targets via `go test -list '^Fuzz'` for each listed package — any new `Fuzz*` target in a listed package is picked up automatically, no workflow edit needed

**Fuzz targets:**

| Target | File | Surface |
|--------|------|---------|
| `FuzzUnmarshalStewardConfig` | `pkg/config/manager_fuzz_test.go` | `yaml.Unmarshal` + `ValidateConfiguration` on steward config payloads (the config-parsing boundary a malformed `cfg push` would hit) |
| `FuzzReassembleDNA` | `features/controller/transport/dna_handler_fuzz_test.go` | Both `json.Unmarshal` calls in `reassembleDNA` on concatenated steward-supplied `DNAChunk` payload bytes (the compromised-steward-to-controller wire boundary) |
| `FuzzParseEID` | `pkg/entitygraph/types/eid_fuzz_test.go` | Hand-rolled `ParseEID` parser on steward/directory-supplied identifier strings |
| `FuzzParseCertificateFromPEM` | `pkg/cert/utils_fuzz_test.go` | PEM decode + `x509.ParseCertificate` (mTLS-everywhere means cert parsing is the highest threat-model-relevant fuzz surface) |
| `FuzzParseCertificateChainFromPEM` | `pkg/cert/utils_fuzz_test.go` | Multi-block `pem.Decode` loop |
| `FuzzParsePrivateKeyFromPEM` | `pkg/cert/utils_fuzz_test.go` | PEM block type dispatch to `x509.ParsePKCS1PrivateKey` / `ParsePKCS8PrivateKey` / `ParseECPrivateKey` |
| `FuzzGzipDecompress` | `features/controller/fleet/storage/compression_fuzz_test.go` | Storage read-back decompression boundary: gzip-decompress then `proto.Unmarshal` into `commonpb.DNA`. Decompression-bomb surface — an attacker writing to the config store's compressed blob could trigger unbounded memory growth. |
| `FuzzOptimizedDNADecompress` | `features/controller/fleet/storage/compression_fuzz_test.go` | Distinct second decode boundary for the `dna-optimized` compressor: gzip-decompress then `json.Unmarshal` into `serializedOptimizedPayload`, then manual field-by-field reconstruction with index bounds checks. |
| `FuzzSplitCSVLine` | `features/steward/dna/hardware_parse_fuzz_test.go` | RFC-4180 CSV parser (hardware_parse.go:27) on raw CIM/WMI command output — real untrusted-input boundary when the invoked binary is compromised or its output is truncated/malformed. |
| `FuzzCimDataRows` | `features/steward/dna/hardware_parse_fuzz_test.go` | Multi-row CSV splitter (hardware_parse.go:55) — exercises header-skip and blank-line-skip logic. |
| `FuzzParseCIMComputerSystem` | `features/steward/dna/hardware_parse_fuzz_test.go` | Full Win32_ComputerSystem CIM parse pipeline including `strconv.ParseInt` on the TotalPhysicalMemory field. |
| `FuzzParseCIMMemoryModules` | `features/steward/dna/hardware_parse_fuzz_test.go` | Multi-row memory module parser — sums capacities across arbitrarily many rows; higher combinatorial complexity than single-row parsers. |

> **Why no `FuzzZstdDecompress` or `FuzzLZ4Decompress`:** `ZstdCompressor.Decompress` and `LZ4Compressor.Decompress` are one-line delegates to `GzipCompressor.Decompress` (compression.go:225, :308 — design decision documented at line 219: "zstd/LZ4 compression requires build tags... GZIP is the universal fallback"). A separate fuzz target for either would exercise the exact same code path as `FuzzGzipDecompress` and add zero real coverage.

**Corpus locations:** `<package>/testdata/fuzz/<FuzzName>/` — crash entries are committed as regression fixtures and uploaded as workflow artifacts by `fuzz-nightly.yml`.

**Local run:**

```bash
# Run a single target for 30 seconds
go test -run='^$' -fuzz='^FuzzParseEID$' -fuzztime=30s ./pkg/entitygraph/types/

# Run all targets via the auto-discovery script (same as CI)
./scripts/fuzz-all.sh 30s
```

### 7. OpenSSF Scorecard

- **Purpose**: Measures supply-chain security posture across 18 checks (dependency pinning, token
  permissions, code review, branch protection, SAST, fuzzing, and more)
- **Scope**: `develop` branch state (Scorecard scores the default branch regardless of which branch
  the workflow runs from)
- **Blocking**: No — runs post-merge on push to `develop` and weekly; NOT a required PR check
- **SARIF Support**: Yes (published to GitHub Security tab and to the OSSF public dashboard)
- **Workflow**: `.github/workflows/scorecard.yml`

#### Baseline (2026-07-24, commit fa292575, Scorecard v5.5.0)

**Overall score: 6.3 / 10**

Scored using Scorecard CLI v5.5.0 with the default `GITHUB_TOKEN` against `develop` commit
`fa292575`. Two checks (`CII-Best-Practices`, `Vulnerabilities`) hit network errors in the
container environment and are excluded from the average; they will resolve on the first GitHub
Actions workflow run (the GHA runner has the required external API access). The score above is the
real CLI-measured value — the first `workflow_dispatch` after the workflow lands on `develop` will
produce the definitive GHA-run score.

**Checks at full marks (10/10):** CI-Tests, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing,
License, Maintained, Packaging, SAST, Security-Policy.

**Checks below full marks — gap list:**

| Check | Score | Gap / Rationale | Owning Story or Status |
|-------|-------|-----------------|------------------------|
| Binary-Artifacts | 9/10 | Scorecard detected binaries in the repository | Follow-up investigation |
| Pinned-Dependencies | 7/10 | ~~Dockerfiles use image tags without SHA digest~~ **Resolved (Issue #3202)**: all six `FROM` lines across `.devcontainer/Dockerfile`, `cmd/steward/Dockerfile{,.debian}` and `Dockerfile.test-runner` are now digest-pinned. Remaining findings are `goCommand` (`go install …@vX.Y.Z` in `security-scan.yml`), `downloadThenRun` (`curl … \| sh` in the devcontainer) and `npmCommand` — see "Accepted risks" below. | Docker image pinning done + digest-drift tracking added to `dependency-pin-check.yml` |
| CII-Best-Practices | -1/10¹ | No OpenSSF Best Practices badge obtained; expected 0/10 on GHA run | Future improvement |
| Vulnerabilities | -1/10¹ | OSV scanner failed due to container network restriction; Trivy + Nancy run as blocking gates in `security-scan.yml`; expected 10/10 on GHA run | Covered by existing blocking gates |
| Token-Permissions | 0/10 | **Resolved (Issue #3202)**: `develop-sanity.yml` and `cla-check.yml` moved their write grants from workflow top level to job level; `test-suite.yml`, `fuzz-nightly.yml` and `dependency-pin-check.yml` gained a top-level `permissions: {}`. Every workflow except `frontend-ci.yml` (which grants only `contents: read`) now starts from default-deny. Three jobs still declare write scopes they genuinely need — see "Accepted risks" below. | Migration done; re-score on the next Scorecard run |
| Signed-Releases | 0/10 | No releases cut yet; no cosign / sigstore provenance attached | Future — when release process is established |
| Contributors | 0/10 | 0 contributing organizations; Scorecard rewards multi-org contribution | **Accepted gap — solo-dev model (CLAUDE.md)** |
| Code-Review | 0/10 | 0 approved changesets found; branch protection deliberately omits required reviewers (CLAUDE.md: "squash-only, no-review, solo-friendly") | **Accepted gap — solo-dev model (CLAUDE.md)**. Will improve to 10/10 when team expansion adds required reviews. |
| Branch-Protection | 0/10 | Two compounding factors: (1) default `GITHUB_TOKEN` lacks `administration:read` scope, so Scorecard cannot read the branch ruleset — a founder-provisioned fine-grained PAT added as `SCORECARD_READ_TOKEN` is required to unlock this; (2) even with a PAT, branch protection deliberately omits required PR reviewers (CLAUDE.md solo-dev model), which caps the score below 8/10 regardless. | **Accepted gap — solo-dev model (CLAUDE.md)**. PAT provisioning is a founder-owned decision. No `SCORECARD_READ_TOKEN` secret is provisioned by this story. |

¹ `CII-Best-Practices` and `Vulnerabilities` hit network errors during the container CLI run.
Expected GHA scores: `CII-Best-Practices` → 0/10 (no badge); `Vulnerabilities` → 10/10
(no unfixed known CVEs in OSV data; Trivy/Nancy blocking gates confirm this).

**Realistic ceiling given the solo-dev model: ~7.5–8.0, not 9.0+**

The source issue's "toward 9.0+" framing is walked back here. Even with all fixable gaps
resolved (Token-Permissions, Pinned-Dependencies, Binary-Artifacts, Signed-Releases,
CII-Best-Practices), Code-Review (0/10) and Contributors (0/10) are structurally capped by the
solo operating model, and Branch-Protection stays below 8/10 without required reviewers. This
ceiling is structural — not a gap list to chase.

**Fuzzing:** 10/10 (native Go fuzz targets; Scorecard recognises Go native fuzzing since v5). Score
may improve further as additional fuzz surfaces land from related stories.

#### Accepted risks (Issue #3202)

These Scorecard alerts stay open deliberately. Each has a reason; none is un-triaged.

| Alert | Reason |
|---|---|
| `TokenPermissionsID` — `release.yml:publish` (`contents`/`id-token`/`attestations`/`artifact-metadata: write`) | The job's purpose is to publish a signed release. It cannot do that without write. Scoped to one job in a `release` environment. |
| `TokenPermissionsID` — `codeql-pack-publish.yml:publish` (`packages: write`) | Publishes the CodeQL extension pack to ghcr.io. Write to packages is the job. |
| `TokenPermissionsID` — `dast-scan.yml:dast-scan` (`security-events: write`) | Uploads ZAP SARIF to the Security tab. Write to security-events is the job. |
| `PinnedDependenciesID` — `goCommand` (`go install …@vX.Y.Z` in `security-scan.yml`) | Tool installs are version-pinned, and the module checksum database plus `go.sum` provide the integrity guarantee a hash pin would. `dependency-pin-check.yml` already tracks these versions weekly. |
| `PinnedDependenciesID` — `downloadThenRun` / `npmCommand` (`.devcontainer/Dockerfile`) | Developer container only — never part of a released artifact or of any steward/controller image. `ARG CLAUDE_CODE_VERSION` is version-pinned and tracked by `dependency-pin-check.yml`. |
| `CodeReviewID` (0/10), `Contributors` (0/10), `BranchProtectionID` | Structural to the solo operating model documented in `CLAUDE.md` (squash-only, no required reviewers). Not a gap to chase — see "Realistic ceiling" above. |
| `CIIBestPracticesID` | No OpenSSF Best Practices badge obtained. Applying for one is a founder-owned decision, not a code change. |
| `VulnerabilitiesID` | OSV scanner network failure in the container run. Trivy and Nancy run as blocking gates and cover the same ground; expected 10/10 on a GHA run. |

**Base-image digests are now tracked.** Digest pinning freezes the image, so a patched re-push of the
same tag is no longer picked up automatically. `dependency-pin-check.yml` resolves each pinned
`FROM … @sha256:…` against the tag's current digest on its weekly run and reports drift into the
`dependency-pins` issue, so a stale base image surfaces the same way a stale tool version does.

### 8. OWASP ZAP — Dynamic Application Security Testing

- **Purpose**: Unauthenticated baseline DAST scan (spider + passive rules) against the controller's single HTTPS listener, covering both the REST API and the embedded SPA (`features/controller/api/spa.go`).
- **Scope**: Public surface only — no authenticated crawl. Authenticated DAST is a follow-on story.
- **Blocking**: Advisory — not a required merge-queue check. Findings are visible in the workflow artifacts; see below for the escalation path.
- **Workflow file**: `.github/workflows/dast-scan.yml`
- **Triggers**: `workflow_dispatch` (manual) + weekly schedule (Sunday 03:00 UTC).

#### Controller bootstrap (no external DB needed)

The scan uses a self-contained flatfile-storage controller:
- `DefaultConfig().Storage.Provider` = `"flatfile"` — no `CFGMS_STORAGE_PROVIDER` override needed, no database service.
- Certs auto-generated by `pkg/cert.Manager` on first boot into the mounted `/app/certs` volume.
- `CFGMS_HTTP_LISTEN_ADDR=0.0.0.0:8080` overrides the loopback-only default (`127.0.0.1:8080`, Story #1919) so ZAP can reach the container. ZAP's Docker container runs with `--network=host` (see zaproxy/action-baseline source), making `localhost:8080` reachable.
- **`CFGMS_ENABLE_TEST_ENDPOINTS` and `CFGMS_SEED_TEST_TOKENS` are NOT set.** The DAST target runs with production auth posture.

#### ZAP self-signed cert

ZAP's baseline scan sends requests directly to the target and does not validate the server's certificate chain by design (it is a DAST tool, not a browser). The controller's auto-generated cert includes `localhost` as a SAN, so ZAP's hostname resolution is correct even if chain validation were enabled.

#### Rules file (`.zap/rules.tsv`)

Suppresses known-acceptable false positives for the CI scanning surface. Format:

```
# Comment
plugin_id<TAB>threshold
# threshold: IGNORE | INFO | LOW | MEDIUM | HIGH | FAIL
```

Populate this file after the first manual run reveals the alert baseline. Only suppress confirmed false positives that are specific to the CI context (localhost, self-signed cert, flatfile storage) — do not suppress production-relevant findings.

#### Artifacts and findings

- **Workflow artifacts**: ZAP HTML, JSON, and Markdown reports are uploaded as `zap-dast-report` (30-day retention).
- **SARIF**: `zaproxy/action-baseline` does not generate SARIF natively. Use the JSON artifact to review findings. A follow-on story can add a SARIF converter step and upload to the Security tab.

#### Escalation path for findings

1. Run `workflow_dispatch` → download `zap-dast-report` artifact.
2. Review the HTML report for findings at MEDIUM/HIGH severity.
3. Genuine issues → fix the code and open a PR.
4. Confirmed false positives specific to CI surface → add an IGNORE entry in `.zap/rules.tsv` with a comment explaining why.
5. Suppress nothing blindly — every entry in `rules.tsv` must have a justification comment.

### 9. Snyk & SonarCloud — Tool Evaluation

This section records the explicit keep/drop decision for Snyk and SonarCloud, evaluated against
the security tooling stack already running in CI (§§1–8 above). The evaluation answers the
acceptance criterion originally scoped in Issue #2930 and landed via Issue #3083.

#### Snyk — Decision: DROP

- **Purpose**: Developer-first SCA (Software Composition Analysis) platform combining CVE scanning
  of dependencies (`snyk test`), container image scanning (`snyk container test`), and SAST
  (`snyk code test`).
- **Unique coverage over the existing stack**: Minimal.
  - CVE / dependency scanning: Trivy (§1) already scans the filesystem for CRITICAL/HIGH CVEs and
    is a blocking PR gate; Nancy (§2) specifically targets Go module vulnerabilities using OSV
    data. Snyk's SCA surface is a subset of what Trivy + Nancy already cover.
  - Container image scanning: Trivy (`--scanners vuln`) covers Docker images; the
    `security-deployment-gate` already runs Trivy with `--exit-code 1` in `production-gates.yml`.
  - SAST (`snyk code`): pattern-based; CodeQL (§5) provides deeper whole-program data-flow /
    taint-tracking analysis for the same vulnerability classes (path-injection, log-injection,
    clear-text logging). gosec (§3) covers Go-specific security anti-patterns. Snyk Code would be
    a weaker, overlapping signal with no gap to fill.
- **Operational cost**: new `SNYK_TOKEN` organization secret required; new CI job to maintain;
  SaaS dependency; paid tier required for private repositories beyond the OSS free quota.
- **Decision: DROP.** The existing Trivy + Nancy + gosec + CodeQL stack covers Snyk's entire scope
  with a blocking gate (Trivy) and deeper semantic analysis (CodeQL). Adding Snyk would increase
  operational surface and introduce a SaaS dependency without adding unique detection capability.

#### SonarCloud — Decision: DROP

- **Purpose**: Cloud-based code quality and security analysis platform offering quality rules,
  security hotspot detection, and taint-flow analysis across Go and TypeScript in a unified
  dashboard.
- **Unique coverage over the existing stack**: Marginal.
  - Go quality and security rules: staticcheck (§4) covers 47 categories of code quality and
    correctness; gosec (§3) covers Go security anti-patterns. SonarCloud's Go ruleset is largely a
    subset of what these two tools already report.
  - TypeScript security analysis: CodeQL (§5) was extended to TypeScript during Issue #2930
    (`language: ['go', 'typescript']`), providing deep data-flow analysis for the SPA. The lint
    gate also runs `eslint-plugin-security` for pattern-based TypeScript security checks.
  - Multi-language unified dashboard: provides a single-pane view, but all gate results are already
    visible in the GitHub Security tab via SARIF (Trivy, gosec, CodeQL all upload SARIF). The
    incremental value of a separate SonarCloud dashboard is low in the solo-dev model.
- **Operational cost**: new `SONAR_TOKEN` organization secret required; new CI job to maintain;
  paid tier required for private repositories (the free SonarCloud tier is OSS/public-repo only;
  CFGMS is AGPL-3.0 but the repository is private); multi-language scan setup adds maintenance
  complexity.
- **Decision: DROP.** The existing staticcheck + gosec + CodeQL (Go + TypeScript) + eslint-plugin-security
  stack covers SonarCloud's scope. The unified-dashboard benefit is not material given SARIF already
  surfaces all findings in the GitHub Security tab. Operational cost (new secret, new CI job, paid
  subscription for private repo) is not justified by the marginal incremental coverage.

## Local Development Workflow

### Prerequisites

Install security tools locally:

```bash
# Install all security tools
make install-nancy

# Install individual tools (Ubuntu/Debian)
sudo apt-get install trivy
go install github.com/securego/gosec/v2/cmd/gosec@v2.28.0
GOTOOLCHAIN="$(go env GOVERSION)" go install honnef.co/go/tools/cmd/staticcheck@2026.1
```

### Development Security Commands

```bash
# Quick security check (development)
make security-check

# Comprehensive security scan (pre-commit)
make security-scan

# Non-blocking scan (CI-friendly)
make security-scan-nonblocking

# Generate remediation report for Claude Code
make security-remediation-report

# Unified development validation
make test-with-security
```

### Integration with CLAUDE.md Workflow

The security workflow is integrated into the mandatory CLAUDE.md development process:

```bash
# Step 6: Run Security Scanning (MANDATORY)
make security-scan  # MUST pass before proceeding

# Alternative: Unified validation (RECOMMENDED)
make test-with-security  # Runs: test + security-scan + summary
```

## GitHub Actions Integration

### Security Scanning Workflow

**File**: `.github/workflows/security-scan.yml`

**Features**:

- Parallel execution across 4 security tools
- SARIF output for GitHub Security tab integration
- Tool-specific caching for performance
- Automated remediation report generation
- Failure notifications with actionable guidance

**Triggers**:

- Push to `develop` and `main` branches
- Pull requests to `develop` and `main` branches
- Manual workflow dispatch with scan type options

**Parallel Jobs**:

1. `trivy-scan` - Vulnerability scanning with SARIF output
2. `nancy-scan` - Go dependency scanning
3. `gosec-scan` - Security pattern analysis with SARIF output
4. `staticcheck-scan` - Code quality analysis
5. `security-validation` - Consolidated results and reporting

### Production Deployment Gates

**File**: `.github/workflows/production-gates.yml`

**Security Gate Features**:

- Critical/High vulnerability blocking via Trivy (`--exit-code 1`)
- Emergency override mechanism
- Comprehensive audit trail
- Integration with existing release gates

**Scope**: `security-deployment-gate` runs only the blocking Trivy scan. Advisory tools (nancy, gosec, staticcheck) run as non-required contexts in `security-scan.yml` and are not executed here.

**Gate Flow**:

1. `security-deployment-gate` - Primary security validation (Trivy only)
2. `production-risk-assessment` - Risk analysis (requires security approval)

## Production Deployment Gates

### Security Gate Logic

The security deployment gate blocks production deployments when:

- **Critical vulnerabilities** are detected (CVE severity: CRITICAL)
- **High vulnerabilities** are detected (CVE severity: HIGH)
- Security scanning tools fail to execute properly

### Gate Decision Matrix

| Security Status | Deployment Allowed | Action Required |
|----------------|-------------------|-----------------|
| Clean | ✅ Yes | Proceed with deployment |
| Medium/Low Issues | ✅ Yes | Monitor and plan remediation |
| High Issues | ❌ No | Fix vulnerabilities or use override |
| Critical Issues | ❌ No | **Mandatory fix** or emergency override |

### Integration Points

All production gates depend on security approval:

- `production-risk-assessment` requires `security-deployment-gate` success

## Emergency Override Process

### When to Use Emergency Override

Emergency override should only be used for:

- **Critical production outages** requiring immediate fixes
- **Security vulnerabilities** in production that need urgent patching
- **Business-critical deployments** that cannot wait for vulnerability fixes

### Override Methods

#### Method 1: Workflow Dispatch

1. Go to Actions → Production Risk Gates → Run workflow
2. Set `emergency_override` to `true`
3. Provide detailed `override_reason`
4. Submit and monitor execution

#### Method 2: Emergency File

1. Create `EMERGENCY_DEPLOYMENT` file in repository root
2. Commit and push to trigger deployment
3. File presence automatically enables override

### Override Audit Trail

Every override creates comprehensive audit documentation:

- **Deployment details**: Branch, commit, actor, timestamp
- **Override reason**: Justification and authorization
- **Security status**: Issues present during override
- **Approval chain**: Required post-deployment actions

**Audit Artifacts**:

- `security-deployment-audit` (90-day retention)

### Post-Override Requirements

When emergency override is used:

1. **Immediate Risk Assessment**: Document security risks
2. **Remediation Planning**: Create timeline for fixes
3. **Security Review**: Obtain security team approval
4. **Follow-up Deployment**: Apply security fixes ASAP

## Automated Remediation

### Claude Code Integration

The security workflow generates structured JSON reports for automated remediation:

```bash
# Generate remediation report
make security-remediation-report

# Output location
/tmp/cfgms-security-remediation.json
```

### Remediation Report Structure

```json
{
  "timestamp": "2025-08-04T16:15:33Z",
  "project": "cfgms",
  "scanning_tools": ["trivy", "nancy", "gosec", "staticcheck"],
  "summary": {
    "total_issues": 327,
    "critical": 1,
    "high": 1,
    "medium": 87,
    "low": 238
  },
  "remediation_suggestions": [
    {
      "tool": "trivy",
      "category": "dependency_vulnerabilities",
      "severity": "CRITICAL_HIGH",
      "auto_fixable": true,
      "claude_prompt": "Fix critical and high vulnerability dependencies...",
      "priority": 1,
      "validation_command": "make security-trivy"
    }
  ]
}
```

### Automated Remediation Workflow

1. **Detection**: Security scan identifies issues
2. **Report Generation**: Structured JSON created
3. **Claude Code Processing**: AI applies fixes automatically
4. **Validation**: Run security scans to verify fixes
5. **Commit**: Push remediated code

### Remediation Priority

1. **Priority 1**: CRITICAL/HIGH CVEs (deployment blocking)
2. **Priority 2**: Dependency vulnerabilities (same session)
3. **Priority 3**: Security patterns (high → medium)
4. **Priority 4**: Code quality (cleanup/refactoring)

## Performance Optimization

### Parallel Execution

The security workflow uses parallel job execution for optimal performance:

**Before Optimization**: Sequential execution (~15-20 minutes)

```
trivy → nancy → gosec → staticcheck → validation
```

**After Optimization**: Parallel execution (~5-8 minutes)

```
┌─ trivy-scan (3-5 min)
├─ nancy-scan (1-2 min)  
├─ gosec-scan (2-4 min)
└─ staticcheck-scan (3-5 min)
    ↓
security-validation (1 min)
```

### Caching Strategy

Each security tool uses optimized caching:

#### Go Module Caching

```yaml
- name: Cache Go modules
  uses: actions/cache@v3
  with:
    path: ~/go/pkg/mod
    key: ${{ runner.os }}-[tool]-go-${{ hashFiles('**/go.sum') }}
    restore-keys: |
      ${{ runner.os }}-[tool]-go-
```

#### Tool-Specific Caching

- **Trivy**: Database and cache directory caching
- **Nancy**: Binary and database caching
- **gosec**: Go module and binary caching
- **staticcheck**: Go module and analysis caching

### Performance Benchmarks

| Tool | Sequential Time | Parallel Time | Improvement |
|------|----------------|---------------|-------------|
| Trivy | 3-5 min | 3-5 min | Baseline |
| Nancy | 1-2 min | 1-2 min | Baseline |
| gosec | 2-4 min | 2-4 min | Baseline |
| staticcheck | 3-5 min | 3-5 min | Baseline |
| **Total** | **15-20 min** | **5-8 min** | **60-70% faster** |

### Resource Optimization

- **Timeout Management**: Tool-specific timeouts prevent hanging
- **Memory Limits**: Prevent resource exhaustion
- **Concurrent Limits**: Optimal parallel job count
- **Artifact Management**: Efficient artifact upload/download

## Metrics and Monitoring

### Workflow Effectiveness Metrics

The security workflow collects the following metrics:

#### Security Scan Metrics

- **Vulnerability Detection Rate**: Issues found per scan
- **False Positive Rate**: Invalid alerts per tool
- **Remediation Time**: Time from detection to fix
- **Scan Success Rate**: Successful scans vs failures

#### Performance Metrics

- **Scan Duration**: Time per tool and total workflow
- **Cache Hit Rate**: Caching effectiveness
- **Resource Usage**: CPU, memory, and artifact storage
- **Parallel Efficiency**: Speedup from parallelization

#### Deployment Gate Metrics

- **Blocking Rate**: Deployments blocked by security issues
- **Override Usage**: Emergency override frequency and reasons
- **Gate Effectiveness**: Issues caught before production
- **Remediation Success**: Fixes applied successfully

#### Developer Experience Metrics

- **Local vs CI Consistency**: Tool behavior across environments
- **Developer Adoption**: Usage of local security commands
- **Remediation Automation**: Claude Code usage statistics
- **Workflow Completion Time**: End-to-end development cycle

### Metrics Collection Implementation

```bash
# Workflow effectiveness analysis
make analyze-security-metrics

# Performance benchmarking
make benchmark-security-workflow

# Developer experience survey
make security-workflow-survey
```

### Metrics Dashboard

Future implementation will include:

- **Grafana Dashboard**: Real-time security metrics
- **Prometheus Integration**: Metrics collection and alerting
- **GitHub Insights**: Repository security health scores
- **Team Metrics**: Developer productivity and security adoption

## Team Expansion Preparation

### PR-Based Workflow Foundation

The current security workflow is designed to scale for team expansion:

#### Current State (Individual Development)

- Security scans on `develop` and `main` pushes
- Direct branch commits with security validation
- Manual emergency overrides

#### Future State (Team Development)

- Security scans on all pull requests
- Branch protection rules requiring security approval
- Code review integration with security results
- Automated PR status checks

### Branch Protection Configuration

When ready for team expansion, implement:

```yaml
# .github/branch-protection.yml
branches:
  develop:
    protection:
      required_status_checks:
        strict: true
        contexts:
          - "security-validation"
          - "trivy-scan"
          - "gosec-scan"
      enforce_admins: true
      required_pull_request_reviews:
        required_approving_review_count: 1
        dismiss_stale_reviews: true
```

### Code Review Integration

Future enhancements for team workflows:

- **Security Review Bot**: Automated security feedback on PRs
- **Risk Assessment Comments**: Automated risk analysis
- **Remediation Suggestions**: In-line fix recommendations
- **Security Score**: PR security health metrics

### Training and Onboarding

Documentation prepared for team expansion:

- **Security Workflow Training**: Complete guide for new developers
- **Tool-Specific Guides**: Individual tool documentation
- **Troubleshooting Runbook**: Common issues and solutions
- **Best Practices**: Security-first development guidelines

## Troubleshooting

### Common Issues and Solutions

#### Issue: Trivy Database Update Failures

**Symptoms**: `trivy` fails with database update errors
**Solution**:

```bash
# Clear Trivy cache and database
trivy clean --all
# Retry scan
make security-trivy
```

#### Issue: Nancy Binary Download Failures

**Symptoms**: `nancy` installation fails or binary not found
**Solution**:

```bash
# Reinstall Nancy with platform detection
make install-nancy
# Verify installation
nancy --version
```

#### Issue: gosec False Positives

**Symptoms**: `gosec` reports issues in vendor code or test files
**Solution**:

```bash
# Add exclusions to .gosecrc file
echo 'exclude-dirs: vendor,testdata' > .gosecrc
# Or exclude specific rules
gosec -exclude G204 ./...
```

#### Issue: staticcheck Performance Issues

**Symptoms**: `staticcheck` runs slowly or times out
**Solution**:

```bash
# Run with specific packages only
staticcheck ./features/... ./pkg/...
# Or increase timeout
staticcheck -timeout 10m ./...
```

### GitHub Actions Troubleshooting

#### Issue: Security Gate Not Blocking Deployment

**Symptoms**: Deployment proceeds despite security issues
**Diagnosis**:

1. Check security gate job logs
2. Verify `deployment-allowed` output
3. Review security scan results

**Solution**:

```bash
# Debug security gate logic
gh run view [run-id] --log
# Check specific job outputs
gh api repos/cfg-is/cfgms/actions/runs/[run-id]/jobs
```

#### Issue: Emergency Override Not Working

**Symptoms**: Override inputs ignored or not processed
**Diagnosis**:

1. Verify workflow dispatch inputs
2. Check override reason provided
3. Review audit trail generation

**Solution**:

```bash
# Verify workflow inputs
gh workflow run production-gates.yml \
  --field emergency_override=true \
  --field override_reason="Critical production fix"
```

### Performance Issues

#### Issue: Slow Security Scans

**Symptoms**: Workflow takes longer than expected
**Diagnosis**:

1. Check individual tool performance
2. Review cache hit rates
3. Analyze resource usage

**Solution**:

- Optimize Go module caching
- Increase parallel job limits
- Reduce scan scope if appropriate

#### Issue: Cache Misses

**Symptoms**: Tools reinstalling on every run
**Diagnosis**:

1. Verify cache key generation
2. Check cache size limits
3. Review cache restoration logs

**Solution**:

```yaml
# Optimize cache keys
key: ${{ runner.os }}-${{ runner.arch }}-tool-${{ hashFiles('**/go.sum') }}
```

### Support and Escalation

For additional support:

1. **Internal Documentation**: Check `docs/development/` directory
2. **GitHub Issues**: Create issue with `security` label
3. **Security Team**: Escalate critical security issues
4. **DevOps Team**: Infrastructure and CI/CD issues

## Summary

The CFGMS security workflow provides comprehensive protection from development to production:

- **4 Security Tools**: Vulnerability scanning, dependency analysis, security patterns, code quality
- **Parallel Execution**: 60-70% performance improvement
- **GitHub Integration**: SARIF output, Security tab, status checks
- **Production Gates**: Critical vulnerability blocking with emergency override
- **Automated Remediation**: Claude Code integration for automatic fixes
- **Comprehensive Audit**: Full audit trail for all security decisions
- **Team Ready**: Foundation prepared for team expansion and PR workflows

The workflow ensures security-first development while maintaining developer productivity and providing clear paths for issue resolution.
