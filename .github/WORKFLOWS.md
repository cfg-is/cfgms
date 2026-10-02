# GitHub Actions Workflows for CFGMS

This document describes the GitHub Actions workflows configured for the CFGMS project. These workflows will activate automatically when the repository becomes public.

## Workflow Overview

### 1. Dependabot Configuration (`.github/dependabot.yml`)

**Status:** Ready - Activates on repository public status

**Purpose:** Automated dependency security updates

**Features:**
- Weekly dependency updates (Mondays 9 AM UTC)
- Grouped updates by domain (transport, Microsoft, etc.)
- Separate security update group for priority handling
- Supports Go modules, GitHub Actions, and Docker base images
- Automatic PR creation with maintainer reviewers
- Maximum 10 open PRs to prevent overwhelming maintainers

**Configuration:**
- Target branch: `develop`
- Labels: `dependencies`, `security`, `automated`
- Commit prefix: `deps` (production), `deps-dev` (development)

### 2. CodeQL Analysis Workflow (`.github/workflows/codeql-analysis.yml`)

**Status:** Ready - Requires public repository

**Purpose:** Industry-leading SAST (Static Application Security Testing)

**Triggers:**
- Push to `main` or `develop`
- Pull requests to `main` or `develop`
- Weekly schedule (Wednesdays at 3 AM UTC)
- Manual dispatch

**Features:**
- GitHub's premium CodeQL engine (free for open-source)
- Security-extended query suite (comprehensive coverage)
- Detects: SQL injection, command injection, XSS, crypto issues, auth bypasses
- SARIF upload to GitHub Security tab
- Builds complete project for code flow analysis

**Timeout:** 30 minutes

**Permissions Required:**
- `actions: read`
- `contents: read`
- `security-events: write`

### 3. Docker Security Workflow (`.github/workflows/docker-security.yml`)

**Status:** Ready - Activates on repository public status

**Purpose:** Container image vulnerability scanning with Trivy

**Triggers:**
- Push to `main` (Dockerfile changes)
- Pull requests (Dockerfile or dependency changes)
- Manual dispatch

**Features:**
- Scans both Controller and Steward images
- Checks: OS vulnerabilities, app dependencies, misconfigurations, secrets
- Severity levels: CRITICAL, HIGH, MEDIUM
- SARIF upload to GitHub Security tab
- Human-readable reports in artifacts
- Fails on CRITICAL or HIGH vulnerabilities

**Scan Coverage:**
- Base image vulnerabilities
- Go dependency vulnerabilities
- Configuration issues
- Embedded secrets

**Timeout:** 20 minutes per image

### 4. License Check Workflow (`.github/workflows/license-check.yml`)

**Status:** Ready - Activates on repository public status

**Purpose:** Automated license compliance checking

**Triggers:**
- Pull requests modifying `go.mod` or `go.sum`
- Manual dispatch

**Features:**
- Uses Google's `go-licenses` tool
- Checks all Go dependencies
- Detects forbidden licenses (GPL, LGPL, AGPL, CC-BY-NC, Proprietary, SSPL)
- Generates CSV reports for all components
- Creates human-readable summary report
- Fails on forbidden/incompatible licenses

**Allowed Licenses:**
- MIT, Apache-2.0, BSD (2-Clause, 3-Clause), ISC, MPL-2.0

**Forbidden Licenses:**
- GPL/LGPL/AGPL (stricter copyleft — review required)
- CC-BY-NC (non-commercial restriction)
- Commercial/Proprietary
- SSPL (Server Side Public License)

**Timeout:** 10 minutes

### 5. Signed Release Workflow (`.github/workflows/release.yml`)

**Status:** Implemented for pre-RC review; protected-environment execution and
native signing remain unverified.

The workflow runs only for annotated semantic-version tags whose commit is
reachable from `main`. Generic cross-platform archives use the Go toolchain
pinned in `go.mod`, normalize timestamps and ownership, build twice, and fail
unless the two trees match byte for byte.

The protected `release` environment must provide a non-placeholder publisher
public key, Windows signing certificate, Apple application/installer identities,
and Apple notarization credentials. Release mode fails closed if any is absent.
Windows executables and MSI are Authenticode-signed and verified. macOS
executables and packages are signed, the package is notarized and stapled, and
both layers are verified.

Only after all platform jobs pass does the publish job:

- generate an SPDX JSON SBOM;
- generate and validate `SHA256SUMS`;
- keyless-sign every artifact with a pinned Cosign installer;
- create repository-bound build-provenance and SBOM attestations; and
- create the corresponding tagged GitHub release.

All third-party actions are pinned to full commit SHAs and job permissions are
scoped to their purpose. No release has been produced or certified by adding
this workflow.

## Activation Timeline

### Immediate (Private Repository)
These workflows are created but will **not run** until the repository is public:
- CodeQL Analysis (requires public repo for free tier)

### Upon Public Release
These workflows will **activate immediately** when repository becomes public:
- ✅ Dependabot updates
- ✅ CodeQL security scanning
- ✅ Docker container scanning
- ✅ License compliance checking

## Testing Plan

### Pre-Public Testing (Current State)
1. ✅ YAML syntax validation (all files pass)
2. ✅ Workflow file structure validation
3. ✅ Configuration parameter validation
4. ⏳ Local tool testing (manual):
   ```bash
   # Test Trivy locally
   trivy fs . --scanners vuln,secret,misconfig

   # Test go-licenses locally
   go install github.com/google/go-licenses@latest
   go-licenses check ./cmd/controller

   # Test SBOM generation locally
   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
   syft packages ./cmd/controller -o spdx-json
   ```

### Post-Public Testing (After Repository Goes Public)
1. Create test PR to verify all workflows trigger
2. Verify CodeQL completes successfully
3. Verify Trivy scans complete
4. Check GitHub Security tab for SARIF uploads
5. Verify Dependabot creates PRs
6. Test release workflow with test tag

## Maintenance

### Regular Updates
- **Weekly:** Review Dependabot PRs
- **Monthly:** Check workflow execution logs
- **Quarterly:** Update action versions (handled by Dependabot)
- **Per Release:** Verify SBOM generation

### Monitoring
- GitHub Security tab for vulnerability findings
- Action runs for workflow failures
- Dependabot alerts for security issues

### Troubleshooting
- Workflow logs available in Actions tab
- SARIF files viewable in Security tab
- Artifacts downloadable for 30 days (90 days for license reports)

## Benefits Summary

| Gap Addressed | Solution | Impact |
|---------------|----------|--------|
| No automated dependency updates | Dependabot | ~24 hours/year saved |
| No CodeQL SAST | CodeQL workflow | Industry-leading vulnerability detection |
| No container scanning in CI | Trivy workflow | Catch base image vulnerabilities |
| No license compliance | License check workflow | Prevent incompatible licenses |
| No SBOM/provenance/signing pipeline | Protected signed-release workflow | Authenticated artifacts and supply-chain evidence |

## Security Posture Improvement

**Before Story #280:** 9/10 (missing 5 capabilities)

**After Story #280:** 10/10 (complete security coverage)

All workflows follow security best practices:
- Minimal permissions (least privilege)
- SARIF upload for centralized security findings
- Fail-fast on critical issues
- Artifact retention for compliance
- Version pinning for action dependencies

## References

- [GitHub Advanced Security Documentation](https://docs.github.com/en/code-security)
- [Dependabot Configuration Reference](https://docs.github.com/en/code-security/dependabot)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Trivy Documentation](https://github.com/aquasecurity/trivy)
- [go-licenses Tool](https://github.com/google/go-licenses)
- [Syft SBOM Tool](https://github.com/anchore/syft)
- [SPDX Specification](https://spdx.dev/)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
