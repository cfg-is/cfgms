# Trivy Rollback Runbook

This runbook covers what to do if the currently-pinned Trivy release (`v0.70.0`) is later flagged as compromised, OR if Trivy itself starts producing untrusted results.

## Context

Trivy was the target of a supply-chain compromise in March 2026 (advisory [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23), CVE-2026-33634). The threat actor "TeamPCP" published malicious releases as `v0.69.4`, `v0.69.5`, and `v0.69.6` and force-pushed compromised tags on `aquasecurity/trivy-action` and `aquasecurity/setup-trivy`. The advisory's safe versions were `v0.69.2` and `v0.69.3` (binary), `v0.35.0` (trivy-action SHA `57a97c7e7821a5776cebc9bb87c984fa69cba8f1`), and `v0.2.6` (setup-trivy SHA `3fb12ec12f41e471780db15c232d5dd185dcb514`).

`v0.70.0` is the project's first post-incident release, published 2026-04-17 with a new GPG key (`B5690EEEBB952194`) for deb/rpm repositories. CFGMS adopts `v0.70.0` based on the project's release announcement and the SHA-256 verification baked into our install path.

## Detection — when to roll back

Roll back if any of these conditions hold:

1. The advisory page is updated to mark `v0.70.0` as compromised or revoked.
2. A subsequent release publishes its own advisory referencing `v0.70.0` as malicious.
3. Trivy in CI starts producing anomalous output: unexpected network calls, unusually large binary size, scan results that don't match other scanners, mass-false-positive or mass-false-negative vulnerability data.
4. The project rotates GPG / sigstore signing keys again without a clear announcement.

Do NOT roll forward to `v0.69.4`, `v0.69.5`, or `v0.69.6` under any circumstances — those releases are confirmed-malicious. Roll BACK to `v0.69.3`.

## Rollback — pin to v0.69.3

`v0.69.3` is the last pre-incident clean release. The APT repository no longer ships it, so installation must use the GitHub release archive directly with checksum verification.

### Verified-install one-liner (use this — never `curl install.sh | sh`)

```bash
./.github/scripts/install-trivy.sh v0.69.3 \
  1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
```

This is the same install helper used by `v0.70.0`. It verifies the archive SHA-256 before extraction. The hash above is the upstream-published SHA-256 of `trivy_0.69.3_Linux-64bit.tar.gz` and is hardcoded here so that a runtime fetch of `checksums.txt` (which would defeat the purpose if the supply chain is mid-compromise) is not required.

### Manual procedure (if the install helper itself is suspect)

```bash
ARCHIVE="trivy_0.69.3_Linux-64bit.tar.gz"
EXPECTED="1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75"

curl -sSfL -o "/tmp/${ARCHIVE}" \
  "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/${ARCHIVE}"
printf '%s  /tmp/%s\n' "${EXPECTED}" "${ARCHIVE}" | sha256sum -c -
tar -xzf "/tmp/${ARCHIVE}" -C /tmp trivy
sudo install -m 0755 /tmp/trivy /usr/local/bin/trivy
rm "/tmp/${ARCHIVE}" /tmp/trivy
```

### What to update when rolling back

1. `.devcontainer/Dockerfile` — `TRIVY_VERSION` and `TRIVY_SHA256` in the Trivy install RUN block.
2. `.github/workflows/security-scan.yml` — both invocations of `install-trivy.sh`.
3. `.github/workflows/production-gates.yml` — the install invocation.
4. `.github/workflows/docker-security.yml` — `TRIVY_VERSION` env var (line 35). The SHA-pinned `aquasecurity/trivy-action` and `aquasecurity/setup-trivy` references at lines 53/81/104/140/168/191 must NOT change — those SHAs are the advisory-confirmed safe versions.
5. `.github/workflows/dependency-pin-check.yml` — `check_version "trivy"` argument and the denylist regex (the v0.69.4–v0.69.6 entries stay; do NOT add v0.70.0 to the denylist on rollback unless the advisory confirms compromise).
6. `Makefile` — error-handler echo strings in the `security-trivy` target.
7. This runbook — update the rollback SHA if you're rolling back to a different version.

## Out of scope

- Rolling back the `aquasecurity/trivy-action` or `aquasecurity/setup-trivy` SHA pins. Those are advisory-blessed and should remain pinned at `57a97c7e...` and `3fb12ec1...` respectively until the advisory recommends new SHAs.
- Replacing Trivy with another scanner. If `v0.69.3` and `v0.70.0` are both compromised, that is a project-wide incident requiring a different decision (Grype, Snyk OSS, etc.) — not a one-line pin change.
