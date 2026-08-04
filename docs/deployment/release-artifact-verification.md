# Release Artifact Verification

The signed-release workflow is a pre-RC control and has not yet produced or
certified a release. When a protected tag build is eventually published, verify
an artifact before extracting or executing it.

## What the release carries

For every supported archive or native installer, the release workflow produces:

- `SHA256SUMS`, covering the primary archives, installers, and SPDX JSON SBOM;
- a keyless Sigstore bundle beside each covered file
  (`<artifact>.sigstore.json`);
- an SPDX JSON software bill of materials;
- repository-bound GitHub build-provenance and SBOM attestation bundles;
- Authenticode-signed Windows executable payloads and MSI; and
- Developer ID-signed, notarized, and stapled macOS payloads and packages.

The workflow publishes nothing unless the tag is annotated, is canonical
semantic versioning, resolves to the checked-out commit, and is reachable from
`main`. Its protected `release` environment must supply all publisher and native
signing identities. The generic archives are built twice with the pinned Go
toolchain and compared byte for byte before signing.

## Verify a downloaded artifact

With GitHub CLI attestation support:

```bash
gh attestation verify cfgms-linux-amd64.tar.gz \
  --repo cfg-is/cfgms \
  --signer-workflow cfg-is/cfgms/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

Or verify its attached keyless signature with Cosign:

```bash
cosign verify-blob \
  --bundle cfgms-linux-amd64.tar.gz.sigstore.json \
  --certificate-identity \
    "https://github.com/cfg-is/cfgms/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer \
    "https://token.actions.githubusercontent.com" \
  cfgms-linux-amd64.tar.gz
```

Then verify the authenticated checksum manifest:

```bash
sha256sum -c SHA256SUMS
```

The Tier-1 bootstrap performs the repository-bound GitHub-attestation check
automatically when a compatible `gh` is installed. Otherwise it requires
Cosign and pins the exact release workflow, tag, and GitHub Actions OIDC issuer.
It refuses extraction if neither verifier is available or verification fails.

## Native checks

After Sigstore/GitHub verification, native platform policy can be checked
independently:

```powershell
signtool verify /pa /all cfgms-steward-windows-amd64.msi
```

```bash
pkgutil --check-signature cfgms-steward-darwin-arm64.pkg
xcrun stapler validate cfgms-steward-darwin-arm64.pkg
```

Do not treat a checksum alone as publisher authentication.
