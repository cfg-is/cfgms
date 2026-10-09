# Release Artifact Verification

CFGMS release binaries are **unsigned**. Pushing a release tag publishes a
GitHub release with raw binaries and a `SHA256SUMS` file. The checksum file
detects corruption or a mismatched download; it does not authenticate the
publisher, because it is served from the same release as the binaries.

## What the release carries

- `cfgms-controller-linux-amd64`
- `cfgms-steward-<os>-<arch>` for `linux`, `darwin` and `windows`, each `amd64`
  and `arm64` (`.exe` suffix on Windows)
- `SHA256SUMS`, covering every binary above

The release notes are the matching `CHANGELOG.md` section. When the repository
variable `CFGMS_RELEASE_PUBLISHER_KEY` is unset, the notes begin with a line
stating the steward binaries carry the development placeholder publisher key.

The workflow publishes nothing unless the tag is annotated, is canonical
semantic versioning, resolves to the checked-out commit, and is reachable from
`main`. Every binary is built twice with the pinned Go toolchain and compared
byte for byte before it is published.

## Verify a downloaded artifact

Download the binaries you need and `SHA256SUMS` into one directory, then:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

On macOS use `shasum -a 256 -c SHA256SUMS`; on Windows compare
`Get-FileHash -Algorithm SHA256 <file>` with the matching line.

The Tier-1 and HA-node bootstrap scripts perform this check automatically for
`cfgms-controller-linux-amd64` and refuse to install on a mismatch.

Because the binaries are unsigned, macOS Gatekeeper and Windows SmartScreen may
warn on first run, and hosts enforcing application allowlisting must allow the
binaries explicitly.
