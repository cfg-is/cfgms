# sign-scripts — CFGMS Script Signing Action

A composite GitHub Action that signs scripts changed in a push using
`cfg script sign` and commits the resulting `.sig` sidecar files back to the
branch.  CFGMS stewards verify these signatures before executing any script,
providing end-to-end integrity guarantees across your MSP fleet.

## Quick start

```yaml
# .github/workflows/sign-on-push.yml (in your MSP script repository)
name: Sign scripts on push

on:
  push:
    branches: [main]

permissions:
  contents: write   # required: action commits .sig files back

jobs:
  sign:
    runs-on: ubuntu-latest   # or windows-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2       # required: action compares HEAD~1..HEAD

      - uses: cfgis/cfgms/.github/actions/sign-scripts@main
        with:
          signing-key: ${{ secrets.SCRIPT_SIGNING_KEY }}
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `signing-key` | **yes** | — | PEM-encoded RSA or ECDSA private key. Pass via a GitHub secret. |
| `script-glob` | no | `**/*.{ps1,sh,py,bat,cmd}` | Glob pattern controlling which extensions are considered. |
| `algorithm` | no | `rsa-sha256` | Signing algorithm: `rsa-sha256`, `rsa-sha512`, `ecdsa-sha256`, `ecdsa-sha384`. |
| `cfg-version` | no | `latest` | CFGMS release version to download (e.g. `v0.4.0`). Pin for reproducible builds. |
| `commit-message` | no | `ci: add script signatures [skip ci]` | Commit message used when pushing `.sig` files. |
| `cfgms-repo` | no | `cfgis/cfgms` | Override when running from a private CFGMS fork. |

## How it works

1. **Changed-file detection** — compares `HEAD~1..HEAD` to find only the
   scripts touched in the current push (not the entire repository).
2. **Binary download** — fetches the appropriate `cfg` binary for the runner
   OS from CFGMS GitHub Releases.
3. **Key handling** — writes the signing key to a temporary file with `0600`
   permissions; the file is removed via `trap`/`finally` even on failure.
4. **Signing** — runs `cfg script sign --key <tmp> --algorithm <algo>` for
   each changed script, producing a `<script>.sig` sidecar.
5. **Commit** — stages only `*.sig` files and pushes them back to the branch.
   If no new signatures were generated the step is skipped.

## Required secrets setup

1. Generate a signing key pair (RSA 4096 or ECDSA P-256):

   ```bash
   # RSA
   openssl genrsa -out signing-key.pem 4096
   openssl rsa -in signing-key.pem -pubout -out signing-key.pub

   # ECDSA
   openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
   openssl ec -in signing-key.pem -pubout -out signing-key.pub
   ```

2. Add the **private key** as a repository secret named `SCRIPT_SIGNING_KEY`:
   - Repository → Settings → Secrets and variables → Actions → New repository secret
   - Name: `SCRIPT_SIGNING_KEY`
   - Value: paste the full PEM content including `-----BEGIN ... KEY-----` headers

3. Register the **public key** in your CFGMS steward configuration:

   ```yaml
   steward:
     script_signing:
       policy: required
       trust_mode: trusted_keys
       trusted_keys:
         - name: "MSP Production Signer"
           thumbprint: "<sha256-thumbprint-of-signing-key.pub>"
   ```

## Examples

### Pin to a specific cfg release

```yaml
- uses: cfgis/cfgms/.github/actions/sign-scripts@main
  with:
    signing-key: ${{ secrets.SCRIPT_SIGNING_KEY }}
    cfg-version: 'v0.4.0'
    algorithm: 'rsa-sha256'
```

### Sign only PowerShell scripts

```yaml
- uses: cfgis/cfgms/.github/actions/sign-scripts@main
  with:
    signing-key: ${{ secrets.SCRIPT_SIGNING_KEY }}
    script-glob: '**/*.ps1'
    algorithm: 'rsa-sha256'
```

### Windows runner

```yaml
jobs:
  sign:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2
      - uses: cfgis/cfgms/.github/actions/sign-scripts@main
        with:
          signing-key: ${{ secrets.SCRIPT_SIGNING_KEY }}
```

### Multi-platform matrix

```yaml
jobs:
  sign:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2
      - uses: cfgis/cfgms/.github/actions/sign-scripts@main
        with:
          signing-key: ${{ secrets.SCRIPT_SIGNING_KEY }}
```

## Requirements

- **CFGMS v0.4.0+** — the `cfg script sign` subcommand was introduced in this
  release.  See [Script Signing CI Guide](../../docs/guides/script-signing-ci.md)
  for the full setup walkthrough.
- **`contents: write` permission** — the action commits `.sig` files back to
  the branch.  Add `permissions: contents: write` to the job or workflow.
- **`fetch-depth: 2`** on `actions/checkout` — required so `HEAD~1` is
  available for changed-file detection.

## Security notes

- The signing key is passed via an environment variable (not an inline
  expression) so GitHub's automatic secret masking applies in all log output.
- The key is written to a `0600` temp file that is always removed, even when
  a signing step fails.
- Only `*.sig` files are ever staged and committed — the action never touches
  other repository content.
- Pin the action to a specific commit SHA in production for supply-chain
  security, e.g. `cfgis/cfgms/.github/actions/sign-scripts@<sha>`.
