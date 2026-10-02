# Script Signing CI Guide

This guide explains how to configure automated script signing in your MSP
script repository using the CFGMS `sign-scripts` GitHub Action.  After setup,
every script change merged to your main branch is automatically signed, and
CFGMS stewards enforce those signatures before executing anything on managed
endpoints.

## Overview

```
MSP script repo (GitHub)          CFGMS steward (endpoint)
─────────────────────────         ───────────────────────────
developer pushes script  ──CI──►  sign-scripts action runs
                                  cfg script sign produces .sig
                                  .sig committed back to branch
                                         │
                                         ▼
                                  steward pulls script + .sig
                                  cfg verifies signature
                                  script executes  ✓
```

Each script resource can require a valid `.sig` sidecar via its own
`signing_policy: required` setting (see [Signing policies](#signing-policies)
below); CI-signed scripts satisfy that requirement once the steward trusts the
signing key (Step 4).

## Prerequisites

- CFGMS v0.4.0 or later (introduces `cfg script sign`)
- A GitHub repository containing your MSP scripts
- A CFGMS steward configured to enforce script signatures (see
  [script module documentation](../modules/script-module.md))

## Step 1: Generate a signing key pair

Generate a dedicated signing key pair for your CI pipeline.  Keep the private
key secret; register only the public key with CFGMS.

**RSA 4096 (recommended for compatibility):**

```bash
openssl genrsa -out signing-key.pem 4096
openssl rsa -in signing-key.pem -pubout -out signing-key.pub
```

**ECDSA P-256 (smaller signatures, equivalent security):**

```bash
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
openssl ec -in signing-key.pem -pubout -out signing-key.pub
```

> **Important:** Do not commit `signing-key.pem` to any repository.
> Delete the private key file after uploading it to GitHub Secrets.

## Step 2: Add the private key as a GitHub secret

1. Open your script repository on GitHub.
2. Go to **Settings → Secrets and variables → Actions**.
3. Click **New repository secret**.
4. Set:
   - **Name:** `SCRIPT_SIGNING_KEY`
   - **Value:** the full PEM content of `signing-key.pem` (including the
     `-----BEGIN ... KEY-----` and `-----END ... KEY-----` lines)
5. Click **Add secret**.

## Step 3: Add the signing workflow

Create `.github/workflows/sign-on-push.yml` in your script repository:

```yaml
name: Sign scripts on push

on:
  push:
    branches: [main]        # adjust to your default branch

permissions:
  contents: write           # required: action commits .sig files back

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 2    # required: action compares HEAD~1..HEAD

      - uses: cfgis/cfgms/.github/actions/sign-scripts@main
        with:
          signing-key: ${{ secrets.SCRIPT_SIGNING_KEY }}
```

Commit and push this file.  On the next push to `main`, the action will
automatically sign any changed scripts and commit the `.sig` sidecars.

## Step 4: Configure CFGMS stewards to trust your signing key

Register the public key thumbprint with each steward that should verify
signatures from this repository.  Add the following to your steward
configuration (typically managed via the CFGMS controller):

```yaml
steward:
  script_signing:
    trust_mode: trusted_keys  # only accept keys in the list below
    trusted_keys:
      - name: "MSP Production Signer"
        thumbprint: "<sha256-thumbprint>"   # see below
```

`trust_mode`, `trusted_keys` and `policy` are all carried into the script
module's runtime signing config (`BuildModuleSigningConfig`,
`features/steward/config/config.go`). **`script_signing.policy` at the
steward level is a fleet-wide enforcement floor.** Setting it to `required`
means every script the steward executes must carry a valid signature,
regardless of that script's own `signing_policy` — a per-script setting may
raise the bar further (e.g. pin a specific trusted key) but can never lower
it below the steward's floor. The field is validated and cascades through
tenant configuration inheritance (a child tenant may only tighten it, never
loosen it — Story #4324), and the resolved floor is enforced on every
execution (Issue #4399). Leaving `policy` unset imposes no floor: whether a
given script requires a signature is then controlled entirely per script —
see [Signing policies](#signing-policies) below.

To obtain the thumbprint:

```bash
# SHA-256 fingerprint of the public key
openssl pkey -in signing-key.pub -pubin -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $2}'
```

Copy the hex output as the `thumbprint` value.

## Step 5: Verify end-to-end

1. Add a test script to your repository and push to `main`.
2. Confirm the signing workflow runs and a corresponding `.sig` file appears
   in the repository.
3. On a script resource with `signing_policy: required`, trigger a script run
   and confirm it executes without a signature error.
4. Manually corrupt the `.sig` file content and confirm the steward rejects
   execution.

## Configuration reference

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `signing-key` | — | PEM-encoded private key (required). Pass via secret. |
| `script-glob` | `**/*.{ps1,sh,py,bat,cmd}` | File extensions to consider for signing. |
| `algorithm` | `rsa-sha256` | Signing algorithm. Match this to the steward config. |
| `cfg-version` | `latest` | Pin to a specific CFGMS release for reproducible builds. |
| `commit-message` | `ci: add script signatures [skip ci]` | Commit message for `.sig` files. |

### Supported algorithms

| Algorithm | Key type | Notes |
|-----------|----------|-------|
| `rsa-sha256` | RSA ≥ 2048 | Default; broadest compatibility |
| `rsa-sha512` | RSA ≥ 2048 | Higher hash strength |
| `ecdsa-sha256` | ECDSA P-256 | Compact signatures |
| `ecdsa-sha384` | ECDSA P-384 | Higher security margin |

The algorithm value must match what is configured in the steward
`script_signing` block that will verify the signatures.

### Signing policies

Whether a given script requires a valid signature is decided by two settings
together: the steward-wide `script_signing.policy` floor (Step 4 above) and
the script's own resource-level `signing_policy` (the `script:` block a
config pushes to the steward — see the `signing_policy` field in the
[script module documentation](../modules/script-module.md)). The steward
executes each script under whichever of the two is more restrictive; a
per-script setting can tighten the floor but can never loosen it.

| Policy | Behaviour |
|--------|-----------|
| `none` | Signatures are ignored (default when neither the steward floor nor `signing_policy` is set) |
| `optional` | Signatures are verified when present, unsigned scripts are allowed |
| `required` | The script is rejected unless it carries a valid `.sig` sidecar signed by a key in the steward's `trusted_keys` |

**Recommended rollout:** start with the steward floor at `optional` (or
unset), verify signatures are being generated and verified correctly, then
set `script_signing.policy: required` on the steward — or `signing_policy:
required` on individual script resources first, if you want to enforce
signing incrementally before raising the fleet-wide floor.

## Windows runners

The action supports `windows-latest` runners out of the box.  PowerShell
scripts (`.ps1`) on Windows runners are signed via `cfg script sign` using a
detached signature, not Windows Authenticode.  Stewards on Windows endpoints
verify the detached `.sig` sidecar.

To run on both Linux and Windows in a matrix:

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

Running on both platforms in a matrix is useful when you want to validate that
signing works on both OSes; for most MSPs a single `ubuntu-latest` job is
sufficient because signature verification is platform-independent.

## Rotating signing keys

1. Generate a new key pair (Step 1).
2. Update the `SCRIPT_SIGNING_KEY` secret in GitHub (Step 2).
3. Add the new public key thumbprint to the steward `trusted_keys` list.
4. Run a full signing pass by re-running the signing workflow (or triggering a
   dummy push).
5. Once all `.sig` files have been regenerated with the new key, remove the
   old thumbprint from `trusted_keys`.

## Troubleshooting

**Action fails with "cfg: command not found"**

The `cfg` binary could not be downloaded.  Check:
- The `cfg-version` input matches a published CFGMS release tag.
- The runner has outbound HTTPS access to `github.com`.
- The `cfgms-repo` input is correct if using a private fork.

**No `.sig` files committed after the workflow runs**

The action only signs files changed in the current push (`HEAD~1..HEAD`).  If
no scripts changed, no signatures are produced.  Verify with:

```bash
git diff --name-only HEAD~1 HEAD
```

Also confirm `fetch-depth: 2` is set on `actions/checkout` — without it
`HEAD~1` does not exist and no files will be detected.

**Steward rejects script despite `.sig` file being present**

- Confirm the algorithm in the action matches `script_signing.algorithm` in
  the steward config.
- Confirm the public key thumbprint in `trusted_keys` matches the key used to
  sign.
- Confirm `trust_mode` allows the key (use `any_valid` temporarily for
  debugging, then revert to `trusted_keys`).

**Signing loop: the sign commit triggers another signing workflow run**

The default `commit-message` includes `[skip ci]` which prevents most CI
systems from re-triggering on the commit.  If your workflow still loops, add
a condition to skip when the commit is from `github-actions[bot]`:

```yaml
on:
  push:
    branches: [main]

jobs:
  sign:
    if: github.actor != 'github-actions[bot]'
```

## Related documentation

- [Script Module](../modules/script-module.md) — full script module reference
- [sign-scripts Action README](../../.github/actions/sign-scripts/README.md) — action inputs and examples
- [Script Signing Configuration](../architecture/operating-model.md) — steward-level signing policy
