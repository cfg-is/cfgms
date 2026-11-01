# Fleet Upgrades

This document describes the operator workflow for upgrading steward binaries across a fleet using the `cfg` CLI.

## Overview

The upgrade workflow has five steps:

1. **Sign** — produce the publisher signature over the binary.
2. **Publish** — upload the steward binary and its signature to the controller's blob store.
3. **Approve** — approve the published blob before dispatch (separate approval step).
4. **Dispatch** — send the upgrade command to matching stewards.
5. **Monitor or rollback** — check per-steward status, and roll back if needed.

## Step 1: Sign the steward binary

Unsigned uploads are rejected. The publisher signature covers a canonical
`content_hash|version|platform|arch` message, so a signature is valid **only** for the
exact version, platform, and arch it was minted for:

```
go run ./scripts/sign-steward-binary /path/to/steward-linux-amd64 v0.5.12 linux amd64
```

This writes `<binary>.sig` and prints the content hash and the URL-safe base64 signature.

By default it signs with the zero-seed **dev** publisher key, which only dev/lab
controllers trust. To sign for a fleet that trusts a real publisher identity, supply the
32-byte Ed25519 seed as standard base64 in `CFGMS_PUBLISHER_SEED`.

> **Why the coordinates are signed.** A content-hash-only signature lets a compromised
> controller serve a genuinely signed *older, vulnerable* binary at a *newer* version's
> URL: the signature verifies, the SHA-256 matches, and the downgrade guard is bypassed
> because the version is controller-attested rather than signed. Binding the coordinates
> closes that rollback path (Issue #2834).

## Step 2: Publish the steward binary

Use `cfg installer publish` to upload the binary and its signature:

```
cfg installer publish \
  --kind steward \
  --version v0.5.12 \
  --platform linux \
  --arch amd64 \
  --binary /path/to/steward-linux-amd64 \
  --signature /path/to/steward-linux-amd64.sig
```

The version, platform, and arch **must** match the values the binary was signed for, or
the controller rejects the upload with `SIGNATURE_VERIFICATION_FAILED`. Add `--force` to
overwrite an existing binary at the same coordinates.

The command prints the blob ID on success. The blob starts in `published` state
and must be approved before it can be dispatched.

### Migrating binaries signed before coordinate binding

Binaries signed under the previous content-hash-only scheme no longer verify. Re-sign and
re-publish (with `--force`) every steward binary the fleet may still converge to **before**
rolling out a controller/steward build that enforces the new scheme — otherwise every
upgrade fails closed until the re-publish completes.

## Step 3: Approve the binary (separate approval step)

Approval is performed via the controller API or admin tooling. A blob in
`published` state cannot be dispatched — dispatch returns 403 until the blob
transitions to `approved`. See the controller administration guide for the
approval workflow.

## Step 4: Dispatch the upgrade

Use `cfg steward upgrade` to dispatch the upgrade to stewards matching a selector:

```
cfg steward upgrade <selector> --version <version>
```

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--version` | Yes | Target steward version (e.g. `v0.5.12`) |
| `--platform` | No | Target platform (`linux`, `windows`). Auto-detected from blob metadata if omitted. |
| `--arch` | No | Target architecture (`amd64`, `arm64`). Auto-detected from blob metadata if omitted. |
| `--wait` | No | Block until all dispatched stewards reach a terminal state |
| `--wait-timeout` | No | Maximum wait duration when `--wait` is set (default: `2m`) |
| `--url` | No | Controller API URL (overrides `CFGMS_API_URL`) |
| `--tls-ca-cert` | No | Path to CA certificate for TLS verification |

Note: `--tls-insecure` is not available on the upgrade command.

### Examples

```bash
# Upgrade a specific steward (async — prints upgrade ID and returns)
cfg steward upgrade id:steward-1780659937223058807 --version v0.5.12

# Upgrade all stewards in a group and wait for completion
cfg steward upgrade group:production --version v0.5.12 --wait --wait-timeout 10m

# Upgrade with explicit platform and arch
cfg steward upgrade id:steward-abc123 --version v0.5.12 --platform linux --arch amd64
```

### Output (async)

```
Upgrade id: abc123-upgrade-id
Dispatched to: 12 stewards
```

### Output (with --wait)

```
Upgrade id: abc123-upgrade-id
Dispatched to: 3 stewards
Waiting... 3 of 3 stewards still in progress
Waiting... 1 of 3 stewards still in progress
DEVICE                                STATUS
------                                ------
steward-1780659937223058807           committed
steward-2890769947334169918           committed
steward-3901879957445270929           committed
```

Exit code is 1 if any steward reaches `failed` or `rolled_back` state.

Both the steward and the privileged launcher enforce the downgrade boundary.
The steward accepts only valid semantic versions and passes an override to the
launcher only when `allow_downgrade` is explicitly authorized. The launcher
independently rejects an older semantic version (including a
release-to-prerelease rollback) and rejects opaque candidates after
semantic-version migration. A direct privileged downgrade requires the
launcher's explicit `--allow-downgrade` flag.

## Step 5a: Check upgrade status

Use `cfg steward upgrade status` to check per-steward upgrade progress:

```
cfg steward upgrade status [selector]
cfg steward upgrade status --upgrade-id <id>
```

### Flags

| Flag | Description |
|------|-------------|
| `--upgrade-id` | Query a specific upgrade record by ID |
| `--url` | Controller API URL |
| `--tls-ca-cert` | Path to CA certificate |

Pass either a positional selector argument or `--upgrade-id`. If a selector is
given, the most recent upgrade record per matching steward is returned.

### Examples

```bash
# Check a specific upgrade by ID
cfg steward upgrade status --upgrade-id abc123-upgrade-id

# Check the most recent upgrade status for a steward
cfg steward upgrade status id:steward-abc123

# Check upgrade status for all production stewards
cfg steward upgrade status group:production
```

### Output

```
STEWARD                                VERSION   STATUS     COMPLETED_AT
-------                                -------   ------     ------------
steward-1780659937223058807            v0.5.12   committed  2026-06-09T10:00:00Z
steward-2890769947334169918            v0.5.11   committed  2026-06-08T14:30:00Z
```

## Step 5b: Roll back an upgrade

Use `cfg steward upgrade rollback` to roll back a dispatched upgrade:

```
cfg steward upgrade rollback --upgrade-id <id> [--to-version <ver>]
```

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--upgrade-id` | Yes | Upgrade record ID to roll back |
| `--to-version` | No | Target version to roll back to (optional; used with `--upgrade-id`) |
| `--url` | No | Controller API URL |
| `--tls-ca-cert` | No | Path to CA certificate |

Rollback requires an explicit `--upgrade-id`. There is no selector-based
most-recent rollback — the upgrade record must be identified explicitly to
prevent accidental fleet-wide rollbacks.

### Examples

```bash
# Roll back a specific upgrade
cfg steward upgrade rollback --upgrade-id abc123-upgrade-id

# Roll back to a specific prior version
cfg steward upgrade rollback --upgrade-id abc123-upgrade-id --to-version v0.5.10
```

### Output

```
DEVICE                                STATUS
------                                ------
steward-1780659937223058807           rolled_back
```

## Upgrade state machine

Each steward tracks upgrade state independently:

| State | Description |
|-------|-------------|
| `dispatched` | Upgrade command sent to steward; awaiting acknowledgement |
| `committed` | Steward successfully upgraded and running new version |
| `failed` | Upgrade failed; steward is on the previous version |
| `rolled_back` | Upgrade was explicitly rolled back |

Terminal states are `committed`, `failed`, and `rolled_back`. The `--wait` flag
polls until all stewards reach a terminal state.
