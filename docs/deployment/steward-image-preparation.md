# Preparing a Steward Image for Cloning

A base image built from a machine that already enrolled a steward carries that
steward's device key, client certificate and steward ID into every clone. Every
clone then presents the same identity. `cfgms-steward prepare-image` is the
supported way to build an image for planned cloning (ADR-034 §6): it removes the
enrolled identity and leaves the trust anchor and the registration token, so each
clone enrolls as a unique device on first boot through the normal registration and
approval flow.

## When to run it

Run it once, on the machine you are about to capture, after the steward is
installed (`cfgms-steward install --regtoken TOKEN`) and before the image is taken.
Do not start the steward again before capturing the image: a start re-enrolls the
machine and recreates the identity.

```bash
# Linux/macOS
sudo cfgms-steward prepare-image --dry-run   # list what would be removed
sudo cfgms-steward prepare-image             # asks for confirmation
sudo cfgms-steward prepare-image --yes       # no prompt
```

On Windows, run the same commands from an elevated (Administrator) prompt.

| Flag | Meaning |
|------|---------|
| `--dry-run` | List what would be removed. Removes nothing and does not stop the service. |
| `--yes` | Skip the confirmation prompt. |
| `--cert-store-dir` | Certificate store directory. Defaults to the platform path used by the steward; set it only for non-default installs. |

The command requires elevation. It checks that the service definition carries a
registration token, stops the steward service (the supervisor does not restart a
service stopped through the service manager), then removes the identity. If the
token is missing it fails and removes nothing. It never prints the token or key
material.

## What it removes

From the certificate store directory (`/var/lib/cfgms/steward/certs` on Linux,
`%ProgramData%\cfgms\steward\certs` on Windows,
`~/Library/Application Support/cfgms/steward/certs` on macOS):

| Item | Holds |
|------|-------|
| `device_identity.enc` | The device identity key. A new one is generated on first start, which gives the clone a different `DeviceID`. |
| `device_identity_tpm.blob` | On Linux hosts with a TPM, the TPM-wrapped device identity key. It only loads on the TPM that created it. A new key is generated on first start. |
| `steward-identity.json` | Steward ID, tenant, device ID, and for trust-on-first-use installs the CA pin. |
| `steward-pending.json` | Pending registration state. |
| `steward-refresh-pending.json` | A queued re-admission request. |
| `steward-readmit-pace.json` | Re-admission pacing. |
| `revocation.json`, `signing-cursor.json` | Node-local records of the issued credential. |
| `ca/` | The local certificate-store CA and its key. |
| `<serial>/` | Each issued mTLS credential: `cert.pem`, `chain.pem`, `key.pem`, `metadata.json`. |

Removal never follows symlinks, and the command refuses a certificate store
directory that is itself a symlink.

## What it keeps

- The installed binary and the service definition, including its `--regtoken` argument.
- The trust anchor: the install-pinned CA file (`/etc/cfgms/controller-ca.crt`, or
  `%ProgramData%\cfgms\controller-ca.crt` on Windows). A compile-baked trust anchor
  needs nothing.
- Machine-generic state: the key-derivation salt and machine-id files, and the
  steward secrets store (its offline-queue key names no identity). The steward
  keeps no DNA cache or offline queue on disk.

On Linux and macOS the steward derives its at-rest key from the OS machine ID
(`/etc/machine-id`) and the kept salt. Reset the machine ID in the image with your
OS tooling so each clone derives a different key-encryption key.

The service is left stopped and enabled. The command does not start it.

## Trust-on-first-use installs

An install-pinned steward keeps its CA in `controller-ca.crt`, so the clone trusts
the same CA as the original. A trust-on-first-use steward stores its CA pin in
`steward-identity.json`; removing that file means each clone re-pins the controller
CA at first boot. That is a weaker trust path. The command prints a note when it
finds a trust-on-first-use identity. Use `install --controller-ca` for images you
clone.

## TPM access on Linux

On a Linux host with a TPM 2.0, the steward keeps its device key inside the TPM and reports `key_protection_level: tpm`. The service account needs read and write access to the resource-managed device `/dev/tpmrm0`, which is normally owned by group `tss` (add the account to that group, for example `usermod -aG tss cfgms-steward`). Without that access, or without a TPM, the steward uses the encrypted file key and reports `file`; the reason is in the steward log and enrollment is unaffected. The backend is chosen once, at first enrollment: a steward that already has a file key stays on it.

## Running it twice

It is idempotent. On an already-prepared or never-enrolled machine it reports that
there is nothing to remove and exits successfully.

## An image that was not prepared

Cloning without `prepare-image` copies the identity to every clone. This command
neither detects nor repairs that case; it is handled by the copy rules, not by
`prepare-image`. Prepare the image, or stop the service on a clone and run
`prepare-image` on it before it first connects.

## Verification

After a clone boots, it should appear in the controller as a pending or newly
approved device with its own `DeviceID`, distinct from the source machine and from
sibling clones.
