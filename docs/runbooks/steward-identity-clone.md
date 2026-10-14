# Steward Identity Clone Runbook

Use this when the controller has detected one steward identity on two machines
(ADR-034): an image was cloned, a disk was copied, or credentials were stolen. The
controller refuses the second machine automatically; nothing is resolved until an
operator decides. No code path moves or replaces an identity on its own.

## 1. Detect

```
cfg steward clones list
```

Each row is a steward ID with the peer address of the machine that already held the
identity (EXISTING PEER), the other peer (OTHER PEER), when it was first and last
detected, and each queued copy (QUEUED COPY is its pending ID, HOSTNAME its hostname).
The copy registers itself with a new device key and `clone_of` set to the original ID, so
it appears in `cfg registration pending` as well. `--format json` also lists the names
(never values) of the provenance fields that differed.

## 2. Decide which machine is the original

`cfg steward status <steward-id>` shows `key_protection_level` (`file`, `tpm` or
`secure-enclave`; `unknown` for a record that predates the field) and `key_algorithm`.
`file` means the device key is a file, so a copy of the machine that holds that file can
sign as the steward; `tpm` and `secure-enclave` keys cannot be copied off the hardware.
`--json` returns the same fields.

Compare the peer addresses and the queued hostname with what you expect the steward to
be. Check the machine itself where you can. Then choose:

| Situation | Action | State left behind |
|-----------|--------|-------------------|
| Both machines are legitimate (planned or accepted clone) | **Split**: `cfg registration approve <pending-id>` | The copy becomes its own steward with a new ID; the original is untouched. |
| The copy is unwanted and the original is safe | **Remove the copy**: `cfg registration deny <pending-id>` | The queued entry is denied; the original is untouched. |
| The copy is unwanted and the original's credentials may be stolen | Deny the copy, then **rotate**: `cfg steward rotate-credentials <steward-id>` | All certificates for the ID are revoked and the record is `archived`. |
| The machine that kept the identity is the wrong one | **Move**: `cfg steward move-identity <steward-id> --to <pending-id>` | The record is rebound to the queued machine, which claims under the original ID. |

### Rotate and revoke

`rotate-credentials` revokes every client certificate issued for the steward ID. The
certificate stored on the approved machine is refused at once, including on streams
that are already open. It sets the record to `archived`, so the next refresh is queued
for approval whatever the refresh policy says. The approved machine runs the normal
re-admission handshake with its device key; finish with `cfg refresh approve <pending-id>`
after you have checked that machine. A copy that does not hold the device key cannot
complete the handshake.

**Limit for file-backed keys.** If the device key is stored in a file
(`key_protection_level: file`), a copy that has the key can also file a refresh
request. Approve only after verifying the machine that asked. Hardware-backed keys
(`tpm`, `secure-enclave`) remove that case, because the key cannot be copied.

### Move

`move-identity` is for the case where the queued copy is the real machine. It requires
a pending registration in the same tenant whose `clone_of` is the steward ID. It:

1. rebinds the steward record to the queued machine's device identity and clears the
   provenance baseline, so that machine re-baselines at its first admission (a device
   already held by another live steward in the tenant is refused, changing nothing);
2. points the queued entry at the original steward ID and approves it;
3. revokes every certificate previously issued for that ID.

The queued machine then claims its registration and receives a certificate whose
common name is the original steward ID. The previous machine's certificate is revoked
and it is refused. If the revocation step fails after the move, the command reports
it; run `cfg steward rotate-credentials <steward-id>` to finish revoking, which
also archives the record, so approve its refresh afterwards.

## Permissions

`cfg steward clones list` needs `steward:read`. `rotate-credentials` and
`move-identity` need `steward:rotate-credentials` and `steward:move-identity`, both
at AssuranceStrong. Each writes a high-severity security audit event
(`steward_credentials_rotated`, `steward_identity_moved`) listing the revoked serials.
