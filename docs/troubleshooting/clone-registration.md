# Steward Re-registered as a New Device (`clone_of`)

## What happened

A steward connected with an identity (steward ID, certificate and device key) that the controller had already approved for another device. The controller decided the connection was a copy — its host provenance differs from the approved machine, or another host already holds the channel — and refused it with the reason `IDENTITY_IN_USE`. The original device is not affected and keeps its channel.

The copy then stopped using the copied key. It generated a new device key, discarded the stored identity it was cloned with, and registered as a new device, naming the original steward ID as `clone_of`. It waits in the normal device approval queue.

## What the operator sees

- `cfg registration pending` lists the new device with the original's steward ID in the `CLONE OF` column. `GET /api/v1/registration/pending` returns the same value as `clone_of`.
- An audit event `steward_clone_registration_queued` (`security_event`, severity `medium`) is written for the queued registration. Earlier events on the original steward ID show why: `steward_provenance_divergence` and `steward_identity_conflict_detected`.
- The pending entry has a different `key_fingerprint` and a new device ID from the original.

`clone_of` is informational. It is kept only when it names an existing steward in the same tenant as the registration token, and it does not influence approval or any authorization decision.

## What to do

1. Confirm the new device is the machine you expect (hostname, source IP, key fingerprint checked on the device).
2. Approve it with `cfg registration approve <pending-id>` if it should join the fleet as its own device, or deny it with `cfg registration deny <pending-id>`.
3. If the original and the copy should not both exist, remove or re-image the copy; nothing needs to change on the original.

## If the refusal was wrong

A legitimate hardware change on the original can make it look like a copy. A steward refused this way also re-registers as a new device; deny that entry and re-baseline the original through the registration-refresh approval (`cfg steward refresh list|approve`).

## Interrupted re-keying

The steward records the original steward ID in `steward-clone-of.json` (in the cert store, mode 0600) before it changes its key. If it stops mid-way, it resumes registering with the new key on the next start and never reuses the copied one. The file is removed once the new identity is connected.
