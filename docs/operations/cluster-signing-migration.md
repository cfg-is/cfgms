# Cluster Signing Identity Migration

A cluster-mode controller signs configuration and commands with one shared signing
certificate held in the vault (see [Cluster CA Trust Anchor Configuration](cluster-ca.md#config-signing-key-path)).
A cluster that existed before the shared identity has one signing certificate and key per
node, as files in each node's certificate directory. This runbook describes how those
nodes converge on one shared certificate, what each node does on its own, and what the
operator does.

Stewards are moved onto the shared certificate by a second mechanism, described in
[Moving stewards to the shared certificate](#moving-stewards-to-the-shared-certificate).

## Modes

| Mode | Meaning |
|------|---------|
| `legacy_local` | The shared namespace does not hold the cursor's serial (or the cursor is empty). The node signs with its own local certificate. |
| `shared` | The cursor names a serial that resolves in the shared namespace. Every node signs with it. |

A cluster starts in `legacy_local` with an empty shared signing cursor.

## Election rules

The shared certificate is chosen deterministically, never by recency:

1. If the shared cursor already names a serial, that serial is the shared certificate.
   This holds even when another node holds a newer signing certificate.
2. If the cursor is empty, an administrator names a serial with
   [`POST /api/v1/certificates/signing/elect`](../api/rest-api.md#post-apiv1certificatessigningelect).
   The endpoint requires an admin certificate and an unscoped (root) caller, the same gates
   as rotation. The serial must already be in the migration namespace, so only a certificate
   a node has validated can be elected. If a cursor already exists the endpoint answers
   `409` and names the existing serial; an election never overrides a cursor.
3. With neither a cursor nor an explicit election, the cluster stays in `legacy_local`
   and nothing is elected. The controller never picks the newest certificate on its own.

Rotation (`POST /api/v1/certificates/signing/rotate`) stays refused with
`SIGNING_MIGRATION_PENDING` until the cluster is in `shared` mode.

## What each node does

On startup, and then once a minute, every cluster-mode node runs three steps:

1. **Import.** It validates every signing certificate whose key is in its local certificate
   directory and stores each valid one, create-if-absent, in the migration namespace
   (`config-signing/migration/<serial>`). Importing is idempotent and safe to run on every
   node at once.
2. **Promote.** When the cursor names a serial that is in the migration namespace but not
   yet in the shared namespace, the node copies it into the shared namespace
   (create-if-absent) and from then on resolves `shared` mode. Any node can promote; the
   first write wins and the rest see the same material.
3. **Remove local keys.** Once the node is in `shared` mode and has read back every one
   of its local signing certificates from the shared (or migration) namespace and found
   the certificate and key equal, it overwrites and deletes each local signing `key.pem`.
   `cert.pem` and the metadata stay. The step is all or nothing: if any one local key
   cannot be verified, no key is deleted.

A node that is not yet upgraded keeps signing with its local key, which is why nothing is
removed before the node itself is in `shared` mode.

The overwrite before the unlink is best effort. It does not defeat media-level recovery
(journaling filesystems, snapshots, SSD wear levelling); treat a signing key that was ever
on a node disk as exposed to anyone with access to that disk's backing media, and rotate
after the migration if that matters to your threat model.

## Moving stewards to the shared certificate

Once a node is in `shared` mode it signs everything with the shared certificate, which a
steward that trusts only one legacy node key cannot verify. A steward migration service
runs on every node, only while that node is in `shared` mode, and migrates the stewards
connected to that node. Only the node holding a steward's stream receives its completion
events, so each node handles its own stewards; every node holds all legacy signers because
they are in the migration namespace.

For each connected steward with no recorded confirmation for the shared serial, the service
sends `push_signing_cert` commands one at a time, waiting for the steward's completion
event before the next:

1. The shared certificate, signed by the shared key. If the steward completes it, it
   already trusts the shared key.
2. Otherwise the same push signed by each legacy migration signer in turn. The first that
   completes is the key the steward trusts. A steward drops a command signed by an untrusted
   key silently, so each candidate is bounded by a 10 second timeout.
3. A confirmation push signed by the shared key. Its completion proves the steward trusts
   the shared key.
4. The confirmation is recorded in the acknowledgement store (keyed by steward and shared
   serial, visible to every node). Only after that, a push signed by the shared key with
   `retire_serials` naming every legacy migration serial. The steward then trusts the shared
   certificate alone.

The work never delays a steward connecting: the connect hook only queues the steward for a
bounded worker pool (eight stewards at a time per node), and a steward that could not be
migrated is retried no more often than every five minutes. A reconciler re-checks the
stewards connected to the node every 30 seconds, so stewards already connected when the
shared certificate became active are migrated without reconnecting. A steward with a
recorded confirmation is skipped without sending anything.

### Reading progress

`GET /api/v1/certificates/signing/migration` returns the shared serial, the number of
stewards, the number that confirmed and up to 100 unconfirmed steward IDs (see the
[REST API](../api/rest-api.md#get-apiv1certificatessigningmigration)). The endpoint needs an
admin certificate and an unscoped (root) caller.

A steward stays unconfirmed when:

- it is offline, or not connected to any node. Nothing is sent to a steward that is not
  connected; it is migrated on its next connect.
- it trusts none of the keys in the migration namespace (for example it was enrolled on a
  node whose signing certificate was never imported). Every candidate times out; the
  service logs `no candidate key delivered the shared certificate` and retries after the
  backoff. Re-enroll such a steward.
- the confirmation could not be recorded. The legacy certificates are not retired from it.

If the retire push itself does not complete after the confirmation was recorded, the node
retries it after the backoff for as long as the process runs. Restarting the node loses
that memory; the legacy certificates then stay trusted by that steward until they are
retired by an operator revocation (`POST /api/v1/certificates/signing/revoke`).

### When it is safe to delete the migration entries

Delete the entries under `config-signing/migration/` only when the progress endpoint shows
every steward you intend to keep confirmed (`confirmed` equal to `stewards`, an empty
`unconfirmed_steward_ids`). A steward that has not confirmed can only be reached through the
legacy signers held in that namespace. After a later rotation the shared serial changes and
each steward is covered by the normal rotation push.

## When a node refuses a local certificate

A local certificate is refused, never imported, when any of these hold:

| Log reason | Cause |
|------------|-------|
| `certificate was not issued by the cluster CA` | The issuer is not this cluster's CA. |
| `certificate is expired` / `certificate is not yet valid` | Outside its validity window. |
| `certificate lacks the CodeSigning extended key usage` | Not a signing certificate. |
| `private key does not match the certificate` | The local key is not this certificate's key. |
| `refusing to overwrite the signing key already stored ...` | The migration namespace already holds different material for the serial. The message names certificate fingerprints only. |

Each refusal is logged by the node (`signing_migration_refused`) and recorded in the audit
log, once per process per distinct reason. A refused certificate with a key on disk also
stops step 3 on that node, because that key can never be verified in the store; remove it
by hand once you have confirmed it is not needed, after which the node completes the step on
its next pass.

## Audit events

Each event is a `security_event` with the serial, a fingerprint and a reason. None contains
PEM or key bytes.

| Action | When |
|--------|------|
| `signing_certificate_elected` | An administrator elected a serial through the endpoint (records the operator's certificate serial). |
| `signing_migration_imported` | A node imported a local certificate into the migration namespace. |
| `signing_migration_refused` | A node refused a local certificate, or a promotion. |
| `signing_migration_promoted` | A node copied the elected serial into the shared namespace. |
| `signing_migration_local_key_removed` | A node deleted a verified local signing key file. |

## Vault policy for the migration namespace

Nodes need to read and create under `config-signing/migration/` and never to update or
delete. Only the operator deletes. The policy block is in
[Cluster CA Trust Anchor Configuration](cluster-ca.md#config-signing-key-path). Migration
entries hold private keys: keep the vault audit device on for this prefix as well, and
alert on any `update`, `delete` or `destroy` against it.

## Operator procedure

1. Upgrade every controller node. Each imports its local signing certificate; confirm with
   the audit log (`signing_migration_imported`, one per node) or by listing
   `secret/metadata/root/config-signing/migration`.
2. Check the shared cursor. If it already names a serial, nodes promote it on their next
   pass; go to step 4.
3. If the cursor is empty, choose the serial and call the elect endpoint. Pick a
   certificate that stewards already trust.
4. Confirm each node reports `shared` mode and logs `signing_migration_local_key_removed`
   for its local key; no signing `key.pem` should remain under any node's certificate
   directory.
5. Watch `GET /api/v1/certificates/signing/migration` until every steward you intend to keep
   is confirmed.
6. **Cleanup (operator only).** After every node has finished and every steward is
   confirmed, delete the entries under `config-signing/migration/` from the vault with
   `bao kv metadata delete`. Nodes never delete them, and the steward migration reads its
   legacy signers from this namespace, so delete only once the progress endpoint shows no
   unconfirmed stewards.
