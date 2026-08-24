# ADR-030: Controller Secret Material at Rest — Root of Trust per Deployment Shape

**Status:** Accepted

**Date:** 2026-08-20

**Deciders:** Founder, Architecture

**Related:**
- Story [#3422](https://github.com/cfg-is/cfgms/issues/3422) — this ADR is its deliverable
- Story [#3462](https://github.com/cfg-is/cfgms/issues/3462) — implements the script changes this
  decision prescribes for `scripts/ha-cluster-node-bootstrap.sh` and
  `scripts/tier1-bootstrap.sh`
- Story [#3130](https://github.com/cfg-is/cfgms/issues/3130) — established the byte-identical
  `secrets.key` requirement across cluster nodes and added the `/run/credentials/` mode-0440
  exception to `pkg/secrets/providers/sops`
- Story [#3417](https://github.com/cfg-is/cfgms/issues/3417) — product-vs-private documentation
  convention (Decision 4 below provides the ownership-boundary text #3417's AC#4 references)
- Epic [#3412](https://github.com/cfg-is/cfgms/issues/3412) — separate private lab documentation
  from the public product repository; this story closes its Scope item 4
- `scripts/tier1-bootstrap.sh:358-359,381` — `LoadCredential=` + `InaccessiblePaths=` reference
- `pkg/secrets/providers/sops/store.go:102-113` — `/run/credentials/` mode-0440 exception
- `pkg/secrets/providers/openbao` — existing managed-root provider
- `pkg/secrets/providers/oskeychain/provider_linux.go` — Secret Service and kernel keyring backends
- `docs/testing/controller-ha-real-cluster-runbook.md` — cluster bootstrap history and known gaps

---

## Context

### What SOPS relocates, not eliminates

CFGMS's default secrets backend (`pkg/secrets/providers/sops`) envelope-encrypts every secret
at rest using a 32-byte AES key loaded at startup from `CFGMS_SECRETS_KEY_FILE`. SOPS relocates
the cleartext-at-rest problem to a single key rather than eliminating it: `secrets.key` itself
currently arrives at the controller as a cleartext file on disk, written during bootstrap
(`scripts/tier1-bootstrap.sh` via `openssl rand`, `scripts/ha-cluster-node-bootstrap.sh` via
`base64 -d` from a caller-supplied env var).

`CLAUDE.md`'s zero-tolerance rule ("No cleartext secrets on disk. Even in development.") is not
satisfied by either script today for `secrets.key`, nor by `ha-cluster-node-bootstrap.sh` for the
four HA-cluster secrets it writes to `/etc/cfgms/ha-secrets.env`.

### What the scripts already get right

`scripts/tier1-bootstrap.sh` (lines 358-359, 381) generates `secrets.key` and wires it into the
service unit as:

```systemd
LoadCredential=cfgms-secrets-key:/etc/cfgms/secrets.key
Environment=CFGMS_SECRETS_KEY_FILE=%d/cfgms-secrets-key
InaccessiblePaths=/etc/cfgms/secrets.key
```

systemd reads the file as root before privilege drop, re-exposes it on tmpfs under
`/run/credentials/`, unit-namespaced, mode `0400`, destroyed on stop — and then blocks the
service from reading the original path via `InaccessiblePaths=`. `pkg/secrets/providers/sops`
accepts `/run/credentials/` paths at mode `0440` since #3130 (`store.go:102-113`).

`scripts/ha-cluster-node-bootstrap.sh` matches this wiring for `secrets.key` (lines 512-513).

### The concrete defect in the cluster path

`ha-cluster-node-bootstrap.sh` writes four values to `/etc/cfgms/ha-secrets.env` (lines 332-341:
`CFGMS_STORAGE_DB_PASSWORD`, `CFGMS_SESSION_HMAC_KEY`, and optionally `OPENBAO_TOKEN` /
`BAO_TOKEN`) and loads them via `EnvironmentFile=/etc/cfgms/ha-secrets.env` (line 511). This is
mitigated only by `InaccessiblePaths=/etc/cfgms/ha-secrets.env` (line 541).

`EnvironmentFile=` is materially weaker than `LoadCredential=`: the environment of a running
process is readable via `/proc/<pid>/environ` by root, and all environment variables are
inherited by every child process the service spawns. The credential directory is not. The fix is
#3462; this ADR establishes the decision those fixes implement against.

### The deeper gap: `secrets.key` is still cleartext on disk

Even with correct `LoadCredential=` wiring, `/etc/cfgms/secrets.key` exists in cleartext on disk
throughout the controller's life. `InaccessiblePaths=` prevents the *service* from re-reading
it at runtime; it provides no protection if an attacker has root on the host before or during
bootstrap, or if a disk image or VM snapshot is copied off the host. The key must not exist in
cleartext on persistent storage at all.

### Three deployment shapes with distinct threat profiles

**Single-node / on-prem / VM / bare metal.** One controller; `secrets.key` is not shared with
other nodes. The root of trust can be hardware-local to the host.

**HA cluster.** Multiple controller nodes sharing one `secrets.key`. Story #3130 established why
this must be byte-identical: secrets persisted as shared rows in the cluster Postgres backend are
envelope-encrypted under `secrets.key`; whichever node writes first determines the key, and every
other node fails to decrypt with `secret ciphertext authentication failed` if it holds a different
key. A hardware-local root cannot satisfy this requirement in isolation — the same plaintext key
must reach each node through some secure distribution path.

**Operator workstation.** Where `cfg` and `cfg bundle` are run; not a daemon; short-lived
interactive sessions. A different actor from the controller daemon with a different lifecycle and
different threat model.

---

## Decision 1 — On-prem / single-node: TPM2-sealed credentials via `systemd-creds`

For single-node deployments (bare metal, VM on controlled infrastructure, on-prem), `secrets.key`
is sealed to the local TPM2 at provisioning time using `systemd-creds encrypt --with-key=tpm2`.
The sealed blob replaces the cleartext file on disk. The unit carries:

```systemd
LoadCredentialEncrypted=cfgms-secrets-key:/etc/cfgms/secrets.key.cred
Environment=CFGMS_SECRETS_KEY_FILE=%d/cfgms-secrets-key
InaccessiblePaths=/etc/cfgms/secrets.key.cred
```

> **Correction (2026-08-22, applied while implementing #3462).** This snippet and the one in
> Decision 2 originally read `LoadCredential=`. That directive does **not** decrypt: it copies the
> file through verbatim, so the service would have received the sealed blob rather than the key.
> The directive that unseals a `systemd-creds`-encrypted credential is
> **`LoadCredentialEncrypted=`**, and it is what both bootstrap scripts emit. Verified live on
> `cfgms-ha-node2`: with `LoadCredentialEncrypted=`, the plaintext appears at
> `$CREDENTIALS_DIRECTORY/<id>` mode 0440; with a blob systemd cannot unseal, the unit refuses to
> start with `status=243/CREDENTIALS`.

`secrets.key.cred` is a `systemd-creds`-encrypted blob, decryptable only by the TPM2 on the host
where it was sealed. It cannot be recovered from a stolen disk image or VM snapshot. The cleartext
`secrets.key` is never written to a file at any point — it exists only in the pipe between the
generator and `systemd-creds encrypt` (see the migration steps below).

**Why `systemd-creds` over raw `tpm2-tools`.** `systemd-creds` integrates directly with
systemd's credential machinery and delivers the decrypted value via `/run/credentials/`, exactly
where `pkg/secrets/providers/sops` already expects it (the `isSystemdCredentialPath` exception in
`store.go` covers this path). It handles PCR selection, key binding, and the sealed-blob format
without bespoke tooling.

**Virtual TPM (vTPM) threat model.** Hyper-V Generation 2 VMs and most modern hypervisors
support vTPM. The effective threat boundary for a vTPM is the hypervisor host — a stolen VHDX
together with the hypervisor's vTPM state store defeats vTPM sealing. For VMs running on
infrastructure within the operator's own physical trust boundary (the lab cluster, on-prem MSP
deployments), vTPM sealing is sufficient. For VMs running on shared or multi-tenant cloud
infrastructure, Decision 2 applies instead.

**`tier1-bootstrap.sh` migration.** The script currently generates `secrets.key` in cleartext
and writes it to `/etc/cfgms/secrets.key`. #3462 updates it to:

1. Generate and seal in one step, with no intermediate file — `systemd-creds encrypt` reads the
   plaintext from stdin when given `-` as its input path:

   ```bash
   openssl rand 32 | systemd-creds encrypt --with-key=tpm2 - /etc/cfgms/secrets.key.cred
   ```

2. Replace the unit's `LoadCredential=` line with `LoadCredentialEncrypted=`, pointing at `.cred`.
3. Remove the `InaccessiblePaths=` line for the now-absent cleartext file; add one for the `.cred`
   file.

**No temporary file, on tmpfs or anywhere else.** An earlier draft of this step wrote the key to a
temp file under `$TMPDIR` and shredded it afterwards. That is unsound on the targets CFGMS runs on
and is rejected here:

- `$TMPDIR`/`/tmp` is **not** tmpfs by default on Debian and Ubuntu — it is a directory on the root
  filesystem. The 32-byte SOPS master key would land on persistent storage, which is the exact
  condition this ADR exists to eliminate and a zero-tolerance violation of `CLAUDE.md`'s "No
  cleartext secrets on disk. Even in development."
- `shred` does not reliably destroy the data it overwrites on ext4, XFS, or btrfs (journalling and
  copy-on-write may leave the original blocks intact) or on wear-levelled SSDs and thin-provisioned
  virtual disks (the overwrite may be redirected to different physical blocks). The mitigation
  fails precisely on the storage stacks these controllers use.
- `PrivateTmp=` offers no protection: the bootstrap script runs from an operator shell, not from
  inside the systemd unit, so the unit's namespacing does not apply to it.

If a future variant of this step genuinely cannot use stdin, it must create the file with
`mktemp -p /run` (or `/dev/shm`) **and** assert the target is tmpfs before writing — e.g.
`findmnt -no FSTYPE --target /run` returning `tmpfs`, aborting the bootstrap otherwise. A path that
is merely *expected* to be tmpfs is not an assertion.

The existing cluster (`cfgms-ctrl-01` on `cfgms-ctrl-01`, `cfgms-ha-node2`,
`cfgms-ha-node3`) was provisioned before this decision and holds cleartext `secrets.key` files.
Migration requires sealing each node's existing key to its own TPM. #3462 documents and performs
that upgrade.

---

## Decision 2 — HA cluster / SaaS: OpenBao as the managed root

For multi-node cluster deployments, the root of trust is OpenBao
(`pkg/secrets/providers/openbao`), already deployed as part of the HA stack
(`cfgms-lab-datasvc:8200`; see `docs/testing/controller-ha-real-cluster-runbook.md` §3).

`secrets.key` and the four HA-cluster secrets (`CFGMS_STORAGE_DB_PASSWORD`,
`CFGMS_SESSION_HMAC_KEY`, `OPENBAO_TOKEN`/`BAO_TOKEN`) are stored in OpenBao's KV v2 store at
designated paths known to the bootstrap script.

At provisioning time each node:

1. Receives a bootstrap OpenBao token via caller-supplied env var (the same mechanism the existing
   `OPENBAO_TOKEN`/`BAO_TOKEN` parameter already uses). The bootstrap token is a use-limited or
   time-limited token that only has read access to the cluster secrets paths — not a root token.
2. Authenticates to OpenBao and pulls each secret.
3. Seals each value as a separate `systemd-creds encrypt --with-key=tpm2` credential file. A node
   with no usable TPM2 **fails provisioning** unless the operator has explicitly opted into the
   host-key path (see below).
4. Records the key mode actually used (`tpm2` or `host`) in the node's bootstrap init record, so
   the binding strength of every node in the cluster is auditable after the fact rather than
   inferred.
5. Stores each sealed blob at a fixed path alongside the unit configuration.
6. The unit carries individual `LoadCredentialEncrypted=` lines pointing to those sealed blobs,
   and no `EnvironmentFile=` lines.

**Why not `--with-key=auto`.** `auto` silently falls back to the host key in
`/var/lib/systemd/credential.secret` when no TPM2 is available. That file sits on the same
persistent disk as the sealed blob, so a stolen VHDX or VM snapshot yields both halves — which
voids the "cannot be recovered from a stolen disk image or VM snapshot" guarantee this ADR makes
for Decision 1, and voids the per-node replay protection claimed below (both halves travel
together, so the blob unseals anywhere). The downgrade happens with **zero signal to the
operator**: provisioning succeeds, the unit starts, and nothing in the resulting system
distinguishes a TPM-bound node from a disk-bound one. Security must not degrade silently when a
precondition is absent; if the TPM is missing, the operator has to know and decide.

**The host-key path is an explicit, loud opt-in.** Where an operator accepts disk-bound sealing —
a lab node with no vTPM, a hypervisor that cannot present one — the bootstrap takes
`--allow-host-key` (env: `CFGMS_BOOTSTRAP_ALLOW_HOST_KEY=1`), which selects
`systemd-creds encrypt --with-key=host`. `host` rather than `auto` is deliberate: the chosen mode
is then unambiguous rather than dependent on what the node happened to have at seal time. In this
mode the bootstrap emits a warning at provisioning time naming the consequence ("credential is
bound to /var/lib/systemd/credential.secret on this node's disk, NOT to a TPM; a stolen disk image
yields the plaintext") and writes `key_mode: host` to the init record. `auto` is not offered by the
bootstrap at all.

**Why this satisfies the byte-identical requirement.** All nodes read the same `secrets.key`
value from the same OpenBao path. The local `systemd-creds` sealing is per-machine so a stolen
disk image from one node cannot be replayed on another, but the underlying plaintext is
authoritative in OpenBao and byte-identical across the fleet.

**Why OpenBao over cloud KMS.** OpenBao is already deployed as the cluster CA backend and
already has a provider in `pkg/secrets/providers/openbao`. For deployments on cloud
infrastructure where a cloud KMS (AWS KMS, Azure Key Vault, GCP KMS) is preferred, the delivery
mechanism is identical — values are pulled at bootstrap and sealed locally — but the source is
the cloud KMS rather than OpenBao. This ADR does not preclude cloud KMS; it designates OpenBao as
the reference implementation for the self-hosted cluster shape because it is already present and
tested.

**Shared-key distribution path at cluster founding.**

1. The founding operator generates `secrets.key` (32 random bytes) out-of-band on a workstation
   with a functioning OS keychain (Decision 3 explains why the workstation keychain is appropriate
   here). The key lives only in the workstation's session-scoped keychain entry during this step —
   never written to disk.
2. The operator stores it in OpenBao at a designated cluster path (e.g.
   `secret/cfgms/cluster/secrets-key`) using the OpenBao CLI or API.
3. Each node's bootstrap pulls the key from OpenBao and seals it to the node's own TPM2 (or, under
   the explicit `--allow-host-key` opt-in, to the node's host key). The plaintext never touches any
   node's persistent disk as a cleartext file.
4. After provisioning the last node, the operator removes any workstation-side temporary copy.
   OpenBao holds the single authoritative copy.

**Reconciling byte-identical with per-machine TPM sealing.** Per-machine TPM sealing means the
sealed blobs differ per node, but the underlying plaintext is the same value stored in OpenBao.
This satisfies both requirements: the key is byte-identical in plaintext (all nodes decrypt the
same secrets), and the sealed blobs are bound to their respective hosts (a stolen VHDX from
`cfgms-ha-node2` cannot be unsealed on `cfgms-ha-node3`).

This replay protection holds only for `key_mode: tpm2` nodes. A node provisioned under
`--allow-host-key` carries its unsealing key (`/var/lib/systemd/credential.secret`) on the same
disk as its blobs, so a stolen image of *that* node yields the plaintext — the blob is still not
replayable on a different node, but it does not need to be. This is the reason the key mode is
recorded per node in step 4: the cluster's at-rest guarantee is the weakest node's, and that has to
be readable from the init records rather than guessed.

**Recovery.** A node that cannot unseal its credential (TPM state lost, vTPM removed) must fail
loudly at startup — it must never generate a fresh random key as a fallback. The operator re-runs
the bootstrap (or an equivalent targeted step) on the affected node to pull from OpenBao and
re-seal with the new TPM. The node then restarts cleanly with the correct shared key.

**Upgrade path for the existing lab cluster** (running `EnvironmentFile=` as of
`develop` @ `62594a79`):

1. Verify that the four HA secrets and `secrets.key` are already stored in OpenBao on
   `cfgms-lab-datasvc`. (They were introduced there at cluster founding per the runbook §3; this
   step confirms the paths match what #3462's updated bootstrap script expects.)
2. Run the updated `ha-cluster-node-bootstrap.sh` (#3462) on each node. The script replaces
   `/etc/cfgms/ha-secrets.env` with per-secret sealed credential files and regenerates the unit
   without `EnvironmentFile=`, adding individual `LoadCredentialEncrypted=` lines.
3. Stop all three nodes together (coordinated shutdown is required because Raft state is
   in-memory — a node restarted alone while its peers are running re-bootstraps as a lone
   self-elected leader and diverges from its peers: `panic: tocommit(4) is out of range
   [lastIndex(3)]` reproduced live in #3130's runbook §3).
4. Start all three nodes together. Verify quorum via `GET /api/v1/raft/status` agreeing on a
   nonzero leader across all three nodes before declaring the migration complete.

---

## Decision 3 — OS keychain: ruled out for controller daemons, retained for operator workstations

**Ruled out for the controller daemon on all deployment shapes.**

On Linux, `pkg/secrets/providers/oskeychain/provider_linux.go` exposes two backends in fallback
order (`platformNewBackend`, line 25):

- **Secret Service** (`secretServiceBackend`, line 54): delegates to `secret-tool`
  (libsecret → gnome-keyring or KWallet). Requires `DBUS_SESSION_BUS_ADDRESS` in the process
  environment. `available()` returns `false` when that variable is absent (line 73), which is the
  normal state for a systemd service on a headless server. Auto-unlocking gnome-keyring at boot
  requires a keyring password stored somewhere at boot, reintroducing the same problem one level
  deeper with an additional daemon in the path.

- **Kernel session keyring** (`keyringBackend`, line 125): headless-safe — no D-Bus required, and
  `available()` succeeds wherever `keyctl` syscall access is granted (line 134-136). However, the
  kernel session keyring is scoped to the user's login session. Keys added to
  `KEY_SPEC_SESSION_KEYRING` are flushed when the session ends. A systemd service that must
  survive reboots, administrator logout, or session key rotation cannot rely on a session-scoped
  keyring; every restart after the session that wrote the key ends would fail to find it.

There is no path to headless, reboot-safe secret delivery via the OS keychain on Linux that is not
also a worse version of `systemd-creds` + TPM2: any scheme that makes the OS keychain unlock
automatically at boot requires a stored credential, which is the same problem `systemd-creds` +
TPM2 solves directly and without an extra daemon.

On macOS, the Keychain daemon is always running, but `security find-generic-password` requires
the item to be created on that specific keychain — a headless service account that never logs in
interactively cannot populate it at bootstrap time without a pre-existing credential source.

On Windows, DPAPI is session-scoped in a similar way for domain user accounts; LSA protected
storage is usable for services but requires Windows-native APIs not present in the current
`oskeychain` provider.

**Retained for the operator workstation.** `pkg/secrets/providers/oskeychain` is the correct
provider for `cfg` and other interactive tooling where:

- The operator is present and the OS session is active.
- The secret's lifetime should be the session — a `cfg` session token that outlives the
  administrator's working session is a security liability, not a feature.
- The Secret Service or kernel keyring is available (they are on any desktop/laptop running a
  modern Linux distribution or macOS).

The operator workstation is also the correct location for the temporary holding of `secrets.key`
during cluster founding (Decision 2, step 1 of the shared-key distribution path) — the session
keyring provides a scratch space for a value that must not touch disk but must survive the 30-60
seconds between generation and upload to OpenBao.

---

## Decision 4 — Ownership boundary: this repository is the product

**This repository** holds code, product documentation, and illustrative examples. It never holds
data about any specific deployment — credentials, host names, keychain target names, inventories,
operational state, or any other deployment-specific material — encrypted or not.

Encryption does not change this boundary. The objection is not that the data is readable; it is
that it is deployment data in a product repository. A SOPS-encrypted `secrets.yaml` for a specific
lab controller is as out of place here as a cleartext one. The reason the removed
`docs/operations/lab-secrets-inventory.md` belonged in a private notes repository rather than here
was not that it was sensitive — it was that it was deployment state, not product documentation.

**A deployment's own configuration may live in that deployment's own repository.** Anyone
running CFGMS — including a maintainer operating a personal lab — keeping their controller
configuration and SOPS-encrypted secrets in a repository they own is a supported, intended
pattern. `CLAUDE.md` already names "Git with SOPS encryption" as the default storage backend;
that is what SOPS is for. The product ships a documented pattern for exactly this use.

**This rule constrains maintainers of this repository, not users of the product.** A user of CFGMS
keeping their deployment secrets in their own git repository, encrypted with SOPS and their own
`secrets.key`, is the product working as designed. Nothing in this decision restricts or discourages
that pattern. The restriction is on the *maintainers of this repository* committing deployment-
specific material to a product repository with a public audience, regardless of whether that
material is sensitive in isolation.

---

## Consequences

### Immediate (addressed by #3462)

- `scripts/tier1-bootstrap.sh` generates `secrets.key` in cleartext today. #3462 updates it to
  generate and seal in a single pipeline (`openssl rand 32 | systemd-creds encrypt
  --with-key=tpm2 - …`) with no intermediate file to shred, and update the unit's
  `LoadCredentialEncrypted=` path to the `.cred` blob.
- `scripts/ha-cluster-node-bootstrap.sh` writes four secrets to `/etc/cfgms/ha-secrets.env` and
  loads them via `EnvironmentFile=`. #3462 removes `ha-secrets.env`, seals each of the four
  secrets individually via `systemd-creds encrypt --with-key=tpm2` after pulling from OpenBao,
  and replaces the `EnvironmentFile=` line with individual `LoadCredentialEncrypted=` lines. #3462 also
  implements the `--allow-host-key` opt-in (warning + `key_mode` in the init record) and fails
  provisioning on a TPM-less node without it; `--with-key=auto` appears in neither script.
- `scripts/ha-cluster-node-bootstrap_test.sh`'s assertions against `ha-secrets.env` and
  `EnvironmentFile=` must be updated by #3462 to match the new sealed-credential pattern.
- The upgrade path for the existing lab cluster (Decision 2's numbered steps) is executed as part
  of #3462's live-validation step.

**Amendment (2026-08-22, #3462) — `<VAR>_FILE` indirection was required to implement Decision 2.**
The decision assumed a credential could be handed to the controller purely by wiring the unit. That
holds for `secrets.key`, which the controller already reads by *path*
(`CFGMS_SECRETS_KEY_FILE`). It did not hold for the other three: `CFGMS_STORAGE_DB_PASSWORD` and
`CFGMS_SESSION_HMAC_KEY` are expanded from `${VAR}` references in `controller.cfg` and
`OPENBAO_TOKEN`/`BAO_TOKEN` are read directly from the environment by
`pkg/secrets/providers/openbao`, so every one of them could only arrive *by value* in the process
environment — exactly what this ADR removes. Delivering them as credentials therefore needed a
by-path form, and #3462 added the conventional one:

- `features/controller/config/config.go` resolves `${VAR}` from `<VAR>_FILE`'s contents when `VAR`
  itself is unset. The direct variable still wins, so nothing about the existing environment
  override behaviour changes.
- `pkg/secrets/providers/openbao` resolves its token from `OPENBAO_TOKEN_FILE` / `BAO_TOKEN_FILE`
  on the same terms.

Both reject a world-accessible file and treat a declared-but-unreadable one as an error rather than
as "unset" — a broken credential must not silently degrade into a missing variable or an empty
token. `ClusterCAConfig`'s doc comment ("the vault token must be supplied via the `OPENBAO_TOKEN`
or `BAO_TOKEN` environment variable — never in the configuration file") still holds: the token is
still never in the config file, and now need not be in the environment either.

### Deferred

- `pkg/secrets/providers/openbao`'s `Available()` reads only `OPENBAO_ADDR`, not the resolved
  `certificate.cluster_ca.vault_address` (surfaced as bug #2 in
  `docs/testing/controller-ha-real-cluster-runbook.md` §3, worked around operationally via
  `OPENBAO_ADDR` in the unit environment). The credential-based bootstrap path in #3462
  works around this gap but does not fix it. A targeted fix to the openbao provider is the correct
  resolution and should be filed as a follow-up story.
- Cloud KMS integration (AWS KMS, Azure Key Vault, GCP KMS) is consistent with Decision 2's
  cluster shape but requires a new provider or extension to `pkg/secrets`. Not in scope for #3422
  or #3462.
- macOS controller deployments (if the controller binary ever targets macOS) and Windows
  controller deployments (if the controller runs as a Windows service) require separate ADRs — the
  `systemd-creds` delivery mechanism is Linux-specific, and the equivalent platform facilities
  (Secure Enclave, DPAPI/LSA) would need their own design analysis.

### Non-decisions

- The systemd-credential + `InaccessiblePaths=` delivery pattern is retained unchanged across all
  shapes. This is already the correct architecture; the decisions above are about what sits behind
  the credential (and about using the `Encrypted` form of the directive), not about replacing it.
- `pkg/secrets/providers/sops`'s mode-0440 exception for `/run/credentials/` paths
  (`store.go:102-113`) is already correct and is not modified.
- The `systemd-creds decrypt` step at service startup is handled by systemd before the service
  process starts — no application-level change is needed in `cfgms-controller` itself.
