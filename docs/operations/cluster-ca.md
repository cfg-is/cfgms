# Cluster CA Trust Anchor Configuration

In a cluster-mode deployment, the controller CA is sourced from a shared OpenBao secret store
rather than being auto-generated on each node. This ensures all cluster nodes present server
certificates that stewards already trust and accept steward client certificates issued by any
peer node.

Two ways a cluster's CA identity is established:

- **Self-generated root** (below) — the default, self-hosted path. The cluster generates its
  own root CA on first boot and stores it in the vault.
- **Regional intermediate** (see [Regional Intermediate (SaaS)](#regional-intermediate-saas)
  below) — a SaaS cell imports an intermediate CA issued out-of-band by an offline root
  ceremony instead of self-generating a root (ADR-032 Decision 2).

## How It Works (Self-Generated Root)

1. **First node (`--init`):** generates the CA in-process, stores the CA cert + private key
   PEM in OpenBao KV v2, writes only the CA public cert to disk (`ca/ca.crt`). The CA private
   key never touches node disk.

2. **Subsequent nodes (`--init`):** retrieve the CA from OpenBao and populate the cert manager
   in-process. The CA key remains vault-only; only `ca/ca.crt` is written for TLS config.

3. **Normal startup:** on every boot, each node loads the CA from OpenBao before issuing or
   verifying any leaf cert.

## Prerequisites

- OpenBao (or compatible Vault) with KV v2 enabled.
- A service token with `read`/`write` access to the configured KV path. The token is supplied
  via `OPENBAO_TOKEN` or `BAO_TOKEN` environment variable — **never** in the config file.
- OpenBao must be reachable over **HTTPS** in production. An `http://` address is rejected
  at startup when `CFGMS_TELEMETRY_ENVIRONMENT=production`.

## Configuration

Add the `certificate.cluster_ca` block to `controller.cfg`:

```yaml
ha:
  mode: cluster

# Deployment-wide realm qualifier naming this cell (ADR-032 Decision 3). Required
# once CFGMS_TELEMETRY_ENVIRONMENT=production — the controller refuses to start
# a production cluster deployment without it. See the "Realm Assignment" section
# below.
realm_id: cell1

certificate:
  enable_cert_management: true
  ca_path: /var/lib/cfgms/ca

  cluster_ca:
    # OpenBao server URL. MUST be https:// in production.
    vault_address: https://vault.example.com:8200

    # KV v2 path where the cluster CA is stored.
    # Format: "<tenantID>/<key-name>"
    # The cert is stored at this path, the key at "<path>-key", and — for an
    # imported regional intermediate — its issuer chain at "<path>-chain".
    vault_key_path: root/cluster-ca

    # Optional: path to a PEM CA cert for verifying vault's TLS certificate.
    # Required when vault uses a private CA.
    # vault_tls_cert: /etc/cfgms/vault-ca.crt

    # Optional: KV v2 mount path (default: "secret").
    # vault_mount_path: secret
```

### Environment Variable Overrides

| Variable | Description |
|---|---|
| `CFGMS_CLUSTER_CA_VAULT_ADDRESS` | Override `vault_address` |
| `CFGMS_CLUSTER_CA_VAULT_KEY_PATH` | Override `vault_key_path` |
| `OPENBAO_TOKEN` | Vault service token (preferred) |
| `BAO_TOKEN` | Alternative vault token env var |

## Security Requirements

**HTTPS in production is mandatory.** The CA private key transits the network during
`LoadCAFromSecretStore` calls. Transmitting it over plaintext HTTP exposes the fleet trust
root. The production guard (`CFGMS_TELEMETRY_ENVIRONMENT=production`) rejects `http://`
vault addresses at startup.

**Token source.** The vault token must come from `OPENBAO_TOKEN` or `BAO_TOKEN` environment
variables. Never write the token into `controller.cfg`; it would be world-readable on disk.
Use a secret injection mechanism (systemd `EnvironmentFile`, Kubernetes secret mount, etc.).

**Key path isolation.** Restrict the service token's policy to the specific KV path used for
the cluster CA. The controller only needs `read` on steady-state nodes and `read`+`write` on
the `--init` node. Example OpenBao policy:

```hcl
path "secret/data/root/cluster-ca" {
  capabilities = ["read", "create", "update"]
}
path "secret/data/root/cluster-ca-key" {
  capabilities = ["read", "create", "update"]
}
```

## Realm Assignment

`realm_id` names this cluster's home cell (ADR-032 Decision 3). It is a single
deployment-wide config value — never stored per-tenant — so every tenant's realm-qualified
identity (`Manager.QualifiedTenantID`) is computed on demand from whatever `realm_id` is
currently configured. There is no per-tenant record to migrate if it is assigned, or
corrected, at any point before a cross-cell surface starts persisting the qualified form.

`realm_id` must be a single Kubernetes DNS label: lowercase alphanumeric characters and
hyphens, no leading or trailing hyphen, 63 characters or less (`cell1`, `cell-us-east-1`).
It is **not** a slash-delimited path — tenant hierarchy is carried by a tenant's parent, never
by string concatenation — so values like `root/msp-a`, `Cell1` or `../..` are rejected. A
malformed `realm_id` refuses to start on every deployment shape and in every environment, not
just production clusters.

**Production cluster deployments must set `realm_id`.** When `CFGMS_TELEMETRY_ENVIRONMENT=production`
and `ha.mode: cluster`, the controller refuses to start with `realm_id` empty — this is what
makes "a realm is assigned before the first production tenant exists" an enforced fact rather
than an optional field nobody sets. Self-hosted deployments (`ha.mode` unset or not `cluster`)
are not gated on emptiness and can leave `realm_id` unset.

## Regional Intermediate (SaaS)

ADR-032 Decision 2 requires that a SaaS cell's controller cluster start up holding a
**regional intermediate** CA — a certificate + private key obtained out-of-band from an
offline root ceremony — instead of self-generating its own root. The offline root itself, and
the ceremony that signs the first regional intermediate under it, are an operations procedure
outside this repository; see ADR-032 for the trust hierarchy this establishes. This section
only covers the config keys that hand the already-issued intermediate to the cluster.

Add three more keys under `certificate.cluster_ca`, alongside the vault keys above:

```yaml
certificate:
  enable_cert_management: true
  ca_path: /var/lib/cfgms/ca

  cluster_ca:
    vault_address: https://vault.example.com:8200
    vault_key_path: root/cluster-ca

    # Regional intermediate import (ADR-032 Decision 2). All three must be set
    # together — a partial set is rejected at startup, before any vault or file
    # I/O happens. Omit all three to fall back to the self-generated-root path
    # above.
    external_intermediate_cert_path: /etc/cfgms/regional-intermediate.crt
    external_intermediate_key_path: /etc/cfgms/regional-intermediate.key
    external_intermediate_chain_path: /etc/cfgms/regional-intermediate-chain.pem
```

- `external_intermediate_cert_path` — the regional intermediate's own certificate, PEM-encoded.
- `external_intermediate_key_path` — the intermediate's private key, PEM-encoded. Read once at
  import time from this local path; **never written to any node's disk** — same invariant as
  the self-generated path above. The vault is the only durable copy.
- `external_intermediate_chain_path` — the issuer chain from the intermediate up to and
  including the offline root (root-terminal). This is what lets `GetCACertificate()` resolve
  the true fleet trust anchor (the offline root) instead of the intermediate's own
  currently-active certificate, and what lets every issued leaf carry the intermediate in its
  own chain for handshake assembly.

When these three paths are set, cluster CA init imports the named material instead of
self-generating, and persists the intermediate's cert (`<vault_key_path>`), private key
(`<vault_key_path>-key`) **and issuer chain** (`<vault_key_path>-chain`) to the vault, so every
cluster node converges on the same vault-held identity. The chain is what makes that
convergence complete: a peer whose own `controller.cfg` has no `external_intermediate_*` keys
loads all three from the vault and therefore publishes the same trust anchor — the offline root
— and issues leaves carrying the same intermediate. Re-import happens on every process start
(the same "every boot, not just `--init`" rule the self-generated path follows) — it is
idempotent, since the same external files produce the same material each time.

Two refusals bound what a boot can do to an established cluster's identity, because
overwriting published CA material invalidates every certificate the cluster has already issued:

- **Import never replaces a different identity.** Each secret is written create-if-absent
  (compare-and-swap), and material already published at the key path is accepted only when it
  is the same material. Pointing a running cluster's `external_intermediate_*` keys at
  different material — or booting a node with stale intermediate material mid-rotation — fails
  closed with an error naming the mismatching certificate fingerprints, leaving the vault
  untouched. Rotating the cluster onto a genuinely new identity is therefore an explicit
  operator action against the vault, never a side effect of editing a config file.
- **A node never generates a CA over unusable or unreadable published material.** The
  self-generate path bootstraps only when the vault says the key path holds nothing at all —
  the store's own "secret not found" signal, never any other read failure. A cert whose key or
  issuer chain is missing is reported as an error rather than silently replaced, and so is a
  read that fails because the node's token lacks `read` on the key path, has expired, points at
  a misconfigured KV mount, or timed out: those leave the real CA published, and treating them
  as absence would re-root the fleet on one boot. The bootstrap write is create-if-absent
  (compare-and-swap) like the import write, so even a misclassified read cannot overwrite a
  published CA — a node that finds the key path already claimed adopts the published CA
  instead of its own generated one.

A vault holding an intermediate's cert + key with **no** `-chain` secret beside it is rejected
at load: without the chain a node cannot tell that its certificate is not the fleet root, and
would publish the routinely-rotated intermediate as the stewards' permanent pinned anchor. If
you see that error, restore the `-chain` secret (the root-terminal issuer chain for the
published intermediate) rather than deleting the CA material.

Rotating the region's active intermediate (signing and deploying a new intermediate under the
same offline root) is an operations action, not a code path this repository automates — ADR-032
records intermediate rotation as "per-region and routine." A steward that pinned the offline
root while one intermediate was active continues to trust leaves issued under a sibling
intermediate with no re-enrollment, because the steward's permanently-pinned trust anchor is
always the root, never an intermediate.

## Single-Node Deployments

Set `ha.mode: single` (or omit `ha`) and leave `certificate.cluster_ca` unconfigured.
The controller generates the CA on first boot, saves `ca.crt` and `ca.key` locally, and
loads them from disk on restart. No vault dependency.

## See also

The OpenBao unseal key and root token this mechanism depends on are not
stored in this repository. Capture them into your deployment's own credential
store the moment they are minted — the unseal key cannot be recovered if lost,
and it protects the cluster CA.
