# Cluster CA Trust Anchor Configuration

In a cluster-mode deployment, the controller CA — the fleet trust root — is sourced from a
shared OpenBao secret store rather than being auto-generated on each node. This ensures all
cluster nodes present server certificates that stewards already trust and accept steward
client certificates issued by any peer node.

## How It Works

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
    # The cert is stored at this path; the key at "<path>-key".
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

## Single-Node Deployments

Set `ha.mode: single` (or omit `ha`) and leave `certificate.cluster_ca` unconfigured.
The controller generates the CA on first boot, saves `ca.crt` and `ca.key` locally, and
loads them from disk on restart. No vault dependency.

## See also

The OpenBao unseal key and root token this mechanism depends on are not
stored in this repository. Capture them into your deployment's own credential
store the moment they are minted — the unseal key cannot be recovered if lost,
and it protects the cluster CA.
