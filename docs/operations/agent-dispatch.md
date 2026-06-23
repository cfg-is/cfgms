# Agent Dispatch

Operational reference for the `agent-dispatch.sh` lifecycle, with a focus on
the credential lifecycle introduced in Issue #2124.

---

## Credential Lifecycle

Each agent container launched by `agent-dispatch.sh launch <N>` receives a
**short-lived, tenant-scoped, least-privilege API key** bound to the
`agent-test/<N>` sub-tenant and the `agent.dev` role. This document covers
how those credentials are minted, injected, and revoked.

### Roles and permissions

The `agent.dev` role grants read-only access sufficient for a dev agent to
inspect controller state but not modify it:

| Permission | Description |
|---|---|
| `steward:read` | Read steward metadata |
| `steward:list` | List stewards in the tenant |
| `steward:read-config` | Read steward configuration |
| `steward:read-modules` | Read module assignments |
| `steward:validate-config` | Validate configuration without applying it |
| `config:list` | List config objects |
| `config:list-deployments` | List deployments |
| `tenant:read` | Read tenant metadata |

Write operations (`config:create`, `config:update`, `config:delete`),
management operations (`steward:manage`, `terminal:*`, `rbac:*`), and
system-admin operations are explicitly excluded.

### Mint (launch)

When `agent-dispatch.sh launch <N>` runs:

1. **Create sub-tenant** — `POST /api/v1/tenants` with
   `{"id": "<N>", "parent_id": "agent-test"}`. Returns HTTP 201 on creation
   or HTTP 409 when the tenant already exists (idempotent — both are success).

2. **Issue API key** — `POST /api/v1/api-keys` with
   `{"name": "agent-<N>", "role_id": "agent.dev", "tenant_id": "agent-test/<N>"}`.
   The controller binds the key to the sub-tenant and records an RBAC
   `RoleAssignment` for audit.

3. **Write to tmpfs** — The key value is written to
   `/run/cfgms/agent-cred/<N>/api.key` (permissions: `0600`, dir `0700`) and the
   key ID to `/run/cfgms/agent-cred/<N>/api.key.id` (`0600`). On Linux hosts,
   `/run` is a tmpfs mount — credentials never reach disk.

4. **Inject into container** — The cred dir is bind-mounted read-only at
   `/run/cfgms/agent-cred` inside the container. The container receives:

   | Env var | Value |
   |---|---|
   | `CFGMS_API_KEY_FILE` | `/run/cfgms/agent-cred/api.key` |
   | `CFGMS_TENANT` | `agent-test/<N>` |
   | `CFGMS_TIER1_URL` | Tier 1 controller base URL |

   The **key value is never in a container env var** — `docker inspect` shows
   only the file path. The key is never in the `claude-creds` volume and never
   baked into an image layer.

**Mint failure** — if the sub-tenant creation or key issuance fails, the
dispatcher emits `CRED_MINT_FAILED:<reason>`, removes any partial cred dir,
and exits non-zero without starting a container.

### Revoke (cleanup)

All three cleanup paths call `revoke_agent_creds <N>` before removing the
container and clone:

- `cleanup-issue <N>` — normal agent exit path
- `cleanup-stale` — orphan sweep for closed/failed/blocked stories
- `cleanup-stale-reviews` — orphan sweep for review containers

The revoke sequence for issue agents:

1. **Delete API key** — `DELETE /api/v1/api-keys/<key-id>`. The in-memory
   cache entry is removed immediately; any in-flight request with the key
   receives HTTP 401 with no cache flush required.

2. **Suspend sub-tenant** — `POST /api/v1/tenants/agent-test/<N>/suspend`
   sets `status: suspended`. Suspended tenants cannot issue new keys or
   authenticate new sessions.

3. **Remove cred dir** — `/run/cfgms/agent-cred/<N>/` is deleted; because it
   lives in tmpfs the data is gone from RAM immediately.

**No-op safety** — if `/run/cfgms/agent-cred/<N>/` does not exist (agent was
launched before Issue #2124 or cred was already cleaned), the revoke path
emits `INFO:no_cred_to_revoke:<N>` and continues without error.

**Controller-unreachable** — if the controller cannot be reached during
revocation, the failure is recorded to
`/run/cfgms/agent-cred/<N>/revoke-failed.txt` (`0600`) in the format:

```
<key-id> <unix-timestamp> <error>
```

Container and clone removal proceed regardless — revocation failures never
block cleanup. The file is left for manual follow-up.

### Required host configuration

| Env var | Purpose |
|---|---|
| `CFGMS_TIER1_URL` | Tier 1 controller base URL, e.g. `https://ctrl.cfgms.lab:9080` |
| `CFGMS_TIER1_ADMIN_KEY` | Admin API key for mint/revoke calls (preferred) |
| `CFGMS_ADMIN_BUNDLE` | Path to admin mTLS bundle (used if `CFGMS_TIER1_ADMIN_KEY` is unset) |

One of `CFGMS_TIER1_ADMIN_KEY` or `CFGMS_ADMIN_BUNDLE` must be set for
launch and cleanup operations that reach the controller. If neither is set,
mint fails with `CRED_MINT_FAILED:no auth available`.

### Security properties

- Key value never appears in `docker inspect` env output.
- Key value never enters the `claude-creds` Docker volume.
- Key value never appears in the image (not baked in at build time).
- Credentials live in RAM only (Linux `/run` tmpfs) and are destroyed on host
  reboot even if cleanup is skipped.
- The `agent.dev` role is fail-closed: it goes through full RBAC and tenant
  isolation enforcement on every controller request — no admin short-circuit.
- Tenant isolation enforcement (Issue #2123) blocks cross-tenant access: a
  key bound to `agent-test/42` cannot read `agent-test/43` data.
