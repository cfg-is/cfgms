# Agent Dispatch

Operational reference for the `agent-dispatch.sh` lifecycle — environment
variables, container lifecycle, credential flows, Tier 1 connectivity, and
tenant isolation.

---

## Environment Variables

### Container-side (injected by the dispatcher)

These variables are set in every agent container launched by
`agent-dispatch.sh launch <N>`.

| Variable | Example | Description |
|---|---|---|
| `CFGMS_TIER1_URL` | `https://ctrl.cfgms.lab:9080` | Base URL of the Tier 1 controller REST API. All `cfg` CLI calls use this as the server endpoint. |
| `CFGMS_API_KEY_FILE` | `/run/cfgms/agent-cred/api.key` | Path to the scoped API key file inside the container. The key value is **never** in an env var; `docker inspect` shows only the file path. |
| `CFGMS_TENANT` | `agent-test/42` | The agent's own sub-tenant. The `agent.dev` role assigned to the key is scoped to this tenant only. |
| `CFGMS_AGENT_MODE` | `true` | Tells Claude Code to follow the Agent Implementation Workflow (Phase 1–4) rather than entering interactive mode. |
| `CFGMS_ADMIN_BUNDLE` | _(empty)_ | Explicitly cleared so the container cannot use the host admin mTLS bundle even if the volume were somehow accessible. |

### Host-side (required before launch/cleanup)

| Variable | Purpose |
|---|---|
| `CFGMS_TIER1_URL` | Tier 1 controller base URL — passed through to the container. Required for `launch`, `smoke-test`, and `health-check`. |
| `CFGMS_TIER1_ADMIN_KEY` | Admin Bearer token for mint/revoke REST calls (preferred). |
| `CFGMS_ADMIN_BUNDLE` | Path to admin mTLS bundle YAML — used if `CFGMS_TIER1_ADMIN_KEY` is unset. |

One of `CFGMS_TIER1_ADMIN_KEY` or `CFGMS_ADMIN_BUNDLE` must be set for `launch`
and cleanup operations that reach the controller. If neither is set, mint fails
with `CRED_MINT_FAILED:no auth available`.

---

## Lifecycle

### Full issue-agent lifecycle

```
agent-dispatch.sh launch <N>
  │
  ├─ mint_agent_creds <N>
  │     POST /api/v1/tenants        → create agent-test/<N> sub-tenant (idempotent)
  │     POST /api/v1/api-keys       → issue agent.dev-scoped key
  │     write /run/cfgms/agent-cred/<N>/api.key   (0600)
  │     write /run/cfgms/agent-cred/<N>/api.key.id (0600)
  │     emit  CRED_MINTED:<N>:<key-id>
  │
  ├─ docker run -d cfg-agent:latest <N>
  │     -v /run/cfgms/agent-cred/<N>:/run/cfgms/agent-cred:ro
  │     -e CFGMS_API_KEY_FILE=/run/cfgms/agent-cred/api.key
  │     -e CFGMS_TENANT=agent-test/<N>
  │     -e CFGMS_TIER1_URL=<...>
  │     -e CFGMS_AGENT_MODE=true
  │     emit  LAUNCHED:<N>:<container-id>
  │
  └─ (agent works; on completion, acceptance reviewer merges PR)

agent-dispatch.sh smoke-test <N>   # optional, on-demand verification
  │     docker run --rm cfg-agent:latest cfg config list \
  │           --tenant=agent-test/<N> --no-bundle
  │     emit  SMOKE_OK:<N>          (exit 0)
  │        or SMOKE_FAILED:<N>:<error> (exit 1)

agent-dispatch.sh cleanup-issue <N>
  │
  ├─ revoke_agent_creds <N>
  │     DELETE /api/v1/api-keys/<key-id>
  │     POST   /api/v1/tenants/agent-test/<N>/suspend
  │     emit   CRED_REVOKED:apikey:<key-id>
  │     emit   CRED_REVOKED:tenant:agent-test/<N>
  │
  ├─ docker rm -f cfg-agent-<N>
  │     emit  CLEANED:container:cfg-agent-<N>
  │
  └─ rm -rf <WORKTREE_BASE>/story-<N>
        emit  CLEANED:clone:<path>
```

### Expected output samples

**launch:**
```
CRED_MINTED:42:key-id-abc123
LAUNCHED:42:d3f1a2b4c5e6...
```

**smoke-test (success):**
```
SMOKE_OK:42
```

**smoke-test (failure):**
```
SMOKE_FAILED:42:connection refused
```

**cleanup-issue:**
```
CRED_REVOKED:apikey:key-id-abc123
CRED_REVOKED:tenant:agent-test/42
CLEANED:container:cfg-agent-42
CLEANED:clone:/path/to/worktrees/story-42
CLEANUP_DONE:42
```

---

## Smoke Test (`smoke-test <N>`)

`smoke-test <N>` verifies that an agent container can reach the Tier 1
controller and authenticate with its scoped key. It runs `cfg config list
--tenant=agent-test/<N> --no-bundle` in a short-lived `--rm` container.

### Credential resolution order

The command checks for credentials **before** launching any container. If none
are found it exits immediately with `SMOKE_FAILED:<N>:no_cred`.

Priority order:

1. `CFGMS_API_KEY_FILE` env var pointing to an existing file
2. Per-agent tmpfs cred at `${AGENT_CRED_BASE}/<N>/api.key` (written by `launch`)
3. `CFGMS_API_KEY` env var (key value directly)

### Output format

| Output | Exit | Meaning |
|---|---|---|
| `SMOKE_OK:<N>` | 0 | `cfg config list` succeeded — Tier 1 reachable and auth valid |
| `SMOKE_FAILED:<N>:no_cred` | 1 | No credential found; container not started |
| `SMOKE_FAILED:<N>:no_tier1_url` | 1 | `CFGMS_TIER1_URL` not set; container not started |
| `SMOKE_FAILED:<N>:<error>` | 1 | `cfg config list` failed; `<error>` is the first line of stderr |

The container is always removed (`--rm`) regardless of success or failure.

---

## API Key Mint / Inject / Revoke Flow

Each agent container receives a **short-lived, tenant-scoped, least-privilege
API key**. The key never appears in `docker inspect` output and is never baked
into an image layer.

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
   `/run/cfgms/agent-cred` inside the container:

   | Env var | Value |
   |---|---|
   | `CFGMS_API_KEY_FILE` | `/run/cfgms/agent-cred/api.key` |
   | `CFGMS_TENANT` | `agent-test/<N>` |
   | `CFGMS_TIER1_URL` | Tier 1 controller base URL |

   **The key value is never in a container env var.** `docker inspect` shows
   only the file path. The key is never in the bind-mounted Claude credentials
   file (`~/.claude/.credentials.json`) — the two credentials are injected
   through entirely separate mounts.

**Mint failure** — if the sub-tenant creation or key issuance fails, the
dispatcher emits `CRED_MINT_FAILED:<reason>`, removes any partial cred dir,
and exits non-zero without starting a container.

### Revoke (cleanup)

All three cleanup paths call `revoke_agent_creds <N>` before removing the
container and clone:

- `cleanup-issue <N>` — normal agent exit path
- `cleanup-stale` — orphan sweep for closed/failed/blocked stories
- `cleanup-stale-reviews` — orphan sweep for review containers

The revoke sequence:

1. **Delete API key** — `DELETE /api/v1/api-keys/<key-id>`. The in-memory
   cache entry is removed immediately; any in-flight request with the key
   receives HTTP 401.

2. **Suspend sub-tenant** — `POST /api/v1/tenants/agent-test/<N>/suspend`
   sets `status: suspended`. Suspended tenants cannot issue new keys or
   authenticate new sessions.

3. **Remove cred dir** — `/run/cfgms/agent-cred/<N>/` is deleted; because it
   lives in tmpfs the data is gone from RAM immediately.

### Security properties

- Key value never appears in `docker inspect` env output.
- Key value never enters the bind-mounted Claude credentials file.
- Key value never appears in the image.
- Credentials live in RAM only (Linux `/run` tmpfs) and are destroyed on host
  reboot even if cleanup is skipped.
- The `agent.dev` role is fail-closed: full RBAC and tenant isolation
  enforcement on every controller request — no admin short-circuit.

---

## Tenant-Isolation Model

Each agent container is bound to its own `agent-test/<N>` sub-tenant. The
`agent.dev` role assigned to the key grants these read-only permissions within
that tenant only:

| Permission | Description |
|---|---|
| `steward:read` | Read steward metadata |
| `steward:list` | List stewards in the tenant |
| `steward:read-config` | Read steward configuration |
| `steward:read-modules` | Read module assignments |
| `steward:validate-config` | Validate config without applying it |
| `config:list` | List config objects |
| `config:list-deployments` | List deployments |
| `tenant:read` | Read tenant metadata |

**What an agent-test/<N> key cannot do:**

- Read or write data in any other tenant (including `agent-test/<M>` where
  M ≠ N, and the root tenant).
- Write configuration (`config:create`, `config:update`, `config:delete`).
- Manage stewards (`steward:manage`), open remote shells (`terminal:*`), or
  modify RBAC assignments (`rbac:*`).
- Perform system-admin operations or modify the tenant tree.

Cross-tenant access is blocked by the controller's tenant isolation enforcement:
a key bound to `agent-test/42` receives HTTP 403 for any request scoped to a
different tenant — even within the `agent-test/` namespace.

---

## Orphan-Revocation Paths

An agent container is an orphan if it is running or exited but its
corresponding story is no longer active. Three automated sweeps handle this:

### `cleanup-issue <N>` — normal exit path

Called by the acceptance reviewer after merging a PR. Revokes creds, removes
the container, and removes the clone worktree.

### `cleanup-stale` — periodic orphan sweep

Runs on the PO cron cycle. For every `cfg-agent-<NUM>` container found (running
or exited), checks:

- Is the GitHub issue CLOSED? → clean up.
- Does the project queue show status `Failed` or `Blocked`? → clean up.

Revokes creds for each stale container before removing it.

### `cleanup-stale-reviews` — review container failsafe

For review containers (`cfg-agent-review-pr-<N>`) that exited without cleaning
up (e.g. the agent crashed). Removes containers older than 30 minutes,
archives the result JSON, and deletes the worktree. Also calls
`revoke_agent_creds` for `review-pr-<N>`.

### Controller-unreachable during revocation

If the controller cannot be reached, the failure is recorded to
`/run/cfgms/agent-cred/<N>/revoke-failed.txt` (`0600`) in the format:

```
<key-id> <unix-timestamp> <error>
```

Container and clone removal proceed regardless. The file is left for manual
follow-up. `cleanup-stale` will attempt revocation again on its next cycle if
the cred dir still exists.

---

## `SMOKE_FAILED` Troubleshooting

| Output | Cause | Fix |
|---|---|---|
| `SMOKE_FAILED:<N>:no_cred` | No API key found for issue `<N>` | Run `launch <N>` first, or set `CFGMS_API_KEY` / `CFGMS_API_KEY_FILE` |
| `SMOKE_FAILED:<N>:no_tier1_url` | `CFGMS_TIER1_URL` not set | Export `CFGMS_TIER1_URL=https://<controller>:<port>` on the host |
| `SMOKE_FAILED:<N>:connection refused` | Controller not reachable | Check `health-check` output for `WARN:tier1_unreachable`; verify the controller is up and the port is accessible from the dispatch host |
| `SMOKE_FAILED:<N>:401` | Key was revoked or expired | Run `cleanup-issue <N>` then `launch <N>` to mint a fresh key |
| `SMOKE_FAILED:<N>:403` | Key lacks permission for the tenant path | Verify `CFGMS_TENANT` matches `agent-test/<N>`; the key is bound to that tenant only |
| `SMOKE_FAILED:<N>:certificate verify failed` | TLS trust mismatch | The controller's cert is not trusted by the agent image; rebuild the image with the correct CA or set `CFGMS_TLS_CA_FILE` |

### `health-check` Tier 1 probes

`health-check` includes a Tier 1 reachability probe:

```
INFO:tier1_reachable:true         — controller /api/v1/health returned 2xx
WARN:tier1_unreachable:<code>     — HTTP <code> or 000 (connection failure)
WARN:tier1_url_not_set            — CFGMS_TIER1_URL not exported on the host
```

`WARN:tier1_url_not_set` is non-fatal for development but means all
`cfg`-to-controller calls from agent containers will fail. Export
`CFGMS_TIER1_URL` before dispatching.
