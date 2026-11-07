# Agent Dispatch

Operational reference for the `agent-dispatch.sh` lifecycle — environment
variables, container lifecycle, credential flows, Tier 1 connectivity, and
tenant isolation.

**Current launch path.** Dev, fix-pr, resolve-conflict and branch agents are
started only by `po-act.sh dispatch | dispatch --branch | dispatch-fix |
resolve-conflict`, which run the FSM supervisor (`.claude/tooling/scripts/fsm/supervisor.py`).
`agent-dispatch.sh launch` and `launch-generic` are removed: they print
`LAUNCH_REMOVED:…` and exit 2. The per-agent Tier 1 credential mint
(`mint_agent_creds`, formerly called by `launch`) is removed too: no tooling
mints a per-agent key, so **dispatched agents currently run without a Tier 1 API
key** and without `CFGMS_TIER1_URL`. The supervisor accepts `--agent-cred-dir
<dir>` and `--tenant <path>` and, when given them, mounts `<dir>` read-only at
`/run/cfgms/agent-cred` with `CFGMS_API_KEY_FILE=/run/cfgms/agent-cred/api.key`,
`CFGMS_ADMIN_BUNDLE=` (empty) and `CFGMS_TENANT=<path>`; `po-act.sh` passes
neither. The revoke and smoke-test mechanics below describe the `agent-dispatch.sh`
functions as they exist; provisioning a per-agent key for FSM runs is open work.

---

## Environment Variables

### Container-side (injected by the dispatcher)

These are the variables the removed `agent-dispatch.sh launch <N>` set. An FSM
agent session sets `CFGMS_AGENT_MODE=true`, plus `CFGMS_API_KEY_FILE`,
`CFGMS_TENANT` and an empty `CFGMS_ADMIN_BUNDLE` only when the supervisor is given
`--agent-cred-dir` / `--tenant` (see above). It never sets `CFGMS_TIER1_URL`.

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
| `CFGMS_TIER1_URL` | Tier 1 controller base URL. Required for `smoke-test` and `health-check`. |
| `CFGMS_TIER1_ADMIN_KEY` | Admin Bearer token for revoke REST calls (preferred). |
| `CFGMS_ADMIN_BUNDLE` | Path to admin mTLS bundle YAML — used if `CFGMS_TIER1_ADMIN_KEY` is unset. |

One of `CFGMS_TIER1_ADMIN_KEY` or `CFGMS_ADMIN_BUNDLE` must be set for cleanup
operations that reach the controller.

---

## Lifecycle

### Issue-agent credential lifecycle

No current launch path mints a per-agent key (see the top of this page). The
smoke test and the revoke in every cleanup path remain:

```
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
2. Per-agent tmpfs cred at `${AGENT_CRED_BASE}/<N>/api.key` (no tooling writes it since `mint_agent_creds` was removed)
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

## API Key Inject / Revoke Flow

No tooling mints a per-agent API key: `mint_agent_creds` (which created an
`agent-test/<N>` sub-tenant, issued an `agent.dev`-scoped key and wrote it to
`/run/cfgms/agent-cred/<N>/`) is removed. What remains:

### Inject (FSM supervisor, when given a key)

`supervisor.py run … --agent-cred-dir <dir> [--tenant <path>]` bind-mounts
`<dir>` read-only at `/run/cfgms/agent-cred` in each agent session container and
sets:

| Env var | Value |
|---|---|
| `CFGMS_API_KEY_FILE` | `/run/cfgms/agent-cred/api.key` |
| `CFGMS_ADMIN_BUNDLE` | _(empty — turns off admin-bundle auto-discovery)_ |
| `CFGMS_TENANT` | `<path>` (only with `--tenant`) |

The key value is never in a container env var; `docker inspect` shows only the
file path. The supervisor reads `<dir>/api.key` and adds its value to the
secret scan, so a candidate or PR text carrying it is never published.
`po-act.sh` does not pass `--agent-cred-dir`, so FSM runs started by the
pipeline get no key.

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
- Credentials under `/run/cfgms/agent-cred/` live in RAM only (Linux `/run`
  tmpfs) and are destroyed on host reboot even if cleanup is skipped.
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
| `SMOKE_FAILED:<N>:no_cred` | No API key found for issue `<N>` | Set `CFGMS_API_KEY` / `CFGMS_API_KEY_FILE` (no current launch path mints a per-agent key) |
| `SMOKE_FAILED:<N>:no_tier1_url` | `CFGMS_TIER1_URL` not set | Export `CFGMS_TIER1_URL=https://<controller>:<port>` on the host |
| `SMOKE_FAILED:<N>:connection refused` | Controller not reachable | Check `health-check` output for `WARN:tier1_unreachable`; verify the controller is up and the port is accessible from the dispatch host |
| `SMOKE_FAILED:<N>:401` | Key was revoked or expired | Run `cleanup-issue <N>`, then supply a fresh key through `CFGMS_API_KEY` / `CFGMS_API_KEY_FILE` |
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
