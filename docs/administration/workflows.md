# Workflow Operations

Run, inspect and cancel workflows using the current CLI. The
[workflow architecture](../architecture/workflow-engine.md) owns declaration and
execution semantics. Workflow authorization follows the accepted scoped-grant
contract; an example selector is not an access grant.

## Workflow Management

`cfg workflow` subcommands manage workflow definitions and their executions on the controller.

### cfg workflow run

Submits a workflow definition file to the controller and starts an execution, printing the execution ID.

```bash
cfg workflow run features/workflow/examples/simple-file-deployment.yaml --url=https://controller.example.com
```

The file is decoded into the workflow engine's own definition type, in either of two forms: flat (`name`, `steps`, … at the top level) or nested under a top-level `workflow:` key. Durations are duration strings (`2s`, `5m`, `1h30m`). `version`, when present, must be a semantic version (`MAJOR.MINOR.PATCH`); the controller defaults it to `1.0.0`. Unknown fields are rejected rather than dropped. The files in `features/workflow/examples/` are valid inputs.

### cfg workflow list

List all workflow definitions registered on the controller.

```bash
cfg workflow list --url=https://controller.example.com
cfg workflow list --url=https://controller.example.com --bundle=/path/to/admin.bundle.yaml
```

Prints a plain-text table with columns: NAME, VERSION, STEPS.

Example output:

```
NAME         VERSION  STEPS
deploy-ring  1.2.0    4
sync-entra   2.0.0    7
```

When no workflows are registered, exits 0 and prints:

```
No workflows registered.
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg workflow status

Show the status of a single workflow execution.

```bash
cfg workflow status <execution-id> --workflow <name> --url=https://controller.example.com
```

The `<execution-id>` is returned by `cfg workflow run`.

Example output:

```
execution_id:  exec_1782879897336049056_1
workflow:      deploy-ring
status:        running
current_step:  step-canary
started_at:    2026-07-01T10:00:00Z
error:         -
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--workflow` | — | Workflow name (required) |
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg workflow cancel

Cancel a running workflow execution.

```bash
cfg workflow cancel <execution-id> --workflow <name> --url=https://controller.example.com
```

Returns an error if the execution is already in a terminal state (completed, failed, or cancelled).

On success:

```
Cancelled execution exec_1782879897336049056_1
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--workflow` | — | Workflow name (required) |
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

### cfg workflow promote-hv-role

Promote a Hyper-V VM from standalone to Failover Cluster role by submitting the
embedded `promote-hv-role` workflow template with the resolved steward and cluster.

```bash
cfg workflow promote-hv-role <vmname> <host-selector> [--cluster <name>] --url=https://controller.example.com
```

`<host-selector>` uses the same grammar as `cfg steward` commands — see
`docs/administration/cli-selectors.md` for the full reference. The selector
**must resolve to exactly one steward**; a selector matching zero or more than
one is always a hard error, never a silent pick. Use a tenant-path prefix or
`id:<steward-id>` to disambiguate across tenants that share a hostname.

When the resolved host belongs to exactly one cluster, `--cluster` is optional.
When it belongs to more than one cluster, `--cluster` is required to name which
cluster the VM should be promoted into.

On success, prints the execution ID and status, which can be observed with:

```bash
cfg workflow status <execution-id> --workflow promote-hv-role --url=https://controller.example.com
```

Example output:

```
Workflow submitted: promote-hv-role
Execution ID: exec_1782879897336049056_1
Status: running
```

**Disambiguating across tenants (multi-cluster case):**

```bash
# Unambiguous single-tenant host with one cluster:
cfg workflow promote-hv-role MyVM hv01 --url=https://controller.example.com

# Multi-tenant environment — use tenant path to pin the correct steward:
cfg workflow promote-hv-role MyVM acme-corp/hv01 --url=https://controller.example.com

# Host in multiple clusters — specify which cluster:
cfg workflow promote-hv-role MyVM hv01 --cluster fc-east --url=https://controller.example.com
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--cluster` | — | Cluster name (required only when the host belongs to more than one cluster) |
| `--url` | — | Controller API URL (required) |
| `--tls-ca-cert` | — | Path to CA certificate for TLS verification (env: CFGMS_TLS_CA_CERT) |
| `--tls-insecure` | false | Skip TLS verification (development only, env: CFGMS_TLS_INSECURE) |
| `--server-name` | — | Override TLS server name for certificate verification |

---
