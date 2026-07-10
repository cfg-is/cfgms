# github_runner module

## Purpose and scope

Idempotent management of a **GitHub Actions self-hosted runner agent** on a
steward host. The module keeps three token-free dimensions of desired state in
sync and reports drift; it is a steward module (local host management only).

| Dimension | Get | Set | Test |
|-----------|-----|-----|------|
| Agent binary at a pinned `version` under `work_dir` | reports installed version | downloads + verifies + unpacks when the version differs | drift if installed ≠ desired |
| Desired `labels` set | reports tracked labels | records desired labels | drift if tracked ≠ desired |
| Runner service `enabled` + `running` | reports service state | converges via the native service manager | drift if not enabled+running |

## What this module deliberately does NOT do

The module is **token-free**. It never mints or consumes a GitHub Actions
registration token and never registers or deregisters the runner with GitHub.
Registration — and therefore the *initial creation* of the runner service and the
*application* of label changes to the GitHub side — is performed by the
publisher-signed register script driven by the **CI-runner provisioning
workflow**, which holds the single-use token. This module owns only the
idempotent steady state that needs no secret. There is no token field anywhere in
its [`schema.yaml`](./schema.yaml) (enforced by a unit test).

This split means: on a freshly provisioned host the module installs the agent
binary and tracks desired labels immediately, and once the provisioning workflow
has registered the service, the module keeps that service enabled and running on
every convergence cycle.

## Configuration options

Schema (`runner` resource):

| Field | Required | Description |
|-------|----------|-------------|
| `version` | yes | Pinned agent version, e.g. `2.319.1` |
| `agent_url` | yes | HTTPS URL to the agent archive (`.tar.gz` on Linux, `.zip` on Windows) |
| `agent_sha256` | yes | Operator-pinned expected SHA-256 (64-char hex). Verified directly — **no network hash lookup** |
| `labels` | no | Desired runner label set |
| `work_dir` | yes | Absolute install directory; also the resource ID |
| `service_name` | yes | OS service name (systemd unit on Linux, SCM service on Windows) |

## Usage examples

```yaml
# A Linux CI runner host (see examples/ci-runners for the full walkthrough)
resource: runner
work_dir: /opt/actions-runner          # also the resource ID
config:
  version: "2.319.1"
  agent_url: "https://github.com/actions/runner/releases/download/v2.319.1/actions-runner-linux-x64-2.319.1.tar.gz"
  agent_sha256: "<64-char hex pinned by the operator>"
  labels: ["self-hosted", "linux", "ci"]
  service_name: "actions.runner.acme-repo.host1.service"
```

`Set` downloads the agent at the pinned `version`, verifies its SHA-256, unpacks
it under `work_dir`, records the desired labels, and ensures the service is
enabled and running. `Test` reports drift when the installed version, tracked
labels, or service run-state differ from desired. A second `Set` against an
already-converged host is a no-op.

## Known limitations

- **Registration is out of scope.** The module never holds a registration token,
  so it cannot create the runner service or push label changes to GitHub. On a
  fresh host it stages the agent and tracks desired labels; the runner service is
  created (and labels applied server-side) by the provisioning workflow's
  publisher-signed register script. Until that runs, `Test` reports drift
  (service not running) by design.
- **Label application is local-only.** `Set` records the desired label set so
  drift resolves locally; applying a *changed* label set to the GitHub side
  requires re-running the register script (token-bearing) via the provisioning
  workflow.
- Live service convergence (systemd/SCM) requires an init system and elevation,
  so it is validated on a real lab host, not in a container.

## Security considerations

The agent archive is unpacked **in-process with the Go standard library**
(`archive/tar` + `compress/gzip` on Linux, `archive/zip` on Windows) — there is
no shell-out to `tar` or `Expand-Archive`, and archive entries that attempt path
traversal (zip-slip) are rejected. The downloaded archive's SHA-256 is verified
against the operator-pinned `agent_sha256` before anything is written to disk; a
mismatch rejects the install with nothing extracted.

The only declared shell-outs (see
[`module.yaml`](./module.yaml) `behavioral_envelope`) are the native service
managers used to converge the already-registered runner service:

- **Linux** — `systemctl` against the runner systemd unit
- **Windows** — `sc.exe` against the runner SCM service

Argument lists are fully static except `service_name`, which is validated against
`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,254}$` before use. No command-string composition,
no `iex` / `-Command` / `-EncodedCommand`. The vendor `config.cmd` / `config.sh`
register tool is **not** invoked by this module.

## Platforms

Linux (systemd) and Windows (SCM), amd64 + arm64. On other platforms the service
executor is a stub returning `ErrUnsupportedPlatform`, so the package still
compiles everywhere.

## Files

| File | Role |
|------|------|
| `module.go` | `Module` (Get/Set), `Configurable`, and `Test`; convergence logic |
| `config.go` | `RunnerConfig` (`ConfigState`) + the on-disk drift state marker |
| `install.go` | download (net/http) + SHA-256 verify + stdlib unpack |
| `service_linux.go` / `service_windows.go` / `service_stub.go` | platform service executors |
| `module.yaml` / `schema.yaml` | signed manifest + resource schema |
