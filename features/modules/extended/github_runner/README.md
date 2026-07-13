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
| `owner` | conditional | GitHub organization or user owning the repository. Required when `service_name` is not set |
| `repo` | conditional | GitHub repository name (without owner prefix). Required when `service_name` is not set |
| `service_name` | no | OS service name (systemd unit on Linux, SCM service on Windows). When omitted, derived from `owner`, `repo`, and the host's hostname |

### Optional service_name and automatic derivation

`service_name` is optional. When omitted, `owner` and `repo` become required and
the module derives the OS service name at convergence time as:

```
actions.runner.<owner>-<repo>.<hostname>
```

where `<hostname>` is the steward host's hostname obtained via `os.Hostname()`,
and any characters not in `[a-zA-Z0-9._@-]` in the owner, repo, or hostname are
replaced with `-` before composition. The derived name is validated against the
service-name character pattern; if it exceeds the length limit (255 characters)
`Set` returns a validation error.

This derivation allows a **single shared role config** (with `owner` + `repo` but
no `service_name`) to converge correctly on any number of runner hosts — each host
produces its own host-unique service name without per-machine config overrides.

### Registration-name coupling (load-bearing)

The GitHub runner's `config.sh` / `config.cmd` register step creates the OS
service as `actions.runner.<owner>-<repo>.<runner-name>`. The `<runner-name>` is
the name given to the runner at registration time.

**Contract:** the runner must be registered with its `<runner-name>` equal to the
steward host's hostname (the value returned by `os.Hostname()`). The module
derives the service name using the same hostname via `os.Hostname()`, so the
derived name exactly matches the service name that registration produced.

If the service name derived by this module does not match the name created at
registration, `Get` will query a non-existent service and report
`installed: false` indefinitely. Ensure the registration step uses the hostname
as the runner name (the S6 live-proof workflow enforces this by registering the
runner with `--name $(hostname)`).

## Usage examples

### Explicit service_name (per-machine config)

```yaml
# A Linux CI runner host with an explicit service name
resource: runner
work_dir: /opt/actions-runner
config:
  version: "2.319.1"
  agent_url: "https://github.com/actions/runner/releases/download/v2.319.1/actions-runner-linux-x64-2.319.1.tar.gz"
  agent_sha256: "<64-char hex pinned by the operator>"
  labels: ["self-hosted", "linux", "ci"]
  service_name: "actions.runner.acme-repo.host1.service"
```

### Shared role config with derived service_name

```yaml
# One role config that works on any number of runner hosts.
# service_name is omitted; the module derives it from owner, repo, and hostname.
# Registration must use the runner name equal to the host's hostname.
resource: runner
work_dir: /opt/actions-runner
config:
  version: "2.319.1"
  agent_url: "https://github.com/actions/runner/releases/download/v2.319.1/actions-runner-linux-x64-2.319.1.tar.gz"
  agent_sha256: "<64-char hex pinned by the operator>"
  labels: ["self-hosted", "linux", "ci"]
  owner: "acme-org"
  repo: "myrepo"
  # service_name is omitted; derived as actions.runner.acme-org-myrepo.<hostname>
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
`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,254}$` before use (for explicit names) or
derived via `sanitizeComponent` (which enforces the same character set) for
auto-derived names. No command-string composition, no `iex` / `-Command` /
`-EncodedCommand`. The vendor `config.cmd` / `config.sh` register tool is
**not** invoked by this module.

## Platforms

Linux (systemd) and Windows (SCM), amd64 + arm64. On other platforms the service
executor is a stub returning `ErrUnsupportedPlatform`, so the package still
compiles everywhere.

## Files

| File | Role |
|------|------|
| `module.go` | `Module` (Get/Set), `Configurable`, and `Test`; convergence logic |
| `config.go` | `RunnerConfig` (`ConfigState`) + the on-disk drift state marker + service-name derivation |
| `install.go` | download (net/http) + SHA-256 verify + stdlib unpack |
| `service_linux.go` / `service_windows.go` / `service_stub.go` | platform service executors |
| `module.yaml` / `schema.yaml` | signed manifest + resource schema |
