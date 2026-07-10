# CI Runner GitHub App — Setup Runbook

**Scope:** self-hosted Hyper-V CI runners managed by CFGMS.

This runbook covers the **one-time** GitHub App bootstrap and documents the **fully-automated** per-runner registration the controller performs. The App is created once; every runner thereafter registers with no human in the loop.

---

## 0. Mental model — one-time vs per-runner

| Step | Frequency | Who |
|------|-----------|-----|
| Create the GitHub App + capture its private key | **Once, ever** | Founder (≈1 click via the manifest flow) |
| Install the App on `cfg-is/cfgms` | Once | Founder |
| Store `app_id` / `installation_id` / private key in the secrets provider | Once | Founder (or scripted capture) |
| Mint registration token, configure + register a runner, deregister | **Every runner / every job** | Controller — **fully automated, no human** |

The only thing requiring a human is creating the App (GitHub does not allow an unattended process to mint an App with admin permissions on an org — by design). Everything downstream is scripted.

---

## 1. Create the App — scripted manifest flow (preferred)

GitHub's **App Manifest flow** creates the App and returns its credentials programmatically, with a single confirmation click — no field-by-field UI config.

1. The controller (or a one-shot local helper) serves an HTML form that POSTs an **app manifest** to:
   - Repo/user-owned: `https://github.com/settings/apps/new?state=<csrf>`
   - Org-owned (preferred for `cfg-is`): `https://github.com/organizations/cfg-is/settings/apps/new?state=<csrf>`
2. Manifest (the exact permissions the MVP needs — see §2):
   ```json
   {
     "name": "cfgms-ci-runners",
     "url": "https://cfg.is",
     "hook_attributes": { "active": false },
     "public": false,
     "default_permissions": {
       "administration": "write"
     },
     "default_events": []
   }
   ```
3. You click **Create GitHub App** once. GitHub redirects back to the helper's `redirect_url` with `?code=<temporary_code>`.
4. The helper exchanges the code (within ~1 hour):
   ```
   POST https://api.github.com/app-manifests/<code>/conversions
   ```
   The response includes `id` (the **App ID**), `pem` (the **private key**), `client_id`, `webhook_secret`, etc. — captured programmatically, never shown field-by-field.
5. **Install** the App on the `cfg-is/cfgms` repository (one click). Record the **installation ID** (`GET /app/installations` as the App, or from the install redirect).

> Fallback (no helper): create the App manually at **Settings → Developer settings → GitHub Apps → New GitHub App**, set the permission in §2, generate a private key, install on the repo. ~2 minutes, once.

---

## 2. Required App permissions (MVP — repo-level runners)

Minimum viable permission set:

- **Repository → Administration: Read and write** — required to mint runner registration tokens (`POST /repos/{owner}/{repo}/actions/runners/registration-token` requires `administration:write`).

That is the only permission the MVP needs. (If we later move to **org-level** runners, swap to **Organization → Self-hosted runners: Read and write**. If we later autoscale on the job queue, add **Repository → Actions: Read** to observe `workflow_job` events.)

No webhook is needed for the persistent MVP (`hook_attributes.active = false`).

---

## 3. Store the credentials (secrets provider — once)

The App credentials are long-lived and MUST live in the CFGMS secrets provider (SOPS-encrypted), never in cfg or cleartext on disk:

- `github_app_id`
- `github_app_installation_id`
- `github_app_private_key` (PEM)

These three are all the controller needs to mint tokens indefinitely.

---

## 4. Per-runner registration — fully automated (controller)

For each runner the controller provisions, with **no human involvement**:

1. **App JWT** — sign a short-lived (≤10 min) RS256 JWT with the private key (`iss = app_id`).
2. **Installation token** — `POST /app/installations/{installation_id}/access_tokens` → a 1-hour installation token.
3. **Registration token** — `POST /repos/cfg-is/cfgms/actions/runners/registration-token` (using the installation token) → a short-lived runner registration token.
4. **Inject + register** — deliver the registration token to the fresh Hyper-V VM via the existing controller-supplied-config path (the controller's standard mechanism for pushing config and secrets to a managed host), then on the VM:
   ```
   ./config.sh --url https://github.com/cfg-is/cfgms --token <reg-token> \
               --labels self-hosted,linux,hyperv --unattended --replace
   ./run.sh    # runs persistently in the foreground — or install as a service for unattended operation
   ```
5. **Deregister on teardown** — `DELETE /repos/.../actions/runners/{runner_id}` (or `--ephemeral` self-deregisters after one job).

> **Ephemeral follow-up (deferred):** replace steps 3–5 with a single `POST /repos/.../actions/runners/generate-jitconfig` call; boot the VM with `./run.sh --jitconfig <base64>`. The runner self-registers, runs exactly one job, self-deregisters, and the VM is destroyed. Same App, same installation token — no extra setup.

---

## 5. Public-repo safety (load-bearing)

Self-hosted runners must never execute untrusted fork-PR code on this PUBLIC repo. The CI workflow gates self-hosted jobs on:

```yaml
if: github.event.pull_request.head.repo.fork == false   # non-fork PRs only (same-repo branches)
```

External fork PRs fall back to GitHub-hosted runners. Additionally set **repo → Actions → "Approval for running fork pull request workflows" = require approval for all external contributors**. No repo secrets are exposed to fork-PR contexts.

---

## 6. Lab Provisioning Results (Issue #2335, measured 2026-07-07 on cfg-lab)

First Linux CI runner provisioned end-to-end on the lab cluster: VM `cfgms-ci-lin-01`
(4 vCPU / 8 GB / 60 GB, Debian 13 cloud image) on host CFG-70-02 via the hyperv
module cloud-init path (ADR-009 §6a), steward enrolled to tenant `gh-ci-runners`,
registered to `cfg-is/cfgms` as runner **`cfgms-ci-lin-01`** with labels
**`self-hosted, Linux, X64, cfgms`** (runner id 21, status `online`).

Measured timings:

| Phase | Measured |
|-------|----------|
| VM provision, cloud-init path (`cfg config upload` → VM booted) | 2 m 42 s |
| Steward enrollment (seeded boot → steward `active` on controller) | ~100 s |
| Registration token mint | 0.44 s |
| Runner registration (agent download 197 MB + deps + `config.sh` + service start) | 63 s |
| Registration sequence → runner `online` in GitHub API | 77.6 s |
| Hyper-V checkpoint create (`Checkpoint-VM`, running VM) | 4.55 s |
| Hyper-V checkpoint revert (`Restore-VMCheckpoint`) | 10.02 s |

`ProvisionTimings.String()` for the registration sequence (checkpoint durations per
the struct semantics — enrollment-confirmed → checkpoint-created spans operator
steps between the two operations):

```
cirunner provisioning: token-mint=437ms sync-trigger=27ms enrollment=1m17.126s total=1m17.59s checkpoint-create=45.126s checkpoint-revert=10.017s
```

The runner was `online` in the GitHub API when first polled 36 s after the
checkpoint revert — the checkpoint-revert pool pattern (Phase 2 ephemeral runners)
is viable.

**Deviations from the target workflow path (pre-existing gaps, filed for follow-up):**
the `cirunner-provision.yaml` workflow could not run this sequence yet. The deployed
lab controller predates the workflow-submission endpoint (`cfg workflow run` → 404),
and one source-level gap blocks it on any current build: the workflow engine
registers the `github` APIProvider with a nil secrets store
(`features/workflow/providers.go` — never re-injected with the controller's secret
store). The `github_runner` module is now registered in the steward factory
(`features/steward/factory/factory.go` — Issue #2427); the operator-assisted
registration used in this lab run was a point-in-time deviation, not a standing
limitation. The registration token for this run was minted directly against the
GitHub API (same endpoint the App-based provider calls) and delivered over an
operator SSH session — never composed into a CFGMS command string. Sequence and
timings otherwise mirror the workflow's steps 1–4.

### Windows runner (Issue #2336, measured 2026-07-07 on cfg-lab)

Windows CI runner provisioned on the same cluster: VM `cfgms-ci-win-01`
(4 vCPU / 8 GB, Windows Server 2025 SERVERSTANDARD from the eval ISO) on host
CFG-70-02 via the hyperv module autounattend path (ADR-009 §6), steward v0.9.10
enrolled to tenant `gh-ci-runners`, registered to `cfg-is/cfgms` as runner
**`CFGMS-CI-WIN-01`** with labels **`self-hosted, Windows, X64, cfgms`** (runner
id 23, status `online`; GitHub canonicalizes the OS/arch label case, as with the
Linux runner).

Measured timings:

| Phase | Measured |
|-------|----------|
| VM provision, autounattend path (`cfg config upload` → VM created + answer ISO staged) | 43 s |
| Full provision (`cfg config upload` → unattended install → steward `active` on controller) | 7 m 16 s |
| Registration token mint | 0.50 s |
| Runner agent download (100 MB zip, in-guest) | 7.2 s |
| Runner agent extract | 14.2 s |
| Registration script v1.1.0 (`config.cmd` register + service install/start; operator ran `config.cmd remove` first to clear the v1.0.0 registration) | 4.8 s |
| Runner `online` in GitHub API after service start | first poll (< 60 s) |
| Hyper-V checkpoint create (`Checkpoint-VM`, running VM) | 7.05 s |
| Hyper-V checkpoint revert (`Restore-VMCheckpoint`) | 5.82 s |
| Revert → `Start-VM` → runner `online` in GitHub API | 137 s |

A production checkpoint (the Server 2025 default) restores the VM to `Off`, so the
revert-pool cycle on Windows is revert (5.8 s) + boot to runner-online (137 s,
including the runner service's delayed auto-start) — viable for Phase 2 ephemeral
runners, with a materially longer recovery than the Linux VM's 36 s.

**Script fix confirmed live:** the shipped `register-github-runner-windows.yaml`
(v1.0.0) ran verbatim and registered the runner (`√ Runner successfully added`,
`√ Settings Saved.`, token never echoed — a recursive literal-token search over
the runner work dir, including the agent's `_diag` logs, found zero hits), but the
runner stayed `offline`: `config.cmd --unattended --replace` only writes settings.
v1.1.0 adds `--runasservice`, which installs and starts the runner's Windows
service (`actions.runner.cfg-is-cfgms.CFGMS-CI-WIN-01`, NETWORK SERVICE, delayed
auto-start) — runner `online` at the first API poll after the script exits.

**Deviations for this run:** same workflow-path gaps as the Linux run above (token
minted directly against the GitHub API; agent staged operator-side because the
`github_runner` module was not yet in the steward factory at the time of this lab
run — that gap was closed by Issue #2427). Two additional lab
findings recorded for follow-up: (1) the deployed v0.9.9 hyperv module rendered the
pre-#2355 `--ca-cert` install flag, which no current steward accepts — resolved by
push-upgrading the HV-host steward to v0.9.10 and staging a matching guest
`cfgms-steward.exe` (both sides must agree on the rendered flag); (2) a steward
`exec` job that runs a Windows batch file (`config.cmd`) completes its work but the
job harness never observes process exit (descendant console handles hold the output
stream open), the completion event never fires, and the controller's per-device
dispatch lock (`features/controller/dispatcher/dispatcher.go`) is then held
indefinitely — `run-cancel` does not release it, and a steward reboot makes the
completion event permanently impossible (controller restart required). Runner
registration on Windows therefore ran over PowerShell Direct rather than the
steward exec channel.

---

## 7. Self-hosted vs GitHub-hosted CI timing (epic #565 MVP success criteria)

Measured 2026-07-08. Point-in-time samples; durations vary run-to-run due to queue
contention on the single-runner pool, module cache state, and ambient GitHub Actions load.

### 7.1 Self-hosted Windows runner (`CFGMS-CI-WIN-01`)

Job: `Native Build (Windows)`, `runner_name: CFGMS-CI-WIN-01` (labels: `self-hosted,
Windows, X64, cfgms`). Routes here for non-fork `pull_request`, `merge_group`, and `push`
events (Issue #2337). Duration = job `started_at` → `completed_at` (excludes queue-wait
before the runner picks up the job).

| Run ID | Event | `started_at` | `completed_at` | Duration |
|--------|-------|--------------|----------------|----------|
| [28919392704](https://github.com/cfg-is/cfgms/actions/runs/28919392704) | pull\_request | 2026-07-08T05:17:30Z | 2026-07-08T05:24:33Z | 7m 3s |
| [28915357324](https://github.com/cfg-is/cfgms/actions/runs/28915357324) | merge\_group | 2026-07-08T03:45:06Z | 2026-07-08T03:52:27Z | 7m 21s |
| [28915407858](https://github.com/cfg-is/cfgms/actions/runs/28915407858) | merge\_group | 2026-07-08T03:39:20Z | 2026-07-08T03:45:05Z | 5m 45s |
| [28915270545](https://github.com/cfg-is/cfgms/actions/runs/28915270545) | merge\_group | 2026-07-08T03:27:18Z | 2026-07-08T03:39:19Z | 12m 1s |
| [28913793047](https://github.com/cfg-is/cfgms/actions/runs/28913793047) | pull\_request | 2026-07-08T02:49:23Z | 2026-07-08T03:00:42Z | 11m 19s |
| [28913609116](https://github.com/cfg-is/cfgms/actions/runs/28913609116) | merge\_group | 2026-07-08T02:42:30Z | 2026-07-08T02:49:21Z | 6m 51s |
| [28912926805](https://github.com/cfg-is/cfgms/actions/runs/28912926805) | pull\_request | 2026-07-08T02:28:06Z | 2026-07-08T02:35:37Z | 7m 31s |

**Sorted: 5m 45s, 6m 51s, 7m 3s, 7m 21s, 7m 31s, 11m 19s, 12m 1s**

**Median: 7m 21s (441 s) · Average: 8m 16s (496 s)**

The 12m 1s sample (run 28915270545) reflects queue serialization: three `merge_group` runs
enqueued in rapid succession on the single `CFGMS-CI-WIN-01` runner — each starts only after
the preceding one completes.

### 7.2 GitHub-hosted Windows runner baseline

Job: `Native Build (Windows)` (post-routing) or `Native Build (windows-latest)` (pre-routing;
the matrix `platform` field was renamed when Issue #2337 updated the matrix expression — the
underlying job is identical). Routes to `windows-latest` for `workflow_dispatch` events and
fork-sourced `pull_request` events; pre-routing all runs used `windows-latest`. The 8 samples
below include 1 post-routing `workflow_dispatch` run and 7 runs from before Issue #2337 merged
into develop (2026-07-07 ~17:20), when all builds used GitHub-hosted runners.

| Run ID | Event | Job name | `started_at` | `completed_at` | Duration |
|--------|-------|----------|--------------|----------------|----------|
| [28885889636](https://github.com/cfg-is/cfgms/actions/runs/28885889636) | workflow\_dispatch | Native Build (Windows) | 2026-07-07T17:30:48Z | 2026-07-07T17:47:51Z | 17m 3s |
| [28879341829](https://github.com/cfg-is/cfgms/actions/runs/28879341829) | pull\_request | Native Build (windows-latest) | 2026-07-07T15:45:34Z | 2026-07-07T16:01:42Z | 16m 8s |
| [28830345350](https://github.com/cfg-is/cfgms/actions/runs/28830345350) | pull\_request | Native Build (windows-latest) | 2026-07-06T23:28:58Z | 2026-07-06T23:40:49Z | 11m 51s |
| [28828564496](https://github.com/cfg-is/cfgms/actions/runs/28828564496) | pull\_request | Native Build (windows-latest) | 2026-07-06T22:48:50Z | 2026-07-06T23:04:33Z | 15m 43s |
| [28826483352](https://github.com/cfg-is/cfgms/actions/runs/28826483352) | merge\_group | Native Build (windows-latest) | 2026-07-06T22:05:48Z | 2026-07-06T22:20:43Z | 14m 55s |
| [28824227037](https://github.com/cfg-is/cfgms/actions/runs/28824227037) | merge\_group | Native Build (windows-latest) | 2026-07-06T21:23:29Z | 2026-07-06T21:39:29Z | 16m 0s |
| [28821984103](https://github.com/cfg-is/cfgms/actions/runs/28821984103) | merge\_group | Native Build (windows-latest) | 2026-07-06T20:44:03Z | 2026-07-06T21:00:26Z | 16m 23s |
| [28811278270](https://github.com/cfg-is/cfgms/actions/runs/28811278270) | merge\_group | Native Build (windows-latest) | 2026-07-06T17:42:41Z | 2026-07-06T18:04:32Z | 21m 51s |

**Sorted: 11m 51s, 14m 55s, 15m 43s, 16m 0s, 16m 8s, 16m 23s, 17m 3s, 21m 51s**

**Median: 16m 4s (964 s) · Average: 16m 14s (974 s)**

### 7.3 Comparison and "materially faster" verdict

| Metric | Self-hosted (`CFGMS-CI-WIN-01`) | GitHub-hosted (`windows-latest`) | Speedup |
|--------|---------------------------------|----------------------------------|---------|
| Median | 7m 21s (441 s) | 16m 4s (964 s) | **2.19×** |
| Average | 8m 16s (496 s) | 16m 14s (974 s) | **1.96×** |

**Epic #565 "materially faster" criterion: YES.** The self-hosted runner completes the
`Native Build (Windows)` job in approximately half the time of the GitHub-hosted baseline —
a 2.19× median speedup (7m 21s vs 16m 4s). Excluding the queue-contention outlier (12m 1s,
run 28915270545) the self-hosted median drops to 7m 3s — a 2.34× speedup.

These are point-in-time measurements taken 2026-07-08 during this story's implementation.
The self-hosted pool currently has one Windows runner (`CFGMS-CI-WIN-01`), so concurrent
merge\_group or PR builds queue and serialize, which inflates individual durations.
GitHub-hosted runners are provisioned on demand with no queuing penalty. Measurements will
shift as the runner pool grows and cache state matures.

### 7.4 Native-Windows job evidence

The following run provides durable evidence that the `Native Build (Windows)` job has
executed and passed on the self-hosted Windows runner:

| Field | Value |
|-------|-------|
| Run ID | [28919392704](https://github.com/cfg-is/cfgms/actions/runs/28919392704) |
| Job name | `Native Build (Windows)` |
| `runner_name` | `CFGMS-CI-WIN-01` |
| Runner labels | `self-hosted, Windows, X64, cfgms` |
| `conclusion` | `success` |
| `started_at` | `2026-07-08T05:17:30Z` |
| `completed_at` | `2026-07-08T05:24:33Z` |
| Event | `pull_request` (non-fork, branch `feature/story-2379-windows-launcher-msi`) |

`CFGMS-CI-WIN-01` is the VM provisioned in §6 (runner id 23, Windows Server 2025
SERVERSTANDARD, 4 vCPU / 8 GB, host CFG-70-02). This run built all CFGMS binaries natively
on Windows (`make build`) and ran the unit test suite
(`go test -race -short -timeout=5m ./pkg/... ./features/...`), both passing on the
self-hosted runner.

### 7.5 Runner resource profile (Story #2428/#2485, hardened 2026-07-09)

The self-hosted CI jobs capture peak CPU% and peak memory usage during each run so
the VM allocation can be compared against actual utilization. This closes the gap
between knowing the *allocation* and knowing the *utilization* before deciding whether
to scale vertically (larger VMs) or horizontally (more VMs).

Story #2485 hardened the sampler: extracted inline YAML blocks to checked-in script
files (`.github/scripts/resource-sampler.sh` / `.github/scripts/resource-sampler.ps1`),
fixed the Linux loop guard bug (unguarded `awk` reads under `set -e` silently killed
the sampling loop), fixed the Windows `pwsh`→`powershell` invocation error, replaced
hardcoded `4vCPU/8GB` with dynamic CIM/proc reads, and scoped state dirs to
`RUNNER_TEMP` (job-unique) instead of `/tmp` / `$env:TEMP`.

**Jobs instrumented:**
- `unit-tests` (Linux, `cfgms-ci-lin-01`)
- `integration-tests` (Linux, `cfgms-ci-lin-01`)
- `Native Build (Windows)` (Windows, `CFGMS-CI-WIN-01`)

Steps run only on the self-hosted path (same fork-gate as the job); fork PRs and
`workflow_dispatch` events skip the sampler entirely — no cost added to hosted CI.

**How to read the resource profile:**

1. **Job log line** — search for `RESOURCE_PROFILE` in the "Report resource profile"
   step log. The line is emitted at the end of each instrumented run:

   ```
   RESOURCE_PROFILE: os=linux   cpu_peak_pct=<n> mem_peak_mb=<peak_mb>/<total_mb> vm=<n>vCPU/<n>GB
   RESOURCE_PROFILE: os=windows cpu_peak_pct=<n> mem_peak_mb=<peak_mb>/<total_mb> vm=<n>vCPU/<n>GB
   ```

   When sampling genuinely produced no data (e.g. the background sampler could not
   start, or the job was cancelled before the first interval), the error form is used:

   ```
   RESOURCE_PROFILE: os=linux   error=no_samples_collected vm=<n>vCPU/<n>GB
   RESOURCE_PROFILE: os=linux   error=sampler_start_failed vm=<n>vCPU/<n>GB
   ```

   `cpu_peak_pct` is the highest single 5 s interval CPU% observed during the job.
   `mem_peak_mb` is the highest used-memory reading (total − available) over the same
   interval. `vm=` is derived at report time from `nproc` / `/proc/meminfo` (Linux)
   or `Win32_ComputerSystem` (Windows) — it reflects the runner's actual configuration,
   not a provisioning target.

2. **Per-run artifact** — raw time-series samples (one line per 5 s interval:
   `HH:MM:SS cpu_pct=<n> mem_used_mb=<n>/<total_mb>`) are uploaded as an artifact
   retained for 30 days. Artifact names:

   | Job | Artifact name |
   |-----|---------------|
   | `unit-tests` | `resource-samples-unit-tests` |
   | `integration-tests` | `resource-samples-integration-tests` |
   | `Native Build (Windows)` | `resource-samples-native-windows` |

   Download from the Actions run page → Artifacts section, or via CLI:

   ```bash
   gh run download <run-id> --name resource-samples-unit-tests
   ```

**Real-world readings (from Story #2485 PR — runs `28987905900` / `28987905945`):**

First instrumented runs with the hardened sampler (Story #2485):

| Platform | Job | Run ID | Job ID | `RESOURCE_PROFILE` line |
|----------|-----|--------|--------|-------------------------|
| Linux | `unit-tests` | [28987905900](https://github.com/cfg-is/cfgms/actions/runs/28987905900) | `86021051708` | `RESOURCE_PROFILE: os=linux cpu_peak_pct=95 mem_peak_mb=2219/5930 vm=6vCPU/5GB` |
| Windows | `Native Build` | [28987905945](https://github.com/cfg-is/cfgms/actions/runs/28987905945) | `86021051568` | `RESOURCE_PROFILE: os=windows cpu_peak_pct=99 mem_peak_mb=3534/8191 vm=4vCPU/8GB` |

Both readings are non-zero, non-placeholder, contain no `${`, and show no `pwsh: command not found` error. The Windows reading matches the 4 vCPU / 8 GB provisioning target from §6. The Linux reading shows 6 vCPU and 5 GB measured RAM (see RAM discrepancy note below).

**Note on Linux VM RAM discrepancy:** §6 documents the Linux runner as provisioned with
8 GB RAM, but the `vm=` field in the `RESOURCE_PROFILE` line will reflect the actual
`MemTotal` from `/proc/meminfo` at run time. Prior observations showed ~4 GB measured
vs 8 GB provisioned target. This discrepancy is an open follow-up for the runner-sizing
owner and is not resolved in this story.

---

## 8. What the founder does vs what the agent builds

- **Founder (one-time prereq):** run §1 (≈1 click) and §3 (drop 3 secrets). That's it, forever.
- **Automated build-out:** the manifest-flow helper (optional), the controller token-minting integration (§4), the VM provisioning + registration wiring, steward management of the runners, and the gated CI-workflow routing (§5).
