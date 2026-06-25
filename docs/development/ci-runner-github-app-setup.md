# CI Runner GitHub App — Setup Runbook

**Status:** DRAFT (epic #565 MVP — self-hosted Hyper-V CI runners managed by CFGMS).

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
4. **Inject + register** — deliver the registration token to the fresh Hyper-V VM via the existing controller-supplied-config path (the #2080 token-delivery pattern), then on the VM:
   ```
   ./config.sh --url https://github.com/cfg-is/cfgms --token <reg-token> \
               --labels self-hosted,linux,hyperv --unattended --replace
   ./run.sh    # (persistent MVP) — or run as a service, see story 4
   ```
5. **Deregister on teardown** — `DELETE /repos/.../actions/runners/{runner_id}` (or `--ephemeral` self-deregisters after one job).

> **Ephemeral follow-up (deferred):** replace steps 3–5 with a single `POST /repos/.../actions/runners/generate-jitconfig` call; boot the VM with `./run.sh --jitconfig <base64>`. The runner self-registers, runs exactly one job, self-deregisters, and the VM is destroyed. Same App, same installation token — no extra setup.

---

## 5. Public-repo safety (load-bearing — see epic #565)

Self-hosted runners must never execute untrusted fork-PR code on this PUBLIC repo. The CI workflow gates self-hosted jobs on:

```yaml
if: github.event.pull_request.head.repo.fork == false   # internal feature/* branches only
```

External fork PRs fall back to GitHub-hosted runners. Additionally set **repo → Actions → "Approval for running fork pull request workflows" = require approval for all external contributors**. No repo secrets are exposed to fork-PR contexts.

---

## 6. What the founder does vs what the agent builds

- **Founder (one-time prereq):** run §1 (≈1 click) and §3 (drop 3 secrets). That's it, forever.
- **Agent / stories (#565):** the manifest-flow helper (optional), the controller token-minting integration (§4), the VM provisioning + registration wiring, steward management of the runners, and the gated CI-workflow routing (§5).
