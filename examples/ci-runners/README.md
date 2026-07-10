# Self-Hosted CI Runners — CFGMS Example

This directory contains a **secrets-free** example configuration for standing up
GitHub Actions self-hosted CI runners on Hyper-V VMs managed by CFGMS.

All sensitive fields use `REDACTED` or `PLACEHOLDER_*` values. Real lab
configuration stays local and is never committed to this repository.

---

## Files in this directory

| File | Purpose |
|------|---------|
| `linux-runner.cfg` | Steward cfg pushed to a Linux runner VM |
| `windows-runner.cfg` | Steward cfg pushed to a Windows runner VM |
| `github-app-secrets.example.yaml` | Documents the three secret key names loaded into the secrets provider |

---

## End-to-end walkthrough

### Step 1 — Provision the VM (ADR-009)

Runner VMs are declared as `hyperv.vm` resources on a Hyper-V host already
managed by CFGMS.  The declarative `source:` block in ADR-009 drives the
ISO-to-OS provisioning cycle:

- OS installs unattended from a stored profile (`unattend: profile://...`).
- Completion mode `steward-registration` boots the finished VM, enrolls the
  steward, and hands control to the controller.

See [ADR-009](../../docs/architecture/decisions/009-hyperv-vm-provisioning-from-install-media.md)
for the full `hyperv.vm` schema and the provisioning state machine.

### Step 2 — Enroll the steward

After first boot the steward calls home and registers with the controller.
No extra steps are required if `completion: { mode: steward-registration }` was
set in the `hyperv.vm` source block — enrollment happens automatically as part
of the provisioning workflow.

For manually booted VMs:

```bash
cfg steward enroll --controller <CONTROLLER_URL> --name <STEWARD_ID>
```

### Step 3 — Push the runner cfg

Upload the appropriate cfg to the enrolled steward:

```bash
# Linux runner
cfg config upload linux-runner.cfg --steward ci-runner-linux-01

# Windows runner
cfg config upload windows-runner.cfg --steward ci-runner-windows-01
```

The `github_runner` module fetches the agent archive, verifies the SHA-256,
installs it under `work_dir`, and manages the runner service.

Before uploading, edit the cfg to set:

- `steward.id` — the enrolled steward hostname.
- `config.version` — the pinned runner agent release.
- `config.agent_url` — the download URL matching the version and OS/arch.
- `config.agent_sha256` — the SHA-256 of the archive (lowercase hex, 64 chars).
  Verify with `sha256sum` (Linux) or `Get-FileHash` (Windows).

Module field names come from
[`features/modules/extended/github_runner/config.go`](../../features/modules/extended/github_runner/config.go).

### Step 4 — Load the GitHub App secrets (one-time)

The controller needs three secrets to mint runner registration tokens. These are
stored in the CFGMS secrets provider (SOPS-encrypted) — never in cfg files or
on disk in cleartext.

See **[docs/development/ci-runner-github-app-setup.md](../../docs/development/ci-runner-github-app-setup.md)**
for the full one-time GitHub App bootstrap:

- Creating the App via the manifest flow (~1 click).
- Installing it on the repository.
- Storing the three credentials:

  ```
  github_app_id
  github_app_installation_id
  github_app_private_key_pem
  ```

The key names in `github-app-secrets.example.yaml` must match exactly — they are
read verbatim by `features/workflow/github_app_provider.go`.

```bash
cfg secrets set github_app_id              <your-app-id>
cfg secrets set github_app_installation_id <your-installation-id>
cfg secrets set github_app_private_key_pem /path/to/private-key.pem
```

### Step 5 — Run the provisioning workflow

Once the steward is enrolled and the secrets are loaded, trigger the runner
provisioning workflow on the controller:

```bash
cfg workflow run github-runner-provision \
  --param steward_id=ci-runner-linux-01 \
  --param owner=<GITHUB_ORG_OR_USER> \
  --param repo=<REPO_NAME>
```

The workflow:

1. Mints a short-lived runner registration token via the GitHub App (§4 of the
   setup runbook — fully automated, no human in the loop).
2. Delivers the token to the steward and invokes `./config.sh` to register the
   runner.
3. Starts the runner service.

Teardown (deregister + destroy VM) runs via the corresponding teardown workflow.

---

## Fork-gate safety

Self-hosted runners on this PUBLIC repository must never execute untrusted
fork-PR code. The CI workflow enforces this with:

```yaml
if: github.event.pull_request.head.repo.fork == false
```

External fork PRs fall back to GitHub-hosted runners. The repo is also
configured to **require approval for fork pull request workflows** under
Settings → Actions. No secrets or self-hosted infrastructure are exposed to
fork-PR contexts.

See [docs/development/ci-runner-github-app-setup.md §5](../../docs/development/ci-runner-github-app-setup.md)
for the full public-repo safety guidance.

---

## No secrets in this directory

All values in the cfg files and the secrets example file are placeholders.
The Trivy secret scanner (`make security-scan`, included in `make test-complete`)
covers this directory and will block any commit that introduces real secret
material.

Real GitHub App credentials, runner registration tokens, and private keys
must never be committed here. Keep them in the CFGMS secrets provider.
