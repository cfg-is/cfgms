# ADR-009: Hyper-V VM Provisioning from Install Media (ISO → Managed Endpoint)

**Status:** Accepted

**Date:** 2026-06-18

**Deciders:** Founder, Architecture

**Related:** [006](006-module-packaging-and-distribution.md) (module kinds — `hyperv` is a steward-on-host module), [003](003-storage-data-taxonomy.md) (unattended profiles as stored config), [001](001-central-provider-compliance-enforcement.md) (secrets central provider for rendered credentials). Epics: #1851 (this capability, M3 of #390), #1792 (Phase 3 — successor / golden-image fleets).

---

## Context

The `hyperv` module today **operates existing VMs**: typed `hyperv.vm` and `hyperv.vswitch` resources with create/modify/start/stop/delete, declarative multi-NIC, and idempotent power, proven end-to-end on cfg-lab (PR #2035). It cannot **create a VM from nothing** — i.e. turn install media into a running, managed OS.

That gap blocks two things at once:

1. **Dogfooding** — CFGMS needs to provision its own test fleet on the lab Hyper-V cluster (#390 milestone M5). Today that is manual.
2. **Product capability** — an MSP managing 50k endpoints wants to declare "a managed VM on host X" and have it materialize, not hand-build it.

The friction worth naming: provisioning an OS from an ISO *feels* imperative (attach media, boot, answer the installer, wait, verify), while CFGMS is declarative and convergence-based. Resolving that tension cleanly — rather than bolting an imperative provisioning subsystem onto a declarative system — is the purpose of this ADR.

Two facts shape the decision:

- **Provisioning is "convergence from nothing."** Most resources already hide imperative steps behind a declarative contract (`package` runs an installer; `service` starts a daemon). A VM install is the same pattern, with one twist: it is *long-running* (5–25 min), which a fast-reconcile convergence loop must accommodate.
- **The destructive blast radius is real.** A VM is durable state. Conflating "won't boot" with "needs rebuilding" risks destroying a recoverable workload. The trigger for provisioning must be **non-existence**, never health.

## Decision

### 1. Provisioning is a declarative extension of `hyperv.vm`, not a new imperative verb

Add an optional `source` block to the existing typed `hyperv.vm` resource:

```yaml
module: hyperv.vm
name: stw-win-01
state: present
config:
  generation: 2
  cpu: 4
  memory_mb: 6144
  vhd_path: C:\ClusterStorage\CSV01\stw-win-01.vhdx
  vhd_size_gb: 64
  switch_name: HVSwitch_1G
  source:                                   # creation-time intent; see §2
    iso: C:\ClusterStorage\CSV01\iso\windows-server-2025.iso   # host path (see §4)
    os_family: windows                      # linux | windows
    unattend: profile://win2025-steward     # stored profile reference (see §6)
    completion: { mode: steward-registration, timeout: 60m }
    on_existing: never                      # never (default) | recreate (explicit opt-in)
```

Convergence makes the declared state true; the OS install is an implementation detail inside the create path. There is exactly one way to make a VM.

### 2. Existence-gated, never health-gated (safety invariant)

**`source` is acted on only when the VM does not exist (by name) on the host.** Health and bootability are never the trigger.

- VM **absent** → provision from `source`.
- VM **exists and `ready`** (or any existing VM with no in-progress provisioning record of ours) → `source` is **inert**; the VM is never touched.
- VM **exists but broken / won't boot** → surfaced as `degraded`; the module **does not** delete-and-rebuild.
- **Destructive reprovision of an existing VM is explicit opt-in** via `source.on_existing: recreate` (default `never`). The default convergence path can never destroy a VM.

To distinguish "my own incomplete provisioning attempt" (provably holds no workload — safe to resume/retry) from "a real existing VM," the module keeps a **per-VM provisioning record** (state below). Auto-retry of an own-incomplete attempt defaults **off** (surface-and-wait); bounded retry is an opt-in knob. Nothing is destroyed automatically, ever.

### 3. Provisioning state machine (long-running convergence)

The module reports a lifecycle status advanced **one step per convergence cycle** — it never blocks the loop on a multi-minute install:

```
absent ─create VM/disks/NIC + attach install ISO + attach seed ISO─▶ creating
creating ─power on─▶ installing ─(unattended install runs)─▶ finalizing ─(detach media, first-boot enroll)─▶ ready
installing ─timeout / marker=fail─▶ failed       (existing-but-unhealthy real VM ─▶ degraded)
```

A controller restart or a slow install simply resumes from the recorded state.

### 4. Install media is a host path; staging is out of scope

`source.iso` is a path on the Hyper-V host (e.g. on a CSV). Getting the ISO there is **not** this module's concern — an operator stages it, or a declarative `file` module resource does. This ADR adds **no** controller blob store, large-object transfer, or ISO distribution path. (Centralized ISO distribution may be revisited later; it is not required for the capability.)

### 5. Answer-file delivery via a host-native secondary VHDX; gen1 + gen2

The unattended answer file is delivered on a **secondary VHDX seed disk** attached to the VM, built on the host with **native cmdlets only** — `New-VHD` + `Mount-VHD` + `Format-Volume` + copy — then detached at `finalizing`. This was chosen over a secondary ISO because building an ISO on the host requires `oscdimg` (Windows ADK), which is **not present on a stock Hyper-V host** (verified absent on cfg-lab; `New-VHD`/`Format-Volume`/`Mount-VHD` are present as part of the Hyper-V + Storage roles the host already runs). A VHDX seed therefore adds **no host dependency and no new Go module** (a pure-Go ISO builder was the alternative, rejected to avoid the dependency). It works on **both Gen1 and Gen2** (no floppy needed). Windows Setup auto-discovers `autounattend.xml` from attached media; debian-installer reads `preseed.cfg` from the labeled seed volume. **The install ISO is never repacked/re-signed** (a known cfg-lab failure with signed UEFI boot media). Gen2 secure-boot template is selected by `os_family` (`MicrosoftWindows` vs `MicrosoftUEFICertificateAuthority`); Gen1 has no secure boot.

### 6. Cross-OS unattended model

| | Linux (Debian 12) | Windows (Server) |
|---|---|---|
| Install answer file | `preseed.cfg` (debian-installer) | `autounattend.xml` (Windows Setup auto-reads from removable-media root) |
| First-boot config/enroll | `late_command` / cloud-init `runcmd` | signed **`.ppkg`** provisioning package at OOBE; file-staged `SetupComplete.cmd` only as fallback |

`autounattend.xml` is the supported mechanism for unattended Windows **Setup** from ISO (not deprecated; install-time, not config-time). A `.ppkg` cannot install the OS — it configures an already-installed Windows. Using a **signed ppkg** for the post-install/enrollment step (rather than an inline PowerShell blob in `<FirstLogonCommands>`) is a deliberate fit with the module banned-pattern rules: a signed declarative artifact over runtime script composition.

### 7. Unattended profiles are stored config, addable without code

A profile (`profile://<name>`) is a stored config object (ADR-003 taxonomy) describing `os_family`, `answer_format`, the answer-file template, and an `enroll` block. Operators add a new OS by adding a profile — **no code change** (the AC). Profiles are rendered with per-VM variables and **secrets from the secrets provider at provision time** — never cleartext in the profile or committed media.

### 8. Enrollment reuses the existing steward-deploy mechanism; `ready` = steward registration

First boot installs and enrolls the steward exactly as a normal steward deployment does (regtoken / mTLS bundle). The VM reaches **`ready` when its steward registers with the controller** — closing bare-hypervisor → installed-OS → registered-steward → managed-endpoint in a single converge.

**Where completion is observed.** Steward registration is a **controller-side** fact, but the `hyperv` module runs on the *host's* steward, which cannot see the controller's registry. Therefore the host-side module advances the VM only as far as `finalizing` (OS installed, seed detached, first boot underway); the transition to `ready` is determined **controller-side** by correlating a newly-registered steward to the provisioned VM via a **correlation identity** baked into the rendered profile (e.g. the expected steward hostname/enrollment label). The provisioning record carries this correlation value so the controller can flip the resource to `ready` (or to `failed` on `completion.timeout`). Decomposition must place the completion check on the controller side, not as a host-side poll of the controller.

**Tradeoff accepted for v1:** a shared/long-lived enrollment secret may sit on the seed media during install. **Future hardening** (separate work): controller-rendered per-VM, single-use, short-TTL enrollment tokens, with seed media detached and the token consumed at first check-in.

### 9. Scope boundary

This capability is **ISO-install only**. Golden-image / template cloning, an image registry, and a branch-build→image pipeline are **Phase 3** (#1792) — they need an image store and build pipeline and are the scale optimization for ephemeral per-dispatch fleets. They are explicitly **out of scope** here.

## Consequences

**Positive**
- One declarative artifact yields a managed endpoint; reuses the convergence loop, the existing `hyperv` module, and the existing enrollment path.
- The dogfood need (provision the test fleet) and the product feature are the **same code**.
- Existence-gating removes the most dangerous failure mode (accidental VM destruction) by construction.

**Negative / risks (and mitigations)**
- Long-running convergence introduces per-VM provisioning state (mitigated by the explicit state machine + record).
- Secrets on seed media during install (mitigated now by reusing the trusted steward-deploy path; hardened later per §8).
- Per-OS answer-file templates to author and maintain (contained to data/profiles, not code).
- UEFI/secure-boot and Gen1/Gen2 pitfalls (handled by `os_family`-driven template selection; secondary-ISO delivery; never re-signing install media).

## Alternatives considered

- **Imperative "provision" verb returning a ready VM.** Rejected — breaks idempotency and the declarative model, and creates a second way to make a VM.
- **Health-gated reprovision (auto-rebuild a broken VM).** Rejected — data-loss footgun; replaced by existence-gating + explicit `on_existing: recreate`.
- **Golden-image cloning first.** Deferred to Phase 3 (#1792) — requires an image store + build pipeline; ISO install is the simpler first capability.
- **Controller blob store for ISOs.** Deferred — host-path + the `file` module is sufficient now.
- **Per-VM short-lived enrollment tokens for v1.** Deferred — reuse the existing steward-deploy enrollment now; harden later (§8).
