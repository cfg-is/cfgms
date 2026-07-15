# Targeting Hyper-V hosts by tag — the `hyperv-host` role

**Issue #2548 · epic #2537 (selector-driven role-config cascade — Path B)**

This runbook shows how to deliver a Hyper-V configuration to a *class* of hosts
by tag, with **no per-steward upload**. You author one role config, select it
with `runtime_os == windows AND tag hyperv-host`, and every steward that matches
inherits the config through the controller's `InheritanceResolver` cascade
(#2546). Tag a host and the resource appears in its effective config; untag it
and the resource is removed.

The worked example delivers a NIC-independent **internal virtual switch**
(`cfgms-role-net`) — uniform across every node, non-destructive, and idempotent.

## Prerequisites

- A controller running a build that includes the tag admin REST (#2545), the
  selector-driven role adapter (#2546), and the role-config REST surface (#2543).
- An admin credential: an admin bundle (`--bundle` / `CFGMS_ADMIN_BUNDLE`) or a
  session (`cfg connect`).
- The role config fragment: [`examples/roles/hyperv-host.cfg`](../../examples/roles/hyperv-host.cfg).
- The tenant that owns the target stewards (below, `infra-hyperv`). A **global
  admin must name the tenant** with `--tenant` — role configs are stored per
  tenant. A tenant-scoped admin is pinned to its own tenant and omits `--tenant`.

## 1. Author the role config

The fragment file carries only the config to inject; the selector is supplied at
author time.

```bash
cfg role create hyperv-host \
  --tenant infra-hyperv \
  --selector "os:windows tag:hyperv-host" \
  --config examples/roles/hyperv-host.cfg

cfg role ls   --tenant infra-hyperv          # hyperv-host listed
cfg role show hyperv-host --tenant infra-hyperv   # inspect selector + fragment
```

The fragment is a single `hyperv.vswitch` resource of `switch_type: internal`,
`state: present`. An internal switch has no host-NIC dependency, so the identical
fragment is valid on every matched node.

## 2. Tag a host — the resource appears in its effective config

```bash
STEWARD=<steward-id>     # e.g. the cfg-lab node's steward id

cfg steward tag add "$STEWARD" hyperv-host
cfg steward tag ls  "$STEWARD"           # hyperv-host

# The injected resource now shows in the resolved config, sourced from the role
# (NOT a per-steward upload):
cfg config show "$STEWARD" | grep -A3 cfgms-role-net
```

The selector is `os:windows tag:hyperv-host`, so a host only inherits the role
when **both** hold: its DNA reports `os == windows` **and** it carries the
`hyperv-host` tag. Tag a Linux host and nothing is injected.

## 3. The host converges the switch

The tagged host applies the injected resource on its **next config-refresh /
convergence cycle**, after which the switch exists on the host:

```bash
cfg steward exec "id:$STEWARD" \
  --shell powershell \
  --command 'Get-VMSwitch -Name cfgms-role-net | Format-List Name,SwitchType'
# → Name: cfgms-role-net   SwitchType: Internal
```

> **Timing (important):** a tag change updates the *resolved* config immediately
> (step 2), but the steward converges against the **last config version it was
> handed** and only pulls a fresh config when that **version bumps**. A tag or
> role change does **not** currently bump the steward's config version, so a
> freshly-tagged host keeps converging its cached config and will not pick up the
> role resource until the version next changes — e.g. any `cfg config upload` to
> that steward (even re-uploading its unchanged device config), which forces a
> re-pull whose fresh resolve now includes the injected resource. A steward
> restart / reconnect alone is **not** sufficient (it re-applies the same cached
> version). Prompt tag-driven convergence — bumping the effective version and/or
> pushing on a role/tag change — is the DNA-currency concern tracked by epic
> #2520; this story's scope is the cascade *delivery*, which is immediate and
> correct. Verified live on cfg-lab 2026-07-15: tagging CFG-70-02 then bumping its
> config version converged `cfgms-role-net` (internal) on the host.

## 4. Untag — the resource leaves the resolved config

```bash
cfg steward tag rm "$STEWARD" hyperv-host

# Removed from the resolved config immediately (the cascade no longer injects it):
cfg config show "$STEWARD" | grep -c cfgms-role-net    # → 0
```

> **The physical switch is NOT auto-deleted on untag.** CFGMS convergence manages
> *declared* resources and does **not** prune resources that merely disappear from
> a config — removing a line never destroys infrastructure. So after untag the
> steward simply stops managing `cfgms-role-net`; the switch remains on the host
> until it is explicitly removed (e.g. `Remove-VMSwitch`, or a config that
> declares it `state: absent`). The story chose an internal switch precisely so
> that this lingering resource strands nothing (no attached VMs). Making a
> role-removal actively tear the resource down is a separate behavior change
> (undeclared-resource pruning) with fleet-wide safety implications — out of scope
> here.

## Removing the role entirely

```bash
cfg role delete hyperv-host --tenant infra-hyperv
```

## Why an internal switch

The role fragment is uniform across every matched node by design, so it must not
depend on any per-host detail. An **external** switch binds a specific physical
NIC (`net_adapter_name`) that differs per node and would strand VMs when removed;
an **internal** switch has neither constraint. Per-host field-level overrides
(shared role + per-host tweaks) are a separate follow-up — see #2548 Non-Goals.
