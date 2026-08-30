# hyperv.vm cloud-init CIDATA seed-visibility investigation (Issue #3168)

## Summary

The planned Arm A / Arm B measurement batch (18-36 VMs across `cfg-lab`'s 3
Hyper-V hosts, comparing serial vs. same-host-concurrent provisioning) could
not run as designed. Before any VM reached the point where CIDATA visibility
could even be observed, two **pre-existing, unrelated infrastructure defects**
were discovered and had to be fixed live to get the provisioning pipeline
itself working end-to-end:

1. **Controller dispatch was completely broken fleet-wide** — filed as
   [#3741](https://github.com/cfg-is/cfgms/issues/3741) (epic, not yet fixed).
   `cfg steward exec` / `run-command` / `run-script` synthesized every run with
   `job_count: 0` regardless of target selector, because the dispatch path
   (`features/controller/api/handlers_runs.go`) fans out via
   `s.clusterFleetQuery`, which is wired to `ControllerService.GetAllStewardsCluster`
   — a method whose own doc comment says **"NOT for dispatch... Use
   `GetAllStewards` for dispatch."** This did not block `cfg config upload`
   (a different, durable-storage-backed path), so it did not block this
   investigation directly, but it meant `cfg steward exec` could not be used
   for any live diagnostic work in this session either.

2. **Controller DNA storage was never initialized on any of the 3 HA
   nodes** — fixed and merged as
   [#3745](https://github.com/cfg-is/cfgms/issues/3745) (PR #3746).
   `CFGMS_DNA_DB_PASSWORD` / `CFGMS_DNA_DATABASE_URL` were read via raw
   `os.Getenv`, with no `_FILE` indirection support (unlike
   `CFGMS_STORAGE_DB_PASSWORD`, which already has it per ADR-030). Every
   node's DNA storage backend failed to initialize on every startup since the
   nodes migrated to sealed-credential secret delivery. With DNA storage
   never initializing, the controller had zero DNA state for any steward —
   which meant `cfg config upload` never triggered a live config-sync push to
   a connected steward. The write to durable storage succeeded silently; the
   steward just never found out. This was the direct blocker for provisioning
   any VM via `cfg config upload` at all, and is now fixed and merged.

With both fixed, the pipeline (`cfg config upload` → steward config sync →
`hyperv.vm` module `Configure`/converge → real VM creation) was proven to
work end-to-end. The investigation then hit a **third, still-open defect**
that made it impossible to distinguish "CIDATA seed not visible" from "guest
never had network to register in the first place," described below.

## What was proven working

- A single VM (`poc-cidata-70-02-01` on `CFG-70-02`) was created, its boot
  disk converted, its CIDATA seed formatted and attached, and the VM started
  — confirmed via `Get-VM`: `State: Running`, `Uptime: 01:18:41`,
  `Status: Operating normally`.
- The seed-attach/format step intermittently fails on the **first** attempt
  for a fresh VM name with an uninformative `hyperv-ps-host: fresh seed op
  failed: exit status 1:` (empty stderr) — observed on both the boot-disk
  format step and the seed-attach step, on different runs, for different VM
  names. A second identical `cfg config upload` of the same resource always
  succeeded. This was **not** investigated further (out of this story's
  scope — see "Files In Scope" — the module's own retry/converge behavior
  already papers over it), but is worth a follow-up story: a transient,
  unexplained `exit status 1` from the PS-host transport on a fresh
  operation is itself a small version of "sometimes the first attempt at a
  vmbus-adjacent operation doesn't work," which may be mechanistically
  related to the CIDATA question this story exists to answer.

## The actual blocker: cross-host guest-VM network reachability

Running the real Arm A protocol (3 hosts × 3 serial VMs) produced a
**9/9 failure rate** — no guest ever registered with the controller within
the 10-minute window (some ran over an hour with no registration). A 100%
failure rate contradicts the story's own premise ("frequently, not always"),
so before recording it as a real measurement it was investigated:

1. **Console check (`diag-cidata-01` on `CFG-70-02`):** the login prompt
   showed hostname `diag-cidata-01`, not `localhost`. This means cloud-init
   **did** successfully detect and read the NoCloud/CIDATA datasource on
   this boot — directly contradicting the story's primary hypothesis for
   this run. The failure is downstream of seed detection.

2. **Controller-side registration logs (all 3 nodes, spanning the entire
   batch window):** zero incoming registration attempts from any of the 9
   Arm A VMs or the diagnostic VMs. Not "rejected" — **absent**.

3. **DHCP lease table (`cfg-dc2-02`, the lab's DHCP server):** every guest
   VM hosted on `CFG-AB-02` and `CFG-C3-02` — all 6 Arm A VMs from those two
   hosts, plus `diag-cidata-ab02` — **did** get an active DHCP lease with
   correct hostname and successful dynamic DNS registration
   (`*.lab.cfg.is`). This means those guests' cloud-init `runcmd` stage ran
   far enough to bring up networking and complete a full DHCP round-trip.
   **None** of `CFG-70-02`'s own 3 Arm A VMs, nor its 2 diagnostic VMs, ever
   appear in the lease table at all — `CFG-70-02`-hosted guests never
   obtain a lease.

4. **Direct reachability, `CFG-70-02` → `cidata-a-cfgab02-02`
   (192.168.234.109, a leased AB-02 guest):** `ping` fails with
   `Destination host unreachable` reported by `CFG-70-02`'s own stack (ARP
   resolution never completes) — despite `CFG-70-02` successfully pinging
   `CFG-AB-02` and `CFG-C3-02`'s **host** IPs (192.168.234.100/.101)
   directly, and successfully pinging `cfgms-lab-datasvc`
   (192.168.234.105).

5. **Local reachability, `CFG-AB-02` → its own guest
   `diag-cidata-ab02` (192.168.234.114):** also fails — **the host hosting
   the VM cannot reach its own guest**, over the same `HVSwitch_1G` external
   switch the VM's DHCP lease came through moments earlier. This rules out a
   physical-switch/VLAN explanation (confirmed `Untagged`, `AccessVlanId: 0`
   on the switch's management-OS adapter) — the failure is either in the
   guest's own network stack shortly after DHCP completes, or in the local
   Hyper-V vSwitch port for that specific VM.

6. The guest console (`diag-cidata-01`) logged, during boot: `TCP: eth0:
   Driver has suspect GRO implementation, TCP performance may be
   compromised.` — a kernel warning about the `hv_netvsc` synthetic NIC
   driver on this image/kernel combination.

**No shell could be obtained on any guest to investigate further.** A
second diagnostic VM (`diag-cidata-ssh`) was created with
`debug_ssh_authorized_key` set specifically so it could be inspected via
SSH — but SSH requires exactly the network path that is broken, so this
did not help. PowerShell Direct is not available for Linux guests. Serial
console output beyond the login-prompt screenshot was not captured.

## Interpretation

The evidence is inconsistent with a purely physical-network cause (VLAN,
switch port security, or a router in the path): DHCP round-trips
successfully in both directions, and `CFG-70-02` reaches every physical
host directly. It is also inconsistent with the CIDATA-visibility
hypothesis this story exists to test: at least one guest (`diag-cidata-01`)
proved cloud-init read the seed correctly (hostname set), and guests that
got DHCP leases clearly had a functioning `runcmd` stage far enough to
complete a DHCP handshake and a dynamic DNS update.

The pattern — DHCP (a broadcast-based, largely fire-and-forget exchange)
succeeds, while ARP/ICMP (which require the guest to keep responding
afterward) fails, even from the guest's own host — points at the guest's
`hv_netvsc` synthetic NIC entering an unresponsive state shortly after
initial bring-up, rather than anything CIDATA- or CFGMS-specific. The GRO
driver warning in the console log is circumstantial support for a
driver/vmbus-level issue on this kernel/image combination, but was not
confirmed as the cause — only observed alongside it.

**`CFG-70-02` never getting a DHCP lease at all (vs. `AB-02`/`C3-02`
getting a lease but losing reachability shortly after) is a second,
possibly separate anomaly** specific to that host, not explained by
anything above. It was not investigated further given time constraints.

## Decision rule (per this story's AC)

The story's Arm A/B decision rule (compare same-host-concurrent vs. serial
failure counts) could not be applied: the pipeline never reached a state
where CIDATA-specific pass/fail data could be collected, because guest
network reachability failed independently of, and prior to, any
CIDATA-specific behavior being observable. **Result: inconclusive, blocked
on a separate, newly-discovered defect** — not a 3-vs-5-style noise case
this story's decision rule anticipates, but a hard precondition failure.

## Recommended next steps

1. **Fix cross-host / guest-network reachability first.** This blocks not
   only this story but any future live Hyper-V VM work on `cfg-lab`.
   Suggested starting points for whoever picks this up:
   - Check `hv_netvsc` driver/kernel version on the `debian-13-generic-amd64.raw`
     image against a known-good combination; the GRO warning is a live lead.
   - Check whether `CFG-70-02`'s failure to get a lease at all (distinct
     from `AB-02`/`C3-02`'s lease-then-unreachable pattern) shares a root
     cause or is a second, independent problem specific to that host's
     switch/NIC binding.
   - Get a console-level (not network-dependent) shell on a guest that has
     completed DHCP but is unreachable, to check `ip link` / `ip neigh` /
     `dmesg` state on the guest side — this session could not, since it had
     no console-only shell access mechanism available for a Linux guest.
2. **File the `exit status 1` seed-op transient failure** (seen on both the
   format and attach steps, always resolved by an immediate retry) as its
   own small follow-up story if it recurs — it's a candidate for being a
   smaller instance of the same class of problem this story investigates.
3. **Re-run this story's Arm A/B protocol** once (1) is resolved. The
   provisioning pipeline itself (`cfg config upload` → convergence → real
   VM) is now proven working end-to-end, so re-running should not require
   repeating any of the infrastructure debugging above.

## VM specs used (for the runs above, and recommended unchanged for the re-run)

- Generation 2, 2 vCPU, 2 GB fixed memory (dynamic memory disabled)
- OS disk: 32 GB dynamic VHDX, from `debian-13-generic-amd64.raw` (Debian 13,
  `generic` cloud image variant)
- Switch: `HVSwitch_1G` (one switch per host, untagged/no VLAN)
- Secure Boot: not explicitly set in these runs (module default); not varied
- Seed dir: local per-host `C:\cfgms-seeds` (non-CSV, per prior lab guidance)
- Boot-disk path: local per-host `C:\VMs\<name>.vhdx` (non-CSV)
