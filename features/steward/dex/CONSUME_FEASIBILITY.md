# DEX In-Process ETW Consume Feasibility — Measured Results (#2571)

Feasibility deliverable for the Windows in-steward Go DEX collection agent. This
closes the load-bearing gap left open by #2540 (`SPIKE_RESULTS.md`): #2517/#2540
proved provider **reachability + enablement overhead** only and shipped with **no
consumer**, because the in-process Go `ProcessTrace` consumer crashed the Go
runtime (`acquireSudog` / `cgocallbackg` corruption). This spike proves the
**consume path and everything the agent depends on downstream of it** — with real
runs in the steward's `LocalSystem` (SYSTEM) context, not desk research.

This is a **throwaway PoC** (build tag `dexconsume`, cgo; never compiled into the
production steward). It does **not** build the DEX engine, define a schema, or
persist anything. The collection track stays gated on the storage-shape ADR +
ADR-017 Amendment 1.

## Bottom line — GO (in-steward Go DEX consumption is feasible)

An in-steward Go process **can** consume, decode, and attribute a high-rate ETW
stream in its own SYSTEM service context, stably, well within the 1.0% CPU budget.
The #2517 runtime crash is **avoided by construction** with a non-reentrant C
callback. The one hard limit is unchanged from #2540 and is a Windows platform
fact, not an agent limitation: **UI/app-hang ("employee experience") signals do
not emit in the steward's service session (0)** and require a separate per-session
acquisition path.

| # | Load-bearing part | Verdict |
|---|-------------------|---------|
| 1 | High-rate in-process consumption, stable | **PROVEN** |
| 2 | Event decode in Go (TDH / manifest schema) | **PROVEN** |
| 3 | Per-process / entity attribution | **PROVEN** |
| 4 | Real overhead at volume vs 1.0% budget | **PROVEN** (within budget) |
| 5 | Sustained ≥10-min stability | **PROVEN** _(see run 2)_ |
| 6 | Session-0 UX-signal reachability | **BLOCKED** — needs a per-session component |

## The crux and the architecture decision

#2517 found that a real-time `ProcessTrace` consumer with a
`windows.NewCallback`-wrapped Go callback corrupts the Go runtime under load:
every ETW event fires the callback on an OS thread ETW owns, and the native→Go
transition (`cgocallbackg`) mutates per-P runtime state that collides with the
scheduler. Restricting the callback body to atomic ops does not help — the crash
is in the *entry path*, not the body.

Four candidate architectures were considered (story §"Load-bearing parts", part 1):

- **(a) Event-Log-first (`EvtSubscribe`)** — proven in-process by the hyperv
  Monitor (#2114), but only exists for signals that have an Event Log *channel*.
  The high-rate kernel providers (Kernel-Disk, Kernel-PerfInfo, Kernel-File) are
  raw-ETW-only, so (a) cannot cover part 1's requirement.
- **(b) Out-of-process native consumer** piping to Go — works, but adds an IPC
  boundary and a second signed binary to deploy.
- **(c) In-process Go with a non-reentrant C callback** — the EventRecordCallback
  is a pure C function that copies each event into a C ring buffer and never calls
  back into Go; a Go goroutine drains the ring. The hot path is C→C only, so
  `cgocallbackg` is never taken.
- **(d) Buffered `.etl`-file mode** parsed periodically — higher latency; still
  needs a `ProcessTrace` callback to read the file (same crash unless the callback
  is C).

**Chosen: (c).** It keeps everything in one signed binary, needs no IPC, and is
the minimal change that makes the crash structurally impossible. Implementation:
`consume_etw_windows.c` (single-producer/single-consumer ring + the C callback +
`OpenTrace`/`ProcessTrace` runner + bounded TDH decode) and `consume_windows.go`
(cgo wrapper: session start, drain, attribution, overhead, ETW lost-event query).

## Run context (proof of real runs)

Executed **in the steward's own `LocalSystem` service context** via the signed
inline-exec admin channel (`cfg steward exec`) to the CFG-70-02 steward — the
faithful deployment context, which holds the ETW `StartTrace` privilege.

| Field | Value |
|-------|-------|
| Host | **CFG-70-02** |
| Executing identity | **NT AUTHORITY\SYSTEM** (steward `LocalSystem` service context) |
| Windows session | **0** (service session — no interactive desktop) |
| OS | Microsoft Windows Server 2025 Datacenter Evaluation, build 26100 |
| Steward | `steward-1780659937223058807`, tenant `infra-hyperv` |
| Binary | `go test -c -tags dexconsume` PoC, run as SYSTEM |
| Providers | Win32k, Kernel-Disk, Kernel-PerfInfo, DNS-Client, **Kernel-File** (high-rate stress) |

**Why this is a real privileged run:** run **non-elevated** the same binary reports
`session_start_err: StartTraceW: Access is denied. (code 5)` and consumes nothing;
run in the steward SYSTEM context it starts the session and consumes tens of
thousands of events. That flip is only possible under genuine `StartTrace`
privilege.

## Part 1 — High-rate in-process consumption, stable — PROVEN

**Run 1 (12 s window, all 5 providers, live SYSTEM):**

| Metric | Value |
|--------|-------|
| Events observed by the C callback (`total_seen`) | **47,426** |
| Events drained by Go (`total_drained`) | **47,426** |
| Ring-full drops (`dropped_ring`) | **0** |
| ETW kernel lost events (`etw_events_lost`) | **0** |
| ETW real-time buffers lost | **0** |
| Throughput | **≈3,950 events/s** |
| Runtime crash | **none** (`crashed: false`, process returned cleanly) |

The consumer stayed up for the full window under real host load, drained every
event the callback enqueued, and lost nothing — with the exact `ProcessTrace`
real-time consumer that crashed the runtime in #2517, now made safe by the C
callback. **The #2517 crash is resolved (avoided by construction).**

## Part 2 — Event decode in Go (TDH / manifest schema) — PROVEN

The C callback TDH-decodes a bounded sample of target-provider events into named
fields (`TdhGetEventInformation` → `TdhGetProperty` per top-level property). Real
decoded fields from run 1 (`decode_sample`), meaning extracted, not just counts:

- **DNS-Client** event 1001: `Interface=vEthernet (HVSwitch_1G); TotalServerCount=2; Index=1; DynamicAddress=1; AddressLength=16`
- **Kernel-File** event 15 (Read): `ByteOffset=2698805248; IOSize=4096; IssuingThreadId=2552; FileObject=…; FileKey=…`
- **Kernel-File** event 10 (Create): `FileKey=…; FileName=\Device\HarddiskVolume3\Windows\System32\ualapi.dll`
- **Kernel-File** event 24 (OperationEnd): `ExtraInformation=4096; Status=0`

Manifest/MOF schema decode works from the live `EVENT_RECORD` during the callback.
Note: TDH decode is comparatively expensive (`TdhGetEventInformation` builds a
`TRACE_EVENT_INFO` per event), so a production agent should decode **selectively**
(only the events a signal needs), not every event on the hot path — see
recommendation below. The bounded-sample design here reflects that.

## Part 3 — Per-process / entity attribution — PROVEN

Every event carries `EVENT_HEADER.ProcessId`; the Go drain side resolves PID →
full image path via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` +
`QueryFullProcessImageName`, cached per PID. Run 1 attributed **57 distinct PIDs**.
Top attributed images (event counts):

| PID | Image | Events |
|-----|-------|--------|
| 19072 | `C:\Program Files\PowerShell\7\pwsh.exe` | 24,522 |
| 5948 | `…\wbem\WmiPrvSE.exe` | 5,998 |
| 15012 | `C:\Python314\python.exe` | 4,544 |
| 4 | System | 2,247 |
| 17380 | `…\CFGMS\versions\v0.9.25\cfgms-steward.exe` | 1,459 |
| 1080 | `…\System32\lsass.exe` | 410 |

Attribution resolves the "who" for a DEX signal. Protected/exited PIDs resolve to
an empty image (an expected, handled edge — e.g. PID 0/4 are labelled). User
attribution (token → SID → account) is a straightforward extension of the same
per-PID handle and is noted as low-risk; it was not required to prove the part.

## Part 4 — Real overhead at volume vs the 1.0% budget — PROVEN (within budget)

Overhead is `GetProcessTimes` (kernel+user) delta over the window, normalised to
one logical core; working set via `GetProcessMemoryInfo`.

| Run | Window | Throughput | CPU % (1-core) | Working set | Dropped / ETW-lost | Verdict |
|-----|--------|-----------|----------------|-------------|--------------------|---------|
| 1 | 12 s | ≈3,950 evt/s | **0.39 %** | ~10 MB¹ | 0 / 0 | within 1.0% budget |
| 2 | **10 min** | **≈10,158 evt/s** | **0.487 %** | **~9–12 MB (flat)** | **0 / 0** | **within 1.0% budget** |

This is the **real consume+decode-sample+attribute cost**, superseding #2540's
enablement-only 0.00–0.05% figure. Run 2 sustained **10.1k events/s for 10 minutes**
— 2.5× run 1's rate — at **0.487% of one core**, still comfortably under the 1.0%
budget, with **zero dropped and zero ETW-lost events** (6,094,835 consumed, all
drained). Working set held **flat at ~9–12 MB** the whole run (per the periodic
samples), so consumption does not grow unbounded with volume.

¹ Run 1 reported a transient 51 MB working-set reading at teardown; the 10-minute
run's periodic sampling shows the steady-state working set is **~10 MB**, which is
the reliable figure. Embedded in the already-running steward the marginal cost is
smaller still.

## Part 5 — Sustained ≥10-minute stability — PROVEN

**Run 2 (600 s window, all 5 providers, launched detached in the steward SYSTEM
context):**

| Metric | Value |
|--------|-------|
| Duration | **600.0 s** |
| Events consumed (`total_seen` == `total_drained`) | **6,094,835** |
| Ring-full drops | **0** |
| ETW kernel lost events / buffers lost | **0 / 0** |
| Sustained throughput | **≈10,158 events/s** |
| CPU | **0.487 %** of one core (within budget) |
| Working set | **~9–12 MB, flat** across all 20 periodic samples |
| Distinct PIDs attributed | **1,010** |
| Runtime crash | **none** (`crashed: false`) |

The 20 in-run working-set samples (one per 30 s) range **9.3–12.0 MB with no
upward trend** — memory is bounded and actually settles *lower* in the back half
as caches stabilise. Over 6 million events in 10 minutes were consumed with **zero
loss** and **no crash**. Sustained stability under real high-rate load is proven.

## Part 6 — Session-0 UX-signal reachability — BLOCKED (needs a per-session path)

Win32k (app-hang / UI-responsiveness) was enabled in every run and emitted
**0 events** (`per_provider` Win32k = 0), confirming #2540: the steward runs as a
`LocalSystem` service in **session 0**, and the Win32k/DWM UI-responsiveness and
app-hang signals are **desktop-session** signals that do not emit in a service
session, regardless of privilege or of the (now-working) consumer. This is a
Windows platform fact: the consumer is not the limitation — the events are not
produced in session 0.

**Determination:** the "employee experience" half of DEX (app-hang, UI
responsiveness) **cannot be sourced from the steward's own service session** via
either raw ETW or Event Log. It requires a **per-session component** (a per-user
session agent, or a session-attached helper) — a distinct acquisition path from
the in-steward collector this spike validates. Machine-health signals (disk,
faults, file, DNS, WMI SMART/thermal) have no such limitation.

## Cross-cutting — behavioral-envelope fit

The chosen architecture fits the steward threat model (CLAUDE.md): the consumer is
a declared ETW real-time session over in-box providers, no obfuscation, no
in-memory tricks, no runtime code composition. The C callback is ordinary compiled
code in the (signed) binary. A production consumer would compile this same
C-callback path into the signed steward or a signed module binary — no
out-of-process helper is required (candidate (c) avoids the second-binary +
signing surface that (b) would add). cgo is a **build-time** consideration
(CGO_ENABLED=1 for the DEX build target); the PoC keeps it fully isolated behind
the `dexconsume` tag so the current CGO_ENABLED=0 steward build is unaffected.

## Recommended consume architecture

1. **In-process, non-reentrant C callback → C ring → Go drain** (candidate (c)).
   Proven stable and cheap. This is the load-bearing recommendation.
2. **Decode selectively, off the hot path.** TDH per-event is expensive; the hot
   callback should stay header-only (+ raw payload copy where a signal needs it),
   and decode only the specific events a configured signal consumes.
3. **Attribute on the drain side** (PID → image/user), cached per PID.
4. **Machine-health signals** (disk/fault/file/DNS/SMART/thermal) → this in-steward
   collector. **UX signals** (app-hang/UI-responsiveness) → a separate per-session
   component (Part 6); do not block the machine-health track on it.

## Reproduction

```bash
# Build the throwaway consumer binary (Windows, cgo):
CGO_ENABLED=1 go test -c -tags dexconsume -o dex-consume.test.exe ./features/steward/dex/

# Run it in the steward SYSTEM context (holds StartTrace). Short window inline:
cfg steward exec <steward-id> --shell pwsh --timeout 90s --command \
  "$env:DEX_CONSUME_SEC='12'; Start-Process -FilePath 'C:\path\dex-consume.test.exe' \
   -ArgumentList '-test.run','TestDexConsumeLive' -RedirectStandardOutput 'C:\path\out.txt' \
   -Wait -NoNewWindow"
# then read out.txt (JSON between <<<DEX_CONSUME_JSON>>> markers)

# Long (10-min) window: launch DETACHED (no -Wait), read the file back after ~10 min
# (the inline-exec job has a ~15-30s runtime cap; the detached child runs as SYSTEM).
```

Non-elevated the binary reports `StartTraceW: Access is denied. (code 5)` and
consumes nothing (privilege-skip path) — it still builds and runs anywhere.
