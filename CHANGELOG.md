# Changelog

All notable changes to CFGMS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.5] - 2026-10-02

Stable snapshot promoted to `main`, covering the v0.10.0–v0.10.5 roadmap milestones. Bundles the
controller-served web console, passkey-first operator identity with step-up and operator-signed
endpoint payloads, the clustered controller (shared Postgres, lease-backed authority, any-node
service), the DNA fragment model and Entity Graph, the stdlib module set, Hyper-V failover-cluster
management, and a fleet-wide tenant-containment hardening pass. See
[`docs/product/roadmap.md`](docs/product/roadmap.md) for the full narrative.

### Added

- **Web console foundation** — React + TypeScript + Vite SPA in `web/` (Issue #2488) served by
  the controller from its single TLS endpoint with a strict CSP (Issue #2494); authenticated app
  shell with tenant switcher, search and alerts (PR #2678), client router and steward asset page
  (PR #2740), and the fleet overview table with live filter, sort, DNA columns, saved views and
  an asset-DNA drawer (Issues #2497, #2498) (Epic #2344).
- **Web management & visibility** — fleet-wide search with the `cfg` selector grammar
  (Issue #2726), audit log browse/filter (Issue #2727), fleet health aggregate tiles
  (Issue #2729), configuration management (Issue #2730), workflow management (Issue #2731),
  module review queue (Issue #2732), and account/role administration (Issue #2733) (Epic #2713).
- **Web enrollment & fleet operations** — registration console with token lifecycle, IP-trust,
  and approve / approve-all / approve-by-CIDR with dry-run preview (Issues #2935, #2936, #2969,
  #2970, #2971); refresh-request queue (Issues #2941, #2973); installer artifacts and deploy
  hand-off page (Issue #2937); row actions, bulk selection, bulk tag edit, move-tenant and
  decommission (Issues #2938, #2939, #2972); Logs and Modules asset tabs (Issue #2940); session
  probe on mount (Issue #2933) (Epic #2857).
- **Web tenant & access administration** — tenant list/update REST and tenant tree view
  (Issues #3125, #3131); account get/update with edit, password reset and enable/disable
  (Issues #3126, #3132); role create/edit/delete and subject↔role binding REST + UI
  (Issues #3128, #3133, #3134); certificate get/revoke REST and lifecycle view (Issues #3129,
  #3135); tenant deletion pipeline with dual-control approval (Issue #3182) and suspend/restore
  cascade with provenance tracking (Issue #3158) (Epic #2858).
- **Web operator completeness** — create config for an unconfigured steward (Issue #2980),
  structured diff in rollback preview (Issue #2981), per-steward push results (Issue #2982),
  Config/Tenant ID pickers (Issue #2983), structured workflow step authoring and variable inputs
  (Issues #2984, #2985), read-only workflow flowchart and browse drawer (Issues #3037, #3039),
  trigger schedule/webhook configuration (PR #3011), and a scripts/runs/jobs surface with a
  confirm-before-run gate backed by new `GET /runs` and `GET /jobs` (Issues #2987, #2988)
  (Epic #2859).
- **Web visibility surfaces** — `/reports` dashboard with KPI tiles, trend chart and template
  generation (Issues #3270, #3271); fleet-wide and per-steward compliance views (Issues #3272,
  #3273) derived from a real drift signal (Issues #3264, #3265); monitoring health and anomalies
  view (Issue #3274); alert center with acknowledge/silence (Issues #3266, #3267, #3275); chart
  and stat-tile design conventions (Issues #3268, #3269) (Epic #2860).
- **Live operations: remote shell and task manager** — steward Terminal RPC dial-out PTY bridge
  (Issue #2760), controller WebSocket route with relay session brokering (Issue #2761) and an
  asset-page Shell tab (Issue #2762); cross-platform process/service snapshot collector, telemetry
  subscribe/stream RPC, web fan-out and Task Manager tab (Issues #2763, #2764, #2765, #2766)
  (Epic #2738).
- **Troubleshooting cockpit** — case store and case CRUD/pin REST with tenant-subtree filtering
  (Issues #3602, #3605, #3606), intake device-claim resolution (Issue #3604), `/cases` route,
  index and cockpit shell (Issues #3608, #3614), and an evidence canvas with drift-diff,
  blast-radius, change-timeline and remediation cards (Issues #3607, #3609–#3612) fed live by a
  Watch-cursor WebSocket fan-out (Issue #3613) (Epic #2854).
- **Passkey web authentication** — web session core with HttpOnly SameSite cookies and
  double-submit CSRF (Issues #2492, #2493, ADR-018); WebAuthn passkey registration establishing
  `AssuranceStrong` (Issue #2782); first-passkey enrollment via single-use magic link
  (Issues #2966, #2968); self-service passkey management with an anti-lockout guard
  (Issue #2992); passkey bootstrap and recovery through the mTLS admin certificate (Issue #2783).
- **Identity assurance and step-up** — graduated assurance levels with a per-permission registry
  replacing the `IsAdmin` bit (Issues #2780, #2781, #2787), step-up challenge with user-presence
  enforcement (Issue #2784), silent WebAuthn session continuity with IP-change downgrade
  (Issue #2788), `cfg` step-up client (PR #2843), web step-up modal and `Manager.Elevate`
  (Issues #2786, #2965, #2967), and per-tenant assurance policy (Issues #2839, #2845)
  (Epics #2737, #2931, ADR-021).
- **Unified administrator identity** — one account per operator across passkey and mTLS: admin
  certificates bound to accounts by serial (Issues #3578, #3580), CLI session scope resolved from
  the bound account (Issue #3576), atomic resumable certificate rotation (Issue #3579),
  offboarding cascade revoking certificates and sessions (Issues #3575, #3581), and `cfg` account
  lifecycle verbs (Issue #3582) (Epic #3178).
- **Zero-standing-privilege `cfg` sessions** — auth-tier middleware with mTLS-only Tier 3
  (Issues #2222, #2224, #2225, #2226), controller session-token issuance/revocation
  (Issue #2232), OS-keychain token storage (Issue #2233), encrypted-at-rest admin credential
  (Issue #2231), `cfg connect`/`disconnect` with rolling renewal (Issue #2248), connection
  registry (Issue #2217), and install-to-PATH targets (Issue #2216) (Epics #2213, #1419, ADR-014).
- **Browser-authenticated CLI enrolment** — enrolment tokens and a pending credential-request
  queue (Issue #3717), approval with marker authority (Issue #3718), headless enrolment
  (Issue #3720), single-use collection (PR #3738), unattended renewal (Issue #3724), revocation
  and containment (Issue #3725), `cfg` browser login via controller rendezvous (PR #3744), and
  web confirmation and approval screens (Issues #3722, #3723) (Epic #3711).
- **Operator-signed endpoint payloads** — canonical signed envelope binding target, nonce and
  expiry (Issues #3690, #3694), CSR-based zero-custody signing credentials (Issues #3692, #3693,
  #3696), WebAuthn payload signing (PR #3734) verified by the steward (Issue #3697), signed
  operator-certificate revocation manifest consumed and delivered to stewards (Issues #3691,
  #3699, #4400), blast-radius bound with audit trail (Issue #3698), and a CLI presence relay for
  user-presence commands (Issue #4287) (Epic #3571).
- **Clustered controller** — complete Postgres provider and shared DNA/fleet state
  (Issues #2117, #2118), cluster-mode storage selection and second-node bootstrap (Issue #2119),
  shared CA trust anchor from OpenBao (Issue #2018), durable shared session store
  (Issues #2736, #2775), cluster-mode startup gates (Issues #2272, #2286), and node membership,
  drain and decommission with CLI (Issues #2278, #2288, PR #2284) (Epics #2051, #2735).
- **Any-to-any provider migration** — `cfg migrate` engine (Issue #2258) covering
  flatfile/SQLite ↔ Postgres (Issue #2265), file ↔ OpenBao secrets including the CA key
  (Issue #2270), local ↔ S3 installer blobs (PR #2285), and a generalized
  `cfg storage migrate` with dry-run reports (Issue #2321) (Epic #2256).
- **Lease-backed leadership authority** — `HasLeadership()` on a monotonic-clock leader lease
  (PR #3448, ADR-029), commands stamped with a fencing term (Issue #3390) and fenced on the
  steward with a persisted ratchet (Issues #3436, #3437), and authority gating on certificate,
  drain, bundle-approval, rollout, installer and decommission endpoints (Issues #3538–#3544)
  (Epics #3386, #3411).
- **Cluster service model** — fenced database lease primitive backing leadership
  (Issues #3756, #3760), lease-claimed singleton scheduling (Issue #3762), transactional delivery
  rows (Issue #3757), shared steward-routing table with controller-to-controller delivery
  (Issue #3764), a node registry (Issue #3763), durable nonce store (Issue #3755), one database
  pool per node (Issue #3758), per-tenant admission control (Issue #3759), and cluster-visible
  revocation and abuse counters (PRs #3860, #3899) (Epic #3751, ADR-031).
- **SaaS topology foundations** — realm-qualified tenant IDs (Issue #3782), path-length-aware CA
  init with subordinate-CA signing (Issue #3777), and CSR-based registration and
  registration-refresh signing (Issues #3780, #3781) (Epic #3752, ADR-032).
- **Cluster fleet durability and store completeness** — durable enrollment state (Issue #3403),
  fleet list and inventory served from the shared store (Issues #3480, #3494, #3495),
  collision-free steward IDs (Issue #3526); subsystems declare required stores and composition
  fails closed, with absent optional capabilities surfaced in health (Issues #3407, #3408, #3409)
  (Epics #3400, #3406).
- **Audit sink architecture** — configurable audit sink selection (Issue #4036), `AuditStore`
  required and fail-closed (Issue #4035), and a forward-only WORM shipper with Object Lock probe
  and buffer-and-flush on outage (Issues #4037, #4039) (Epic #4033, ADR-033).
- **Steward module foundation** — `features/modules/` split into `stdlib/` and `extended/`
  (Issue #2469), canonical-fragment contract with `owns:` declaration (Issue #2471), stdlib
  completeness gate (Issue #2473), and new stdlib modules `user`, `cert_trust`, `time` and
  `hostname` (Issues #2474, #2475, #2476, #2460) plus the `patch` Windows backend (Issue #2472)
  (Epic #2460, ADR-016).
- **Module runtime and trust** — installed bundle modules run through the module runtime and are
  verified on read-back (Issues #4410, #4425), unified Windows module transport (Issue #4393),
  git source resolver pinned to the requested ref (Issue #4409), `additional_publishers`
  resolved in strict mode (Issue #4398), `script_signing.policy` as a fleet-wide floor
  (Issue #4399), and all three `module_trust` modes proven on the load path (Issue #4426).
- **New and extended modules** — `github_runner` (Issues #2188, #2427), local `activedirectory`
  extended module registered (Issue #4445), Microsoft Entra ID `entra_user` and `entra_group`
  with tenant-partitioned execution credentials (Issues #4325, #4420), and the `package` module's
  declarative provider allowlist with SYSTEM-context installs (PR #2821).
- **Capability-driven observation** — `observe_when` manifest field and resolution against
  baseline DNA (Issues #3101, #3103), a Tier-2 whole-domain observe sweep (Issue #3104), and an
  observe read-only conformance helper (Issue #3102) (Epic #2890, ADR-024).
- **osquery integration** — safe query invocation (Issue #3562), `always_pull` activation
  (Issue #3563), curated `host:*` facts (Issues #3564, #3565, #3568), and ad-hoc fleet queries
  via catalog RPC and gated REST dispatch (Issues #3566, #3569) (Epic #2855).
- **Module Monitor and event stream** — event-driven Monitor wired into the convergence loop
  (Issues #2112, #2113, #2435), pluggable EventBus with correlation IDs (Issue #2139),
  convergence outcome events, per-call module timeouts and streamed script output
  (Issues #2141, #2142, #2143), and `GET /stewards/{id}/logs` (Issue #2144) (Epics #2110, #2135,
  ADR-012).
- **Reboot windows** — `reboot_window` schema, tenant cascade and timezone resolution
  (Issues #2975, #2976), steward-side reboot Gate with a deferred outcome (Issues #2977, #4411),
  fail-closed patch Gate (Issue #2978), and authoring endpoints and CLI (Issue #2979)
  (Epic #2898, ADR-026).
- **Registration refresh** — device identity key and refresh handshake so stewards offline past
  certificate expiry can recover (Issues #2093, #2094, #2095, #2096), with admin CLI and refresh
  policy (Issue #2097) (Epic #1845, ADR-011).
- **Steward install and version management** — launcher-managed installs on Linux, macOS and
  Windows MSI (PR #2346, Issues #2379, #2380), build-time publisher key and version stamping
  (Issue #2377), canonical log directories (Issue #2378), controller-trust anchoring
  (Issue #1517, ADR-013), `desired_version` auto-converge with self-fetch (Issue #2260,
  PR #2863), deployment rings and a rollout API with ring-advance and halt (Issues #2271, #2339,
  #2340), and steward move and decommission (Issues #2341, #2408) (Epics #2257, #2376).
- **Timeout-safe long module operations** — `sync_config` apply decoupled from the command
  deadline, bounded auto-retry, and a distinct retry-exhausted status (Issues #3801, #3802,
  #3803) (Epic #3799).
- **DNA sync and history** — current-state heartbeat hashing and snapshot sync (Issues #2521,
  #2522), durable history with retention (Issues #2525, #2526), divergence-triggered full sync
  (PR #2555), data-plane DNA persistence with a write-integrity guard and required-field contract
  (Issues #2616, #2617, #2618, #2642), periodic refresh (Issue #1915), and Hyper-V host and
  virtualization attributes (Issue #1950) (Epics #2520, #1932).
- **DNA fragment model** — fragment proto, canonical serialization, two-level Merkle hash,
  assembler with authority resolver, and partial-sync protocol (Issues #2901, #2902, #2903,
  #2905, #2906), with host facts partitioned into `host:*` fragments (Issues #2910, #3332)
  (Epics #2852, #2911, ADR-017).
- **Entity Graph** — `pkg/entitygraph` contract and store with edges, claim-scoped ingest,
  drift/desired-state, temporal reads, durable Watch feed and retention (Issues #2871, #2873–#2878,
  ADR-022, ADR-023); REST read API and operator-asserted edges (Issues #2880, #3374); populated
  by DNA fragments, drift-diff and apply-outcome records, the tenant tree, a MAC/GUID correlator
  and Hyper-V topology edges (Issues #2907, #3368, #3369, #3370, #3373, #3375, #4413)
  (Epics #2851, #2853).
- **Hyper-V provisioning from install media** — VM create from ISO or cloud image with seed
  VHDX, unattended-profile model, Debian preseed and Windows autounattend profiles, existence
  gating and a completion reconciler (Issues #2043–#2048, #2050, #2080), and post-enrollment
  cleanup (Issue #2081) (Epics #1851, #2077, ADR-009, ADR-010).
- **Hyper-V failover-cluster management** — cluster resource read/write with CNO gating
  (Issues #2199, #2202), membership Monitor (Issue #2241), HA-role VMs with declarative role
  properties and cluster-access lifecycle (Issues #2240, #2314, #2319, #2330), `cluster.cfg`
  cascade with owner-gated convergence (Issues #2420–#2425, #2577), durable provisioning records
  (Issues #2371, #2447), and the `promote-hv-role` workflow and CLI (Issues #2667–#2671)
  (Epics #2198, #2306, #2418, #2576, #2657).
- **`hyperv.vm` resource** — live storage relocation (Issue #2411), checkpoint-aware comparison
  and declarative checkpoint policy (Issues #2626, #2627), in-place rename via `old_name`
  (Issue #2776), configurable `secure_boot` (Issue #3169), whole-domain observe (Issue #2891),
  and an operator write path for profile overrides (Issue #3785) (Epic #2625).
- **Fleet targeting and orchestration** — unified selector surface with hostname, `id:`,
  tenant-path and tag keys (Issues #1913, #2438–#2444), durable steward tags and `cfg steward tag`
  (Issues #2542, #2544, #2545), role-based config targeting (Issues #2543, #2546), rolling batch
  jobs with quorum awareness and rollback (Issues #2294–#2299), config broadcast with push status
  (Issue #2366), and connection/session monitoring APIs (Issues #2367, #2368) (Epics #2359,
  #2537, #2343, #415).
- **Workflow engine** — in-controller runtime for controller-kind modules (Issue #1914),
  parameterized descriptor execution (Issue #2659), GitHub App runner-token provider
  (Issue #2191), and `cfg workflow list/status/cancel` (Issue #2276).
- **Architecture decisions** — ADR-009 through ADR-033 record the work above, including
  ADR-019 third-party module inclusion and delegated publisher trust (PR #2357), ADR-020 DNA
  required-field declaration, ADR-025 tenant access boundary and ADR-027 tenant suspension and
  cascading deletion (PR #3152), and ADR-030 controller secret material at rest.

### Changed

- **Controller HA no longer uses Raft.** Leadership is a fenced database lease and membership is
  a node registry; any node serves requests and inline leadership gates were removed from the
  request path (Issues #3760, #3761, #3763, ADR-031).
- Steward registration and registration refresh use a CSR-based signing flow; the steward's
  private key no longer crosses the wire (Issues #3780, #3781).
- Tenant scope is an explicit three-state value instead of "empty string means root", with one
  canonical tenant context key (Issues #4316, #4326).
- `cfg` fleet configuration files standardize on the `.cfg` extension (Issue #2532).
- The controller refuses to start on a `0.0.0.0` bind without an external address (Issue #1901),
  includes `external_address` in its certificate SANs (Issue #2017), and no longer defaults
  `external_url` to localhost (Issue #3196).
- Smoketest-gated in-place restart is the supported controller upgrade path; the port-swap
  orchestrator is frozen as experimental (Issues #2015, #2019).
- Heartbeat staleness is measured by controller receipt time and persisted durably
  (Issues #2037, #2463); the steward `UpgradeStore` is durable SQLite (Issue #2464).
- `patch` rejects a declared `maintenance.window` at validation in favor of reboot windows
  (Issue #2892).
- Shipped container images move to Alpine 3.24 and Debian 13 trixie and drop curl
  (Issues #3842, #4236); Go toolchain 1.27.1 (Issues #3627, #3836).
- Canonical documentation rewritten to current state: product vision, regenerated config schema,
  corrected storage default, repaired links and runbooks (PRs #4201–#4217).
- Development infrastructure: CI split between pull request and merge queue with native
  Windows/macOS unit tests on the PR side (Issues #2595, #4219), blocking golangci-lint and
  log-injection gates (Issues #3442, #4086), a dead-package and no-Python architecture check
  (Issues #4317, #4303), and pipeline/agent tooling including a multi-lab security-review sweep
  (Epics #3026, #3900).

### Fixed

- RBAC `DeleteRole`/`DeleteSubject` deadlocks on the non-reentrant mutex (Issues #4322, #4351).
- Flatfile storage renames with POSIX semantics on Windows so readers are never blocked
  (Issue #4262); file logging provider no longer leaks handles after Close on Windows
  (Issue #4145); SQLite retries `SQLITE_BUSY` and normalizes DNA timestamps to UTC
  (Issues #2068, #3306, #4189).
- Postgres: session timestamps rounded to microsecond precision (Issue #3864), audit-chain head
  seeding type error (Issue #3863), NULL-safe RLS unscoped reads (Issue #3478), and tenant-scoped
  `device_id` uniqueness across providers (Issues #3506, #3508, #4350).
- Script timeouts kill the whole Windows process tree via a Job Object (Issue #2715); WMI and
  PowerShell subprocess cleanup is bounded on cancellation (Issue #3600); `time` module works in
  non-admin Windows sessions (Issue #4147); `hostname` handles a missing `wmic.exe` (PR #2707).
- Steward: on-connect 30s context no longer truncates `module.Set` (Issue #2480), Monitor
  create-retry loop is bounded (Issue #3876), failed mTLS config is fatal (Issue #1662), and
  convergence fixes for `script`, `package` (apt) and `github_runner` (Issues #2478, #2479,
  #2481).
- Control plane: refused stewards keep an escalating reconnect backoff (Issue #3481), the initial
  dial retries until the context expires (Issue #3849), and leaked QUIC goroutines are closed
  (Issue #2160).
- Controller config: `certificate.ca_path` honored (Issue #3171), REST `cert_path` resolved from
  the config file directory (Issue #3197), and root-anchored paths no longer re-anchored on
  Windows (Issue #3460).
- API routing: dead `POST /api/v1/webhooks/git-push` route restored (Issue #3263), `GET
  /api/v1/modules` registered and `cfg module approve` routed (Issue #4270), detailed
  health/metrics routes wired (Issue #4208), and config upload validation returns `400`
  (Issue #2482).
- DNA and Entity Graph: persist rejections surface as errors instead of silent acceptance
  (Issue #2641), DNA sync now writes to the Entity Graph (PR #4449), timestamp comparison across
  UTC midnight (Issue #3707), and directory DNA query filters applied (Issue #4368) with O(1)
  indexer stats (Issue #4239).
- Hyper-V: seed VHD mounts no longer leak and are dismounted after a deadline kill (Issue #3168),
  and seed-phase failures are gated and diagnosable (Issue #2467).
- osquery batch-mode semicolon requirement and `cpu_family` mapping (Issue #3570).

### Security

- **CodeQL triage and fixes** — M365 OAuth callback values are escaped against reflected XSS
  and the page is now rendered with `html/template` (Issues #4489, #4495); `DeleteSecret` no
  longer returns the key or storage path, so API-key hashes stay out of errors and logs
  (Issue #4489); controller command publisher log fields are sanitized against log injection
  (Issue #4494).
- **Maintenance lease renewal** — a transient renewal error is retried within the lease's
  latency budget instead of being treated as a lost lease, preventing duplicate maintenance runs
  across controllers (Issue #4487).
- **go-winio Close/Accept deadlock** — module pipe listeners upgraded past the upstream race
  that could hang steward module shutdown on Windows (Issue #4459).
- **Dependency CVE updates** — pyjwt 2.15.0 and urllib3 2.8.0 in the scanner image (PR #4462)
  with semgrep 1.179.0 (Issue #4491); undici 7.30.0 and brace-expansion in `web/` (PR #4463);
  grpc v1.83.2 for CVE-2026-84445 (PR #3989); `golang.org/x/net`/`x/crypto` HIGH CVEs
  (Issue #2130); nanoid 3.3.18 for CVE-2026-67213 (PR #3250).
- **Tenant containment** — registration, token, role, trust-admin, credential, identity and
  operational handlers enforce tenant containment (Issues #4334, #4335, #4336); service,
  transport, terminal, workflow executors and config paths tenant-scoped (Issues #4337, #4338,
  #4340, #4346); RLS write policies (Issue #4321); access-level fail-open and suspend race closed
  (Issue #4347); Entity Graph `owning_tenant` bound to the authenticated peer (Issue #4319).
- **Tenant-subtree scoping** of tenants, roles, certificates, accounts, stewards, compliance,
  reports, secrets, sessions and config listing (Issues #2869, #3137–#3147, #3281, #3310, #3347,
  #3429, #3438), with session scope derived from actual tenant scope (Issue #3194).
- **Fail-closed defaults** — stewards fail closed without mTLS material (Issue #4318) and enforce
  module trust and script signing against configuration downgrade (Issue #4324); controller never
  leaves a cleartext bootstrap admin credential (Issue #4342), seals credentials instead of
  passing them through `EnvironmentFile=` (Issue #3462), and fails closed on an ephemeral secret
  store (Issue #2998).
- **Input and log hygiene** — path validation, integrity verification and cache-key scoping
  (Issue #4348); path containment checked before symlink resolution (Issue #2120); LIKE
  metacharacters escaped in tenant predicates (Issues #4074, #4320); audit checksum covers every
  field with nested secret redaction (Issue #4098); sanitized logged errors (Issues #4073, #4341);
  registration token redaction (Issues #2173, #2932); passkey-management IDOR fixed
  (Issue #2992); HttpOnly on logout cookie deletion (Issue #2687); security headers on 404/405
  responses (Issue #4183).
- **Security tooling** — OWASP ZAP DAST baseline (Issue #2950), OpenSSF Scorecard (Issue #2951),
  CodeQL and Dependabot for `web/` (Issue #2949), and Go native fuzz targets for config, DNA
  transport, EIDs, certificate PEM and CIM/WMI parsing (Issues #2952, #2953) (Epic #2861).

### Removed

- **BREAKING**: Raft consensus (`go.etcd.io/raft/v3`) removed from the controller; clustered
  deployments use the database lease and node registry (Issue #3763).
- **BREAKING**: Password web login removed — web login is passkey-only (Issue #2993) — and `cfg`
  no longer authenticates with API keys (Issue #3688).
- **BREAKING**: `commonpb.DNA.attributes` and the flat `DNARecord` store removed from the DNA-sync
  wire protocol in favor of fragments (Issues #3322, #3329, #3331).
- Steward install `hyperv`/`winrm` flags (Issue #1894) and unconsumed `steward.mode` and
  `steward.logging.format` config keys (Issue #4209).
- Unreachable code deleted after capability mapping: `features/siem` (Issue #4327), RBAC JIT and
  delegation paths (Issue #4328), the orphan reports implementation (Issue #4332), the network
  Active Directory module (Issue #4447), and stale `api/proto` duplicates, the git config
  provider and the workflow transform engine (Issue #4405).
- Loopback WebAuthn ceremony relay in `cfg` (Issue #3728).

## [0.9.7] - 2026-06-15

Stable snapshot promoted to `main`. Bundles the controller in-place upgrade work (now proven
live), the steward fleet-upgrade system, installer distribution, Hyper-V host onboarding, real
DNA collectors, and architecture decisions ADR-006/007/008. See
[`docs/product/roadmap.md`](docs/product/roadmap.md) for the full narrative.

### Added

- **Controller upgrade & state externalization** — smoketest-gated in-place restart upgrade
  (real-state `/api/v1/ready` gate, keep-previous-binary rollback) and the GA host/container
  blue-green target; documented in ADR-007 (Epic #2014).
- **Steward fleet upgrade system** — `push_steward_binary` command handler (Issue #1943),
  selector-based steward upgrade dispatch API with tenant isolation (Issue #1945),
  `cfg steward upgrade/status/rollback` CLI (Issue #1947), `UpgradeStore` interface for upgrade
  state (Issue #1941), and fleet steward upgrade integration tests (Issue #1948).
- **Installer distribution** — multi-platform installer artifact upload and storage API
  (Issues #1702, #1704), `cfg installer upload`/`download-url` commands (Issue #1705),
  Linux `install.sh` with interactive fingerprint TOFU (Issue #1708), and a fleet
  install-package docker-compose harness (Issue #1709).
- **Hyper-V host onboarding** — Start-VM/Stop-VM/Set-VM lifecycle module (Issue #1842),
  `install-hyperv-host.ps1` orchestrator (Issue #1854), and onboarding runbook (Issue #1855).
- **Real DNA collectors** — Linux and Windows security collectors (Issue #1939) and network
  collectors (Issue #1946).
- **cfg CLI additions** — `cfg config diff` against live steward config (Issue #1938),
  `cfg config rollback` (Issue #1942), `cfg steward dna` with `--attribute` filter (Issue #1933),
  `cfg steward logs` + controller log-pull API (Issue #1937), `cfg steward modules` endpoint and
  command (Issue #1949), and `cfg steward exec` for single-steward ad-hoc runs (Issue #1934).
- **Control-plane protocol** — `execute_script` command (Issue #1992) and `script_completed`
  plus wire-crossing events (Issue #1997) added to the proto enums; `CommandPushStewardBinary`
  and `EventStewardUpgrade*` constants (Issue #1940).
- **Architecture decisions** — ADR-006 module packaging and distribution (Issue #1879),
  ADR-008 durable execution substrate for the workflow engine.

### Changed

- Container images add `HEALTHCHECK` and `--no-install-recommends`; CI hardened with
  `persist-credentials: false` and action SHA pinning. `.gitattributes` forces LF on shell
  scripts and Go sources.

### Removed

- **BREAKING**: The `git` storage provider has been removed (Issue #664). Existing git-backed
  deployments must migrate to the OSS composite (flatfile + SQLite) using
  `cfg storage migrate --from git --to flatfile` before upgrading. The controller now rejects
  `storage.provider: git` at startup with actionable instructions.

## [0.9.6] - 2026-05-24

Consolidation + AGPL governance release. Bundles the v0.9.0–v0.9.5 work that has shipped to `develop` since v0.8.1 (2026-01-25) but was never tagged, plus the AGPL-3.0 relicense (Epic #1716). See [`docs/product/roadmap.md`](docs/product/roadmap.md) for the full list of bundled v0.9.x epics.

### Changed

- **BREAKING (licensing)**: CFGMS is now licensed under **AGPL-3.0-only**. The previous Apache-2.0 + Elastic License v2 dual-license model has been retired (Epic #1716). Every file in the repository — controller, steward, protocol, integrations, CLI, workflow engine, and HA clustering — is now AGPL-3.0. A separate commercial-embedding license is available via cfg.is for third parties wishing to embed CFGMS in proprietary products without AGPL obligations; see [LICENSE.CommercialLicenses.md](LICENSE.CommercialLicenses.md).
- **CLA upgraded to v2.0** (Issue #1744, PR #1753). §3 / §4 broadened to "any license selected by the Copyright Holder at its sole discretion" so future license changes do not require re-papering. §5(f) adds AI-assisted contribution disclosure. §1 copyright assignment retained.
- **High Availability (HA) is now in every build.** The `commercial/` build-tag split has been removed (Issue #1745, PR #1780). `pkg/ha` is the unified package — controllers built from the public source tree include Raft consensus, failover, and split-brain protection by default.

### Added

- `LICENSE` — full GNU AGPL-3.0 text (Issue #1747).
- `LICENSE.CommercialLicenses.md` — describes the outbound commercial-embedding license offering (Issue #1747).

### Removed

- `LICENSE-APACHE-2.0` and `LICENSE-ELASTIC-2.0` (Issue #1747).
- `commercial/` directory and the `commercial` build tag (Issue #1745).
- `docs/architecture/ha-commercial-split.md` and `docs/product/feature-boundaries.md` (Issues #1748, #1750).
- `"AGPL"` from `.github/workflows/license-check.yml` forbidden-dependency-licenses list (Issue #1747) — AGPL dependencies are now compatible with the project's own AGPL-3.0 license.

### Migration notes

- **Embedding CFGMS in a proprietary product**: contact licensing@cfg.is. The public repository remains AGPL-3.0 for all users.
- **Self-hosting CFGMS for your own organization** (including as an MSP serving clients via the public network): AGPL-3.0 permits this. If you modify CFGMS and expose those modifications via the network, AGPL-3.0 §13 requires you to make corresponding source available to your users.
- **Existing forks** as of the migration date are grandfathered under their original Apache-2.0 license. Future merges from upstream after the relicense carry AGPL-3.0 terms.

### Added
- Semantic versioning policy documentation
- CHANGELOG.md for tracking version history
- Public-facing roadmap for community visibility
- Controller `--config` CLI flag for specifying custom configuration file path
- `CFGMS_CONTROLLER_CONFIG` environment variable for configuration file path
- Production-ready configuration file search paths with priority order

### Changed
- Roadmap version numbering updated for clearer progression
- **BREAKING**: Controller configuration file renamed from `config.yaml` to `controller.cfg` (Issue #290)
  - Migration: Rename your `config.yaml` to `controller.cfg` or use `--config` flag
  - New search priority: CLI flag → `CFGMS_CONTROLLER_CONFIG` env → `/etc/cfgms/controller.cfg` → `./controller.cfg`
  - All configuration files remain in YAML format despite `.cfg` extension
  - Aligns with CFGMS naming convention (steward uses `<hostname>.cfg`)

## [0.7.0] - Unreleased

### Added

#### Open Source Preparation
- **Dual Licensing**: Apache 2.0 for open source, Elastic License v2 for commercial features
- **License Headers**: SPDX headers added to all 802 source files
- **Community Documentation**: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- **User Documentation**: QUICK_START.md, DEVELOPMENT.md, ARCHITECTURE.md
- **Feature Boundaries**: Clear documentation of OSS vs Commercial features

#### Security Hardening
- Security audit with 9/9 findings remediated (100%)
- SQL identifier whitelist validation
- Regex timeout mechanism
- Admin operation audit controls
- API key persistence to durable storage
- PostgreSQL Row-Level Security (RLS) for tenant isolation
- Central Provider Compliance Enforcement System (6-layer defense)

#### Architecture Improvements
- Dual-CA bug fix for production mTLS
- SOPS storage provider configuration fix
- Cache migration to centralized `pkg/cache` (681 lines removed)
- gRPC removal - migrated to MQTT+QUIC protocol
- Renamed cfgctl to cfg for better discoverability

### Changed
- High Availability (HA) code moved to commercial tier with build tags
- Security rating improved from A- to A (0 High/Medium vulnerabilities)
- Upgraded to Go 1.25.3 for security and performance
- Updated golangci-lint to v2.x

### Removed
- gRPC dependencies and service definitions
- 18 internal documentation files before OSS launch
- 9 test binaries from repository
- 24 unfinished TODO items (6 fixed, 18 removed)

## [0.6.0] - 2025-10-21

### Added

#### Endpoint Management
- **Advanced Script Execution**: Git-versioned scripts with semantic versioning
- **DNA Parameter Injection**: Dynamic `$DNA.OS.Version` and `$CompanySettings` variables
- **Ephemeral API Keys**: Secure script-to-controller callbacks
- **Multi-Platform Scripts**: PowerShell, Bash/zsh, Python, batch/cmd support

#### Configuration Templates
- Template marketplace infrastructure with 3 example templates
- OSS template marketplace (GitHub-based, community contributions)
- Template testing framework with unit tests and scenarios
- Compliance validation via DNA + drift detection

#### Windows Patch Compliance
- Policy-driven patching with declarative configuration
- Patch type policies (Critical: 7 days, Important: 14 days)
- Major version upgrade support (Win 10->11, 23H2->24H2)
- Windows Update COM API integration (no WSUS dependency)
- Patch configs declaring maintenance.window or maintenance.schedule are rejected at validation with a clear error (reboot windows are not yet implemented)

#### Performance Monitoring
- Endpoint performance metrics (CPU, memory, disk, network)
- Top 10 CPU/memory consumers per device
- Process/service watchlist with auto-start option
- Threshold-based alerting (warning/critical levels)
- Time-series storage interface ready for InfluxDB/TimescaleDB

#### Controller Health Monitoring
- Controller metrics (MQTT broker, storage, queues, resources)
- Workflow/script queue depth monitoring
- Email alerting via SMTP
- Request tracing for troubleshooting
- Health API endpoints (simple + detailed + Prometheus)
- CLI tools: `cfg controller status`, `cfg trace <request_id>`

## [0.5.0] - 2025-09-15

### Added

#### Global Logging
- Pluggable logging provider with File and TimescaleDB backends
- RFC5424 structured logging fields
- Syslog forwarding support
- Complete component migration to structured logging

#### Advanced Workflow Engine
- Conditionals, nested workflows, loops
- Try/catch error handling
- Cron scheduling and webhooks
- SIEM integration API
- Transform functions and Go templates
- JSONPath/XPath support
- Interactive debugging (pause/resume, breakpoints)
- Workflow versioning and templates

#### Reporting Framework
- DNA and audit integration
- 8 compliance report templates
- Multi-format export (JSON/CSV/PDF/HTML/Excel)
- Report scheduling and pagination

#### Platform Capabilities
- Internal platform monitoring with anomaly detection
- Lightweight SIEM engine (10k+ events/sec)
- Production security hardening (HIPAA/SOX/PCI/GDPR)
- High availability with Raft clustering (1.3s failover)
- QA infrastructure consolidation with unified Docker testing

#### MQTT+QUIC Communication
- Complete gRPC to MQTT+QUIC migration
- NAT traversal support
- 2,738 lines of integration tests
- 60+ test scenarios with 79% coverage increase
- TLS/mTLS security validation (98/100 rating)
- Multi-tenant isolation testing

## [0.4.6.0] - 2025-08-20

### Added

#### Complete Storage Migration (Epic 6)
- RBAC storage migration to pluggable architecture
- Audit and compliance storage with retention policies
- Configuration and rollback storage migration
- Session and runtime storage migration
- Storage provider testing infrastructure
- Memory storage backend eliminated from global registry
- Shared cache utility consolidation
- SQLite DNA storage as default backend

## [0.4.5.0] - 2025-08-01

### Added

#### Core Global Storage Foundation (Epic 5B)
- Pluggable storage architecture with provider interfaces
- Enhanced Git storage provider with SOPS encryption
- Enhanced database storage provider with PostgreSQL
- Foundation storage migration maintaining backward compatibility

## [0.4.0] - 2025-07-15

### Added

#### Advanced Module System
- Module dependency management with circular detection
- Complete module lifecycle (init, startup, shutdown)
- Module versioning with semantic versioning support

#### Advanced RBAC + Zero-Trust
- Role inheritance with override capabilities
- Fine-grained permissions with resource-level controls
- Enhanced multi-tenant security with tenant isolation
- Just-In-Time (JIT) access framework
- Risk-based access controls
- Continuous authorization engine
- Zero-trust policy engine

#### M365 Foundation
- Multi-tenant consent flow implementation
- Delegated permissions OAuth2 authentication
- MSP admin consent flow with client onboarding

#### Unified Directory Management
- Directory service abstraction (AD + Entra ID)
- Directory DNA integration with drift detection
- Active Directory provider with LDAP operations
- Entra ID provider with Microsoft Graph API

## [0.3.2] - 2025-06-15

### Fixed
- Critical security vulnerabilities (CVE-2025-21613, CVE-2025-21614)
- GitHub Actions gosec installation issues
- Terminal session race conditions with mutex synchronization

### Changed
- Updated go-git from v5.12.0 to v5.13.0

## [0.3.1] - 2025-06-01

### Added
- Local security scanning (Trivy, Nancy, gosec, staticcheck)
- Unified `make security-scan` and `make test-with-security` targets
- GitHub Actions parallel security workflow (60-70% performance improvement)
- Production deployment gates blocking critical/high vulnerabilities

## [0.3.0] - 2025-05-15

### Added

#### Workflow Engine & SaaS Foundation
- Comprehensive WorkflowError with debugging
- Enhanced condition evaluation (AND/OR/NOT)
- Loop constructs (for, while, foreach)
- M365 Virtual Steward prototype
- API Module Framework with universal provider interface

#### Enterprise Configuration Management
- Git backend with SOPS encryption
- Configuration rollback with risk assessment
- Configuration templates with DNA integration
- Version comparison tools with semantic diff

#### DNA-Based Monitoring
- Enhanced DNA collection (161 attributes)
- DNA storage with content-addressable deduplication
- Drift detection engine
- Comprehensive reporting system

#### Remote Access & Integration
- Terminal core implementation
- Terminal security controls
- E2E test framework for cross-platform testing
- Production readiness validation

## [0.2.1] - 2025-04-01

### Added
- BMAD agent sprint planning implementation
- GitHub CLI automation for project board management
- Test infrastructure cleanup (98%+ success rate)

### Fixed
- Pre-existing test failures (config service, monitoring deadlocks)
- Race conditions in export manager

## [0.2.0] - 2025-03-01

### Added
- Configuration data flow implementation
- gRPC upgrade with configuration push
- DNA-based sync verification
- Configuration validation
- Basic RBAC/ABAC
- Certificate management
- Basic API endpoints
- Configuration inheritance
- Basic monitoring
- Basic multi-tenancy
- Script execution capabilities
- Workflow engine with HTTP client, webhooks, delays

## [0.1.0] - 2025-01-15

### Added
- Core architecture definition
- Component interaction design
- Security model establishment
- Initial documentation
- Module system framework
- Basic Steward functionality
- Basic Controller functionality
- Steward-Controller integration validation

---

## Version Types

- **Alpha** (0.x.x): Active development, API may change
- **Beta** (0.x.x-beta): Feature complete, testing phase
- **Stable** (1.x.x): Production ready with backward compatibility

## Links

- [Roadmap](docs/product/roadmap.md)
- [Versioning Policy](docs/development/versioning-policy.md)
- [Contributing](CONTRIBUTING.md)
