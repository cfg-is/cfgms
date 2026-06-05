# ADR-006: Module Packaging and Distribution

**Status:** Accepted  
**Date:** 2026-06-05  
**Issue:** #1879  
**Epic:** #1877 — Module packaging and distribution — controller-cached out-of-process modules

---

## Context

CFGMS modules today are compiled directly into the steward binary. This approach has two structural problems:

1. **Distribution lock-in**: A module cannot be updated without rebuilding and redeploying the entire steward binary. MSPs managing 50k+ endpoints cannot hot-swap individual capabilities without a full agent upgrade.

2. **No trust boundary**: All modules share the same process space and the same signing identity. There is no mechanism to distinguish CFGMS-authored modules from third-party modules, and no way to apply different trust policies to each.

These problems compound at fleet scale: an operator who wants to run a third-party module alongside CFGMS-authored modules has no way to express differentiated trust between them.

### What compiled-in modules cannot provide

| Capability | Compiled-in | Out-of-process |
|---|---|---|
| Independent distribution | No — full redeploy required | Yes — bundle per module |
| Publisher-level trust differentiation | No — single signing identity | Yes — per-publisher keys |
| Behavioral isolation | No — shared process | Yes — separate process, scoped OS grants |
| Version-pinned fleet deployment | No | Yes — content-addressed bundles |
| Capability update without binary redeploy | No | Yes — new bundle, no agent rebuild |

### Four execution paths on a steward

A steward receives work through four distinct paths:

1. **Module execution** — a signed, content-addressed bundle spawned as a child process; communicates back via gRPC. *(This ADR governs this path.)*
2. **Script execution** — operator-authored scripts (shell, PowerShell) staged to disk and executed via OS process. *(Separate epic.)*
3. **Inline cfg CLI** — an operator runs `cfg exec` interactively. *(Separate epic.)*
4. **Remote shell** — controller proxies a constrained interactive shell session to an authorized operator. *(Separate epic.)*

Paths 3 and 4 are named here for completeness. Their execution models will be governed by separate epics. This ADR defines only path 1 (modules) and the signing and trust model that paths 2–4 will reference where applicable.

---

## Decision

### Out-of-process gRPC binaries

Modules are distributed as **signed bundles** containing a self-contained executable. On activation the steward spawns the binary as a child process; the module communicates back over a local Unix socket or named pipe using the CFGMS module gRPC API. The steward process manages the module lifecycle (start, health-check, stop).

Rationale for out-of-process over a plugin ABI (shared library or embedded scripting VM):

- No shared memory: a module crash cannot corrupt steward state.
- No language-version coupling: a module binary links against its own runtime.
- The gRPC contract is stable and versioned; the module's internal implementation is opaque to the steward.
- Behavioral observation by the OS (process accounting, syscall auditing) is straightforward.

The controller is the **single cache point** for module bundles in a fleet. Stewards fetch bundles from the controller; they do not pull directly from an external registry.

### Three module kinds

Every module commits to exactly one kind via the `executors:` field in `module.yaml`. The kinds are mutually exclusive.

| Kind | Where it runs | What it manages |
|---|---|---|
| `steward` | Steward host | Local resources on the device the steward runs on (files, packages, firewall, services) |
| `outpost` | Steward host | Remote LAN devices — the steward acts as a proxy agent for devices that cannot run a steward |
| `workflow` | Controller | Cloud and SaaS APIs; runs on the controller node against external services |

The `executors:` field is a **single-element list** in v1. The list type is chosen for forward compatibility; future versions may permit cross-kind composition, but no commitment is made here.

```yaml
# module.yaml — example kind declaration
executors:
  - steward
```

### Bundle content addressing

A bundle is uniquely identified by the four-tuple:

```
(publisher, name, version, content_hash)
```

- `publisher` — the identity whose signing key is in the bundle's signature block
- `name` — the module's logical name within a publisher's namespace
- `version` — semantic version string
- `content_hash` — SHA-256 digest of the canonical bundle archive (including manifest)

The controller uses this tuple as its cache key. A bundle cached under a given tuple is immutable: a new `content_hash` means a new bundle, even if publisher, name, and version are unchanged. This prevents silent mutation — an update always produces a new content-addressed object.

### Publisher identity

Publisher public keys are **baked into the steward binary at build time**. They are not configurable via `cfg push` or any runtime configuration path.

This is an intentional security boundary: an operator who can push configuration cannot expand the set of trusted publishers. Changing the trusted publisher set requires a steward binary rebuild and a managed rollout — the same change control as any other security-sensitive modification to the agent.

Each publisher key entry includes a display name, key fingerprint, and policy scope compiled directly into the binary. The steward's verification logic walks this compiled set; there is no runtime key store.

### Trust modes

The steward supports three trust modes, configurable per-publisher or per-module in the steward's running config:

| Mode | Verification | When to use |
|---|---|---|
| `strict` | Steward verifies the bundle signature independently against its compiled key set, ignoring any controller attestation | Highest-value modules, regulated environments |
| `controller` | Steward accepts the controller's attestation that it has already verified the signature; steward does not re-verify | Default for all modules |
| `bypass` | Signature verification is skipped entirely | Development and local testing only; must not appear in production deployments |

`bypass` mode is accepted only when the steward is running with the development flag set. A production steward that receives a `bypass` trust mode instruction logs a warning and falls back to `controller` mode.

### Approval workflow shape

When the controller receives a bundle request (from a steward or a fleet deployment job), it evaluates the bundle's `(publisher, name, version, content_hash)` tuple against its approval state:

- **Trusted** — publisher is in the approved-publisher list and the specific bundle version is explicitly approved: forward to the requesting steward immediately.
- **Unknown** — publisher is not approved, or the specific version has not been approved: place in the approval queue and notify the fleet operator.
- **Revoked** — publisher or version is on the revocation list: reject, log the event, do not forward.

Approval state lives at the controller. Stewards do not maintain their own approval queue. A steward that receives a bundle from the controller can trust that the controller-side approval check has already passed (for `controller` mode) or re-verify the signature independently (for `strict` mode).

### Stdlib governance

The CFGMS standard library modules follow **the same module contract** as third-party modules: same `module.yaml` structure, same bundle format, same signing requirement. The only distinction is that stdlib modules are the **installer payload** — they are distributed with CFGMS itself, and their publisher keys are the CFGMS build keys already compiled into the steward binary.

There is no internal module API or privileged trust level available only to stdlib modules. This ensures the stdlib contract is continuously exercised by the same mechanisms that protect third-party modules and keeps the privileged-code surface area minimal.

### End-to-end signing

Signatures are **forwarded intact by the controller**. The controller does not strip the publisher's signature and re-sign with its own identity.

Consequences of this design:

- In `strict` mode, the steward can verify the publisher's signature without relying on the controller's integrity.
- The controller cannot forge or alter a bundle's provenance; its role is attestation and caching, not re-signing.
- If a bundle is modified in transit, the steward's verification step detects the tampering because the content hash in the manifest will not match the archive.

### Behavioral envelope

Every module declares its behavioral envelope in `module.yaml` as part of the signed bundle:

```yaml
# module.yaml — behavioral envelope fields
permissions:
  filesystem:
    read:  ["/etc/hosts", "/var/log/cfgms/"]
    write: ["/etc/cfgms/"]
  network:
    outbound: ["10.0.0.0/8"]
  processes:
    spawn: false
```

The envelope is **part of the signed bundle** — it cannot be changed without invalidating the signature. The steward enforces the envelope where the OS supports process-level observation (Linux namespaces, Windows Job Objects, macOS sandbox). On platforms where enforcement is not available, the envelope is recorded and logged but not enforced at runtime. CI lint gates on declared permissions at bundle publish time on all supported platforms.

### Banned execution patterns

The following patterns are banned from module and script payloads. CI lint rejects bundles that contain them:

| Pattern | Reason |
|---|---|
| `iex` | PowerShell Invoke-Expression — executes arbitrary strings |
| `-Command "<string>"` | PowerShell inline string execution |
| `eval` | Shell eval — executes arbitrary strings |
| `-c "<string>"` | Shell inline string execution |
| `-EncodedCommand` | PowerShell base64-encoded command |
| `-ExecutionPolicy Bypass` | PowerShell execution policy bypass |

Scripts must be **staged to disk** before execution. Inline string execution bypasses disk-based content addressing and behavioral envelope enforcement, and is prohibited regardless of trust mode or publisher identity.

---

## Out of Scope for v1

The following are deferred to future ADRs or epics:

- **Revocation propagation** — real-time push of revocation events from publisher to steward fleet
- **Auto-update** — automatic bundle version promotion within a semver range
- **OCI-compatible resolver** — fetching bundles from an OCI-compatible registry
- **Outpost runtime** — the process model for `outpost`-kind modules (the kind is named and reserved here; its execution environment is not yet defined)
- **Execution paths 3 and 4** — inline cfg CLI and remote shell; governed by separate epics

---

## Consequences

### Positive

1. **Independent distribution**: Modules can be updated without rebuilding or redeploying the steward binary.
2. **Publisher-level trust**: Operators can apply different trust policies to different publishers without shared-identity coupling.
3. **Process isolation**: A misbehaving module cannot corrupt steward state or access other modules' memory.
4. **Content integrity**: The four-tuple content address makes silent bundle mutation detectable.
5. **Auditable provenance**: End-to-end signatures mean the controller cannot alter what the publisher signed.
6. **Stdlib parity**: Stdlib and third-party modules share the same contract; no hidden privileges exist for first-party code.

### Negative

1. **Process startup overhead**: Spawning a child process per module activation has higher latency than a function call. Long-lived modules amortize this cost; short-lived activations do not.
2. **IPC serialization cost**: All data crossing the steward↔module boundary must be marshalled through gRPC. Large payloads (e.g. file contents) require streaming.
3. **Binary portability burden**: Module publishers must cross-compile for each supported platform and architecture and include all variants in the bundle.
4. **Build-time key management**: Adding a new trusted publisher requires a steward binary rebuild and a managed fleet rollout; there is no runtime escape hatch.

### Neutral

- The `executors:` field as a single-element list adds no observable overhead. The list type is a forward-compatibility marker only.
- Behavioral envelope enforcement degrades gracefully on platforms that lack process-level observation primitives. This is a platform constraint rather than an architectural gap.

---

## Alternatives Considered

### Shared library (plugin ABI)

Load modules as shared libraries into the steward process at runtime.

**Rejected:** A crash or memory safety violation in the module takes down the steward. Language and compiler version coupling makes cross-publisher distribution impractical. OS-level behavioral observation is not possible when the module runs in the steward's process space.

### Embedded scripting runtime

Ship a scripting language runtime inside the steward and require modules to be authored in that language.

**Rejected:** Constrains the module ecosystem to one language and one runtime version. Modules that need direct OS-level access must cross a high-overhead bridge. The embedded VM becomes a shared dependency with its own vulnerability surface.

### Controller re-signs bundles

The controller verifies the publisher signature, then re-signs the bundle with its own key before forwarding to stewards.

**Rejected:** Breaks the publisher-to-steward trust chain. A steward in this model trusts the controller rather than the publisher — a compromised controller can forge any bundle. End-to-end signing preserves publisher identity all the way to the execution host.

### Runtime publisher key injection

Allow operators to inject publisher keys via `cfg push` at runtime without a steward rebuild.

**Rejected:** Expands the privilege surface of the configuration push path. An attacker with write access to configuration could add their own publisher key and subsequently push malicious bundles fleet-wide. Baking keys into the binary ensures this attack requires a binary-level compromise, not a configuration-level one.

---

## References

- Epic #1877 — Module packaging and distribution — controller-cached out-of-process modules
- Story #1879 — modules: write ADR-006 — Module Packaging and Distribution
- [ADR-001](001-central-provider-compliance-enforcement.md) — Central Provider Compliance Enforcement
- [ADR-003](003-storage-data-taxonomy.md) — Storage Data Taxonomy
- `docs/architecture/plugin-architecture.md` — CFGMS pluggable provider architecture
