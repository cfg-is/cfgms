# Module Distribution Architecture

This document is the canonical reference for the CFGMS module bundle format, content
addressing scheme, trust store shape, and signature verification flow. It is the primary
guide for S5 (controller cache) and S7 (steward trust mode enforcement) implementors.

## Overview

CFGMS modules are distributed as signed bundles. Each bundle carries:

1. A **manifest** (`ModuleMetadata`) describing the module.
2. **Binary paths** keyed by `os-arch` (e.g. `linux-amd64`, `windows-amd64`).
3. **Signatures** — one or more Ed25519 detached signatures over the bundle's content hash.
4. A **content hash** — a deterministic SHA-256 fingerprint of all binary content and
   the manifest YAML.

---

## Content Addressing

Every bundle is uniquely identified by a four-tuple:

```
(publisher, name, version, content_hash)
```

This tuple is called a `ContentAddress` and is returned by `Bundle.ContentAddress()`.

### How the content hash is computed

`pkg/modules/bundle.ComputeContentHash` produces the hash:

1. Collect `(os-arch, binary-content)` pairs from the bundle's binaries map.
2. Sort the pairs lexicographically by `os-arch` key.
3. Feed each `key || content` in sorted order into a SHA-256 digest.
4. Feed the manifest YAML bytes last.
5. Base64-encode (standard encoding) the 32-byte digest.

The sort step makes the hash independent of Go map iteration order. Two bundles with
identical binary content and manifest always produce the same hash.

---

## Bundle Format

```go
// pkg/modules/bundle.Bundle
type Bundle struct {
    Manifest    *ModuleMetadata   `yaml:"manifest"`
    Binaries    map[string]string `yaml:"binaries"`   // os-arch → file path
    Signatures  []BundleSignature `yaml:"signatures"`
    ContentHash string            `yaml:"content_hash"`
}
```

`Binaries` values are file paths relative to the bundle root directory. Actual binary
content is not embedded in the bundle struct — the controller cache resolves paths to
file content when computing or verifying hashes.

```go
// pkg/modules/bundle.BundleSignature
type BundleSignature struct {
    Publisher string `yaml:"publisher"` // must match a registered PublisherIdentity
    Algorithm string `yaml:"algorithm"` // "ed25519" for v1
    Signature []byte `yaml:"signature"` // 64-byte Ed25519 signature
}
```

---

## Signing Scheme

**Ed25519 detached signature** — the only scheme for v1 bundles.

**What is signed:** the UTF-8 encoding of `Bundle.ContentHash`.

**Why Ed25519:**
- No external CA dependency — publisher identity is a raw 32-byte public key.
- Deterministic — same message + key always produces the same signature.
- Compact — 64-byte signature, 32-byte public key.
- Fast — ~70k verifications/second on modest hardware.
- Stdlib — `crypto/ed25519` ships with every Go release; no external dependencies.

Additional verifiers (cosign, minisign) can be added in future stories without changing
the bundle format by adding new `BundleSignature` entries with different `Algorithm`
values.

---

## Publisher Identity

```go
// pkg/modules/trust.PublisherIdentity
type PublisherIdentity struct {
    Name      string // human-readable identifier, e.g. "cfgms"
    PublicKey []byte // raw 32-byte Ed25519 public key
    Algorithm string // "ed25519"
}
```

### CFGMS publisher key

`pkg/modules/trust.CFGMSPublisherIdentity()` returns the built-in CFGMS publisher
identity. The public key is stored in the package-level variable:

```go
var cfgmsPublisherPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

This is a placeholder (32 zero bytes). The real key is injected by the release pipeline:

```
go build -ldflags "-X github.com/cfgis/cfgms/pkg/modules/trust.cfgmsPublisherPublicKey=<base64>"
```

---

## Trust Store

```go
// pkg/modules/trust.TrustStore
type TrustStore interface {
    AddPublisher(PublisherIdentity) error
    GetPublisher(name string) (PublisherIdentity, bool)
    ListPublishers() []PublisherIdentity
    IsTrusted(name string, pubKey []byte) bool
}
```

The default implementation is `InMemoryTrustStore` — thread-safe, non-persistent. It is
pre-seeded at startup from:

1. `CFGMSPublisherIdentity()` — the baked-in CFGMS publisher.
2. Additional publishers declared in `steward.cfg` (steward) or controller tenant
   configuration (controller).

The trust store is rebuilt at each startup.

---

## Signature Verification Flow

`pkg/modules/trust.VerifyBundleSignature(bundle, sig, store)`:

```
1. Look up sig.Publisher in store.
   → Not found: ErrPublisherNotTrusted

2. Validate stored key length == 32 bytes.
   → Wrong length: ErrKeyMismatch

3. ed25519.Verify(storedPublicKey, []byte(bundle.ContentHash), sig.Signature)
   → Verify returns false: ErrInvalidSignature

4. Return nil (verification passed).
```

---

## Controller Cache Layout (S5 reference)

The controller caches bundles at a path derived from the content address:

```
<cache-root>/<publisher>/<name>/<version>/<content_hash>/
    manifest.yaml
    binaries/
        linux-amd64
        linux-arm64
        windows-amd64
        ...
    signatures.yaml
```

The `content_hash` path component makes each unique bundle version immutable — a new
build of the same `(publisher, name, version)` tuple is stored under a different hash
directory without overwriting the old one.

---

## Installed Bundle Layout (Steward, Issue #4425)

The controller cache layout above is not the shape a bundle takes once installed on a
steward. An installation root is a plain directory — its location on disk is chosen by
whatever staged it there, not by content address — containing exactly:

```
<installation root>/
    module.yaml     # the publisher's manifest — ModuleMetadata, byte-for-byte
    bundle.yaml      # sidecar: binaries map, signatures, content hash
    <binaries, at the paths bundle.yaml's binaries map records>
```

`module.yaml` (`pkg/modules/bundle.ManifestFileName`) holds only the manifest
(`ModuleMetadata`) — the same bytes `ComputeInstalledContentHash` hashes when
re-verifying the bundle. The rest of `Bundle` — `Binaries`, `Signatures` and
`ContentHash` — has no home in `ModuleMetadata`, so it lives in a second file,
`bundle.yaml` (`pkg/modules/bundle.BundleSidecarFileName`):

```go
// on-disk shape of bundle.yaml
type installedSidecar struct {
    Binaries    map[string]string `yaml:"binaries"`   // os-arch → file path, relative to root
    Signatures  []BundleSignature `yaml:"signatures,omitempty"`
    ContentHash string            `yaml:"content_hash"`
}
```

The sidecar is a separate file rather than extra keys appended to `module.yaml`
because `module.yaml` is the publisher's own manifest and is covered by the
publisher's signature: `ComputeInstalledContentHash` hashes the manifest bytes
directly, so rewriting `module.yaml` at install time to append these fields would
change those bytes and invalidate every signature over the bundle. `bundle.yaml` is
steward-authored install metadata, never signed itself, and installing a bundle never
touches the publisher's signed manifest.

**Binaries stay root-relative on read.** `Bundle.Binaries` values are relative-path
strings by contract (see `Bundle` above); `pkg/modules/bundle.ReadInstalled(root)`
returns them exactly as recorded in the sidecar, not resolved into absolute paths. A
caller that needs to execute a binary resolves it itself via
`InstalledBinaryPath(root, ...)` — the same confinement check
`ComputeInstalledContentHash` already applies to every binary and to `module.yaml`
itself, so a `bundle.yaml` binaries entry that escapes root (e.g. `../../etc/shadow`)
is refused with `ErrBinaryPathEscapesRoot` on read exactly as it would be on write.

**Reading validates the manifest.** `ReadInstalled` parses `module.yaml` with
`features/modules.ParseModuleMetadata`, the canonical validating parser, not a bare
`yaml.Unmarshal`. The manifest is publisher-supplied untrusted input, and the parser is
what enforces the module contract on it — non-empty name, semver version, non-empty
publisher, exactly one valid `executors` value, well-formed dependency constraints and
`observe_when` predicates. It is also the only thing that populates
`ModuleMetadata.Kind`, which is `yaml:"-"` and is derived from `executors` rather than
read from YAML; since `Kind` is the ADR-006 module-kind confinement boundary (steward
vs outpost vs workflow), a bare unmarshal here would hand every consumer a bundle with
an empty `Kind`. A manifest that fails validation is refused with `ErrManifestInvalid`.
A missing `bundle.yaml`, a `bundle.yaml` that fails to parse, and a missing
`module.yaml` each fail with their own named error (`ErrSidecarMissing`,
`ErrSidecarMalformed`, `ErrManifestMissing`) rather than a partially populated Bundle.

**`ReadInstalled` is not a trust boundary.** It does call `VerifyInstalledContent`
before returning, so a bundle whose files changed independently of its sidecar is
refused with `ErrContentHashMismatch`. But the expected hash it compares against is
read from `bundle.yaml`, which is steward-authored install metadata and is **never
signed**. That makes the check a self-consistency check against an *unsigned local
anchor*: it catches a partial write or a binary replaced on its own, and it does **not**
survive an attacker with write access to the installation root, who rewrites the binary
and the sidecar's `content_hash` together. CFGMS's threat model puts that attacker in
scope — stewards run on hosts that may be compromised.

Trusting a `ReadInstalled` result therefore requires the step `ReadInstalled` cannot
perform, in this order:

1. **Publisher-signature verification** —
   `features/steward/modules/trust.StewardTrustEnforcer.VerifyForLoad`, which honours
   `steward.cfg` `module_trust.mode` and checks `Bundle.Signatures` against the trust
   store via `pkg/modules/trust.VerifyBundleSignature`. This makes the expected
   `ContentHash` a *signed* value instead of an unsigned local anchor.
2. **On-disk content re-check** — `VerifyInstalledContent`, binding the bytes currently
   on disk to that signed hash.

This is the same step-1/step-2 framing documented on
`features/modules/extended/osquery.PreExecVerifier`, which is the worked example of the
two in the correct order. `ReadInstalled` performs step 2 only; a caller that wires
installed bundles into execution owns step 1. `DiscoverInstalled` inherits the same
limit for every bundle in the map it returns.

**Discovery.** `pkg/modules/bundle.DiscoverInstalled(dir)` enumerates the immediate
subdirectories of `dir`, reads each as an installation root, and returns a
`map[string]*InstalledBundle` keyed by `Bundle.Manifest.Name` — `InstalledBundle` pairs
the reconstructed `Bundle` with the root it came from, since `Binaries` stays
root-relative. A subdirectory that fails to read is skipped, with its error collected
and returned (joined) rather than dropped, so one bad bundle does not prevent the rest
from being discovered. Two installation roots declaring the same module name are a
hard error naming both roots; the second root's bundle does not overwrite the first in
the returned map.

**Nothing produces this layout on a real steward yet.** The current Windows and macOS
installers place module binaries flat and bare into a shared `modules/` directory, with
no `module.yaml`, no `bundle.yaml`, and no per-module installation root — see the
installer gap note on Issue #4425. This section defines and implements the format that
a future installer change and a future steward-wiring story (the remainder of Issue
#4410's split) will produce and consume; this story's own writer
(`WriteInstalledSidecar`) is currently the only producer of a `bundle.yaml` that
matches it.

---

## Controller Approval Workflow (S5)

After a bundle is fetched from a git source and placed in the cache, the controller runs it through an approval workflow before making it available for steward delivery.

### Approval State Machine

```
                         ┌──────────────────────────────┐
  Trusted publisher      │  ApprovalWorkflow.Evaluate() │
  + valid signature  ────►   AutoApprove                ├──► approved
                         │                              │
  Unknown publisher  ────►   QueueForReview             ├──► pending ──► approved
                         │                              │       (admin Approve())
  Sig verify fails   ────►   Reject                     ├──► rejected
                         └──────────────────────────────┘
```

### Decision Rules

| Condition | `ApprovalDecision` | Cache status |
|-----------|--------------------|--------------|
| Publisher in trust store AND `VerifyBundleSignature` passes | `AutoApprove` | `approved` |
| Publisher NOT in trust store | `QueueForReview` | `pending` |
| Publisher in trust store, signature fails | `Reject` | `rejected` |

### `cfg module approve` CLI Usage

Operators can promote a queued bundle to approved:

```
cfg module approve cfgms/hyperv@0.2.1
cfg module approve cfgms/hyperv@0.2.1 --content-hash 9f2c4a1b
```

The CLI resolves the ref against `GET /api/v1/modules/approvals` (the pending review queue) to find the matching entry's address, then calls `POST /api/v1/modules/approvals/{address}/approve`, which transitions the cache entry from `pending` to `approved` via `ApprovalWorkflow.Approve(addr)`. Only `pending` entries can be approved; `approved` and `rejected` entries return an error, as does a ref with no matching pending entry.

`module:approve` carries `RequireUserPresence: true` (ADR-021 Decision 4): approval authorizes a signed binary to execute on every targeted endpoint, so the POST above needs a fresh `X-Presence-Token` — a proof the admin actually touched their security key for this specific approval, not just an already-authenticated session. `cfg module approve` obtains one automatically via the CLI presence relay (Issue #4287, ADR-021 Amendment 7):

1. The controller answers the first `POST .../approve` attempt with `401` and `WWW-Authenticate: CFGMS-StepUp ..., presence="required", permission="module:approve"`.
2. `cfg` lodges a presence request (`POST /api/v1/cli-presence/lodge`) bound to that exact method, path, request-body hash and permission, and prints a short confirmation code and a URL at the controller's own web UI origin (`https://<controller>/cli/presence?request_id=<id>`) — never a CLI-local address.
3. The admin opens that URL, confirms the code and the displayed action match the terminal, and completes the WebAuthn presence ceremony there. The page displays the bound permission, method, path and request-body digest — the relay accepts no caller-supplied description, so the approval shown is the approval being authorized. The controller mints the presence token bound to the same method/path/body-hash/permission the CLI lodged, and hands it to the durable request record.
4. `cfg` polls `POST /api/v1/cli-presence/{id}/collect` for the token, then retries the original `POST .../approve` with `X-Presence-Token` attached. The approval now succeeds.

Automation (API-key/`AssuranceMachine` principals) cannot lodge a presence request at all (ADR-021 Amendment 7 Decision 2) — `module:approve` stays an admin-only, presence-proven action.

Because the cache key includes the content hash, `publisher/name@version` can match several pending bundles — and since `QueueForReview` is reached before signature verification, a bundle's claimed publisher is unverified at that point. A ref matching more than one pending entry is refused with an error listing each candidate content hash; pass `--content-hash` (full value or an unambiguous prefix) to name the bundle that was reviewed. The approved content hash is echoed on success.

To inspect all cached modules (`cfg module list` calls `GET /api/v1/modules`):

```
cfg module list
cfg module list --status pending
```

### Git Source Resolver (live, Issue #4409)

`GitSourceResolver` (`features/controller/modules/sources/git`) resolves a
`publisher/name@version` reference to a `Bundle` by cloning the publisher's
configured git repository and reading `module.yaml`, `binaries/` and
`signatures/` out of the checkout. It is wired into the running controller as
the `resolver` argument of `Server.SetModuleResolution` at startup
(`features/controller/server/server.go`), constructed from controller
configuration rather than from a hard-coded source list or path.

**Configuration.** Controller config carries a `module_sources` map from
publisher name to source repository namespace:

```yaml
module_sources:
  cfgms:
    type: git
    base: https://git.example.com/cfgms
```

The clone URL for a given module is `<base>/<name>` (e.g. `.../cfgms/firewall`
for `cfgms/firewall@1.0.0`). The resolver's clone cache lives under
`<controller data root>/module-sources`, alongside the other module-subsystem
directories under the same root. When `module_sources` is empty or absent, or
when the clone root cannot be created, startup logs a warning and continues
with a nil resolver — the same nil-tolerant pattern already used for the
module cache above, never a crash.

**Version pinning.** `version` is resolved to an exact commit — via `git
ls-remote` for a tag or branch name, or via a full fetch-and-checkout for a
raw commit SHA — and that exact commit is checked out before `module.yaml` and
the binaries are read. The local clone cache directory is keyed by the
resolved commit, not only by the requested version string, so a first
resolution that happened to land on the wrong commit can never poison a later
lookup for the same version: a different resolved commit is always a different
cache entry. Resolving `pub/name@v1.0.0` and `pub/name@v2.0.0` against a
repository where those tags point at different commits fetches and returns
their respective content, not whichever commit the repository's default
branch currently happens to be on. An unresolvable ref fails the request with
an error naming the ref — there is no fallback to the default branch.

**What this does not do.** Supplying the resolver makes it reachable for the
module cache's read/approve/reject REST surface and for
`handleUpdateStewardConfig`'s required_modules resolution path, but
`ResolveCfgRequiredModules` only runs when the cache lister, resolver,
approver *and* trust store are all non-nil. The approver and trust store are
not wired at startup, so a `cfg push` declaring `required_modules:` is still
never blocked on cache/approval state — that enforcement remains a distinct,
not-yet-scheduled change.

### Implementation Reference

- `features/controller/modules/approval` — `ApprovalWorkflow`
- `features/controller/modules/cache` — `ModuleCache`
- `features/controller/modules/sources/git` — `GitSourceResolver`
- `cmd/cfg/cmd/module.go` — CLI commands

---

## Steward Trust Mode (S7 reference)

The steward enforces trust before loading a bundle:

1. Compute the content hash of the received bundle and compare to `ContentHash`.
   Mismatch → reject (content integrity).
2. For each `BundleSignature`, call `VerifyBundleSignature`. At least one signature must
   pass from a publisher in the steward's trust store.
3. If no trusted signature is found → reject with `ErrPublisherNotTrusted`.

Trust mode policy (permissive vs. strict) and per-publisher allowlists are S7 concerns.
