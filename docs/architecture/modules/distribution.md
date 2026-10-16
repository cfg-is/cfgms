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

`pkg/modules/bundle.ComputeContentHashFromDigests` is the only code that feeds the
digest; `ComputeContentHash` SHA-256s each binary and delegates to it. The hashed
stream is length-framed, so distinct inputs never produce the same bytes:

1. A fixed format tag (`cfgms-module-content-v1`).
2. For each `os-arch` entry, sorted by key: a 4-byte big-endian key length, the key,
   then the fixed-width 32-byte SHA-256 of that platform's binary.
3. An 8-byte big-endian manifest length, then the manifest YAML bytes.
4. The result is SHA-256 hashed and base64-encoded (standard encoding).

Keys must be unique and drawn from the allowlist (`windows|darwin|linux` x
`amd64|arm64`, see `bundle.ValidPlatformKey`); anything else is refused. Sorting makes
the hash independent of map order, and because the stream carries binary digests, a
holder of the digest list and manifest can verify a signature without holding every
platform's binary. Hashes from earlier formats are invalid.

A bundle signature only counts when the signature's publisher equals the publisher
named in the bundle's manifest (`trust.ErrPublisherManifestMismatch`), checked before
any key lookup.

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
2. Additional publishers: on the controller, `module_trust.publishers` in `controller.cfg`
   (name and base64 public key); on the steward, the names in `steward.cfg`
   `module_trust.additional_publishers`, resolved against key material compiled into the
   steward binary (`STEWARD_ADDITIONAL_PUBLISHER_KEYS`).

The trust store is rebuilt at each startup. The controller's set changes only by editing
`controller.cfg` and restarting; no API, CLI command or `cfg push` field changes it. See the
[operator guide](../../operations/module-publishing.md).

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

### Installer payload: signed bundle installation roots

Every stdlib module ships in the steward installer as one signed bundle installation
root — the layout `ReadInstalled` and `DiscoverInstalled` read. A root holds:

| File | Content |
|------|---------|
| `module.yaml` | the publisher's manifest, copied byte-for-byte from `features/modules/stdlib/<name>/module.yaml` (never rewritten: the content hash covers its bytes) |
| `cfgms-module-<name>[.exe]` | the module binary, at the manifest-relative path recorded in `Binaries` |
| `bundle.yaml` | the sidecar: `binaries`, `content_hash` and `signatures` |

**Installed locations.** One subdirectory per module, in the directory each installer
already used for the earlier flat binaries:

- Windows: `C:\Program Files\CFGMS\modules\<name>\`
- Linux and macOS: `/usr/local/lib/cfgms/modules/<name>/`

Bundle discovery for the steward must read exactly those paths. This is a different
registry from `features/steward/discovery`, which loads `ModuleInfo` from `module.yaml`
and searches `/opt/cfgms/modules` on Unix; that search path is unchanged and is not where
either Unix installer stages.

**Stdlib roots are single-platform.** Each installer-payload root's `Binaries` map holds
exactly one entry, `<os>-<arch>`, for the platform the installer ships to (for example
`{"linux-amd64": "cfgms-module-file"}`). `ComputeInstalledContentHash` reads every entry
in `Binaries` from disk and errors on a missing one, so a root listing all platforms would
fail `VerifyInstalledContent` on a machine that holds only its own binary.

A third-party root published to a git source (`cfg module bundle build`) is the opposite:
it carries every platform's binary, and the content hash covers the digest of each. The
controller serves, and the steward downloads and installs, only the steward's own
platform's binary; the steward verifies it against the digest list, which is enough to
recompute the signed content hash without the other platforms' binaries.

**Build-time signing.** `scripts/sign-module-bundle assemble` builds a root: it copies the
manifest, places the binary, computes `ContentHash` with `bundle.ComputeContentHash` over
the binary and manifest bytes, signs exactly `[]byte(ContentHash)` — the bytes
`trust.VerifyBundleSignature` verifies — as publisher `cfgms` (the only name
`CFGMSPublisherIdentity()` answers to), and writes the sidecar through
`bundle.WriteInstalledSidecar`. Assembly is reproducible (explicit file modes, no
timestamps, deterministic Ed25519), which `scripts/release/build-reproducible.sh`
requires because it builds every tree twice and compares them. On Windows the binary is
Authenticode-signed before assembly, because the Authenticode signature is part of the
bytes that are hashed.

- `make build-stdlib-bundles` assembles `bin/modules/<os>-<arch>/<name>/` for every
  platform in `PLATFORMS`.
- `build/windows/build-msi.ps1` and `build/darwin/build-pkg.sh` assemble their payload
  roots; the release archives carry `modules/<name>/`, which `build/linux/install.sh`
  installs.
- `scripts/check-stdlib-payload-boundary.sh` requires each of the Windows, Linux and
  macOS payload declarations to name a per-module root directory, not a flat binary.

**Seed and dev key.** The seed is the standard-base64 32-byte Ed25519 seed in
`CFGMS_PUBLISHER_SEED`; it is never written to disk or echoed. With no seed, roots are
signed with the well-known zero-seed dev key (public half
`O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`), still with a non-empty `Signatures`
list, and the tool prints the build invocation that makes them loadable. A steward built
with the default `STEWARD_PUBLISHER_KEY` carries the all-zero placeholder public key, and
`VerifyBundleSignature` refuses every bundle against it with `ErrUntrustedPublisherKey`.
The dev loop therefore needs:

```bash
make build-steward STEWARD_PUBLISHER_KEY=O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=
```

`scripts/release/build-reproducible.sh` (`make release-artifacts`) never signs with the
dev key. It aborts before assembling anything unless `CFGMS_PUBLISHER_SEED` is set, is
not the dev seed, and derives the same public key as `--publisher-key` — the key it bakes
into `cfgms-steward`.

A steward still carries its compiled-in built-ins alongside these installed bundles;
converting the built-ins to bundles is separate work under ADR-016.

---

## Controller Approval Workflow (S5)

After a bundle is fetched from a git source and placed in the cache, the controller runs it through an approval workflow before making it available for steward delivery.

### Approval State Machine

```
                         ┌──────────────────────────────┐
  Trusted publisher      │  ApprovalWorkflow.Evaluate() │
  + valid signature  ────►   QueueForReview             ├──► pending ──► approved
                         │                              │       (admin Approve())
  Unknown publisher  ────►   QueueForReview             ├──► pending
                         │                              │
  No signature, or       │                              │
  sig verify fails   ────►   Reject                     ├──► rejected
                         └──────────────────────────────┘
```

### Decision Rules

| Condition | `ApprovalDecision` | Cache status |
|-----------|--------------------|--------------|
| Bundle carries no signature | `Reject` | `rejected` |
| Publisher in trust store, signature fails | `Reject` | `rejected` |
| Publisher in trust store AND `VerifyBundleSignature` passes | `QueueForReview` | `pending` |
| Publisher NOT in trust store | `QueueForReview` | `pending` |

`Evaluate` never returns `AutoApprove`: a human approves every version, trusted publisher
or not (`AutoApprove` is only reported for a bundle a human already approved). A rejected
content address is immutable, so a trusted publisher's bad signature permanently rejects
that publisher/name/version; the publisher must publish a new version. A bundle with no
signature can never be approved.

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
configured git repository and reading the bundle installation root (`module.yaml`,
`bundle.yaml` and the binaries it names) out of the checkout. It is wired into the
running controller together with the approver and the trust store at startup
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

**Repository layout.** One repository per module at `<base>/<name>`. The repository root at
the tag **is** the bundle installation root, exactly what `cfg module bundle build --out`
produces; a multi-platform module carries every platform in that one root. The root is read
strictly: files other than the bundle files (and `.git`) are refused.

**Version pinning.** `version` must be an exact semantic version with no `v` prefix, and
the repository tag must be exactly that string. Only tags are listed and fetched;
branches, `HEAD`, commit ids and `v`-prefixed versions are refused. The tag is fetched
shallowly into a scratch directory that is removed before the call returns; the returned
bundle holds the bytes. An unresolvable tag fails the request naming the tag — there is no
fallback to a branch. Resolved bundles are rejected when the manifest's publisher, name or
version differ from the request or when a signature names a different publisher than the
manifest.

**Transport.** A source base must be an absolute `https://` or `ssh://` URL with a host,
no credentials, no query and no fragment (`ValidateBase`, also applied to `module_sources`
at controller startup). Every git subprocess runs with an explicit environment: only the
`https` and `ssh` protocols, no prompts, no system or user git config, hooks disabled, no
submodules, certificate verification on, and ssh in batch mode with host-key checking.
`GIT_SSL_CAINFO` and `GIT_SSH_COMMAND` in the controller's environment pass through.

**Trust anchor.** The publisher signature, not the tag and not the transport, is the trust
anchor. The content hash is recomputed from the fetched bytes, and every binary is
verified against its digest, so a moved tag produces different bytes and a different hash.

**Required modules gate.** `ResolveCfgRequiredModules` runs on every `cfg push` that
declares `required_modules:`. Each version must be exact (`bundle.IsExactSemver`); anything
else is refused with `ErrVersionNotExact` before any source is contacted. A cached,
approved bundle passes; a cached pending or rejected bundle blocks the push; an uncached
bundle is resolved, evaluated and stored, and blocks the push until a human approves it.

### Steward Pull

A steward whose applied configuration declares `required_modules:` compares each entry
with its installed bundles. A module not installed at exactly that publisher, name and
version is fetched with the `FetchModuleBundle` RPC over the steward's mTLS connection,
for the steward's own platform only, verified under `module_trust.mode`, and installed by
`features/steward/modules/install`. Stdlib names are never fetched. The controller serves
the RPC only when the steward's own effective configuration requires that exact
publisher/name/version and the bundle is approved; every refusal returns the same
`NotFound` response and the reason is logged on the controller. Install verification
order, the replace procedure and the sentinel errors are documented in the `install`
package.

Operators: see the [module publishing guide](../../operations/module-publishing.md) for
the end-to-end procedure and troubleshooting.

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

Trust mode (`steward.cfg` `module_trust.mode`):

- `controller` (default) trusts the controller's approval.
- `strict` verifies publisher signatures on the steward against the compiled-in CFGMS key
  and the `additional_publishers` keys compiled in through `STEWARD_ADDITIONAL_PUBLISHER_KEYS`.
  It is the control that holds if the controller or an admin account is compromised.
- `bypass` disables enforcement and is for development only.

The content hash is recomputed in every mode.
