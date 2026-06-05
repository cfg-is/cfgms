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
   configuration (controller). Persistence is a S5 (controller) and S7 (steward) concern.

The trust store is rebuilt at each startup. There is no durable persistence of trust
store state in this story — that is deferred to S5 and S7.

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
```

This calls `ApprovalWorkflow.Approve(addr)`, which transitions the cache entry from `pending` to `approved`. Only `pending` entries can be approved; `approved` and `rejected` entries return an error.

To inspect pending bundles:

```
cfg module list --status pending
cfg module list --tenant root/msp-a --status pending
```

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
