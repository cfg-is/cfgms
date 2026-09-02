# ADR-013: Steward Controller-Trust Anchoring and Binary Distribution

**Status:** Accepted

**Date:** 2026-06-24

**Deciders:** Founder, Architecture

**Related:** [006](006-module-packaging-and-distribution.md) (end-to-end publisher signing — this ADR applies the same principle to the steward binary and its upgrade channel), [010](010-steward-side-provisioning-enrollment.md) (enrollment), [011](011-registration-refresh.md) (registration refresh). Epic: #2051 (SaaS cluster) **depends on** this. Story: #1517 (re-scoped to the install/compile slice below).

---

## Context

Today the steward has a controller URL compiled into the signed binary. The stated security goal: an attacker cannot take the signed binary and point a steward at *their* controller — because controller substitution is an endpoint-RCE vector (the controller pushes config, modules, and scripts to the host). This is correct as an intent but conflates two separate concerns and creates two problems:

1. **It blocks clustering at scale.** A single compiled URL feels like it ties a steward to one controller. In reality, clustering is a *server-side* concern: a single hostname fronts an arbitrarily large controller cluster via DNS / load-balancer / anycast, and the steward never needs to know there are N nodes. The compiled-URL model already scales — the constraint was imagined, not real.

2. **It makes self-hosting painful.** An independent operator (e.g. an MSP running their own controller instead of the CFGMS SaaS) cannot "install and go" like Salt/Ansible. They must: boot the controller (which generates its CA), export the CA, and **stand up their own build + signing pipeline** to produce stewards pinned to that CA — before deploying the first steward.

The key realization that resolves both: **the URL was never the security; the pinned trust anchor is.** What actually stops controller substitution is **mTLS certificate validation against a pinned CA**. An attacker's controller cannot present a cert chaining to the pinned CA, so the connection fails before any config/module/script is exchanged — the URL never enters into it. The compiled URL only added defense-in-depth against config-level redirection (which CA pinning already defeats).

Two concerns were being conflated and must be separated:

- **Distribution integrity** — "is this binary genuine CFGMS software?" → solved by **code signing**. Global, always CFGMS.
- **Connection trust** — "which controller may this steward obey?" → solved by a **pinned CA**, validated via mTLS on every connection.

---

## Decision

### 1. Decouple distribution-signing from connection-trust

These are independent axes. The steward binary is **code-signed** for authenticity (a single CFGMS code-signing identity — Authenticode on Windows, notarization on macOS, sigstore/cosign for Linux/containers). Code signing proves the binary is genuine CFGMS software; it grants **no** controller trust. Connection trust is established separately, by a pinned CA. An attacker holding a genuine CFGMS-signed binary still cannot redirect a steward to their controller, because authenticity ≠ authorization.

### 2. Connection trust is a pinned CA, validated by mTLS every connection — pin the root, not the leaf

The steward validates the controller's server cert against a pinned **CA trust anchor** on every connection (mTLS-over-QUIC, `CFGMS_TRANSPORT_USE_CERT_MANAGER=true`). The address (URL) is just where to connect; safety comes from the CA pin. Apply **"pin the root, let the leaves vary"** on two axes:

- **Address:** pin a **root domain** (e.g. `*.cfg.is`), not a literal URL → a single stable hostname fronts the cluster (DNS/LB/anycast); subdomains/regions/endpoints flex underneath.
- **Trust:** pin the **CA**, not a specific controller cert → all cluster nodes present certs chaining to the pinned CA.

**Chain-aware amendment (Issue #3778, ADR-032).** For a SaaS cell, "pin the CA" means the steward pins the **shared offline root**, never the cell's currently-active regional intermediate — `pkg/cert`'s `GetCACertificate()` returns that root even when the cert manager issuing leaves is itself backed by an imported intermediate. Leaves arrive as **leaf + intermediate chains** (`issuer_chain` alongside `client_cert`/`ca_cert` in the registration and refresh responses), and the steward's TLS trust pool is built from leaf + chain + root accordingly — see the steward-operating-model's Bootstrap TLS Trust section. This is what makes routine intermediate rotation (§4) possible without re-enrollment: the pinned anchor never changes when only the intermediate does. The self-hosted single-CA pin, where there is no intermediate and no chain, is unchanged by this amendment.

### 3. Trust-source spectrum — one codebase, three enrollment postures (a build/install flag)

The steward generalizes from "baked URL + CA" to a **trust-source** that may be supplied at compile time, at install time, or learned at first contact. All three are the **same CFGMS-signed codebase**; they differ only in *where the connection-CA pin comes from*:

| Mode | CA pin source | Setup effort | Assurance / tamper-resistance |
|------|---------------|--------------|-------------------------------|
| **TOFU** | pinned on first contact (URL + token supplied at install; CA pinned-on-enroll, then immutable) | lowest — token only | medium — a **first-contact** window (mitigated by token secrecy + out-of-band delivery) |
| **Install-pinned** | CA bundle/fingerprint supplied at install (`--controller-ca`) | low — copy a fingerprint | high — no TOFU window; trusts the install process |
| **Compile-baked** | CA + root compiled into the binary, under the code signature | a build step | max — the binary self-enforces; tamper breaks the signature |

It is a single gradient: *trust first contact → trust the install → trust the build*. Recommended mapping: **SaaS = compile-baked**; **self-hosted default = install-pinned** (Salt-like *and* high-assurance, no build infra); **lab = TOFU**; **sovereign operator = compile-baked with their own re-sign** (see §5).

In every mode the pinned CA is stored **immutably and protected** (OS keychain, per the no-cleartext-secrets rule) and locked after enrollment.

### 4. Day-2 trust maintenance is uniform — a signed, root-constrained update channel

Regardless of enrollment mode, once trust is established, controller/cluster changes (new nodes, regions, failover endpoints, CA rotation) flow through one channel: the controller pushes a **signed** directive that the steward accepts only if it (a) is signed by a key chaining to the **currently-pinned CA** and (b) targets an endpoint **within the pinned root domain**. The root-domain constraint bounds even a *compromised* controller — it can re-balance stewards across its own cluster but cannot exfiltrate them to an attacker domain. Migration to an unrelated controller (different CA) is a re-enroll, not an update.

**Regional-intermediate issuance (Issue #3778) is a first-class event on this same channel, not a special case.** Because the pinned anchor is always the shared root (§2), a region rotating its active intermediate — or a cell newly issuing under a fresh regional intermediate — is just another certificate the steward's existing leaf-verification already handles: the new leaf's `issuer_chain` bridges to the same never-changing pinned root. No signed directive, no re-enrollment, and no pin update are needed for intermediate rotation specifically; that is the property this story's test suite (`pkg/cert` intermediate-rotation-survival coverage) proves directly.

### 5. Code-signing for community releases; sovereign re-sign is the multi-root boundary

CFGMS code-signs official community releases so anyone can download-and-run an authentic binary (the "install and go" path). An operator who refuses to trust *any* CFGMS-signed binary (sovereignty / air-gap) **rebuilds and re-signs with their own code-signing identity and a baked CA** — this is the deliberate **multi-root** boundary, where a separate build is correct and expected. Do not attempt to make one binary span trust roots.

### 6. The upgrade channel is end-to-end publisher-signed

The controller *distributes* steward upgrades (pulling signed artifacts from the release store, caching, and serving them — reusing the module-distribution substrate of ADR-006), but the steward **verifies the publisher signature before applying** an upgrade. A compromised controller can therefore distribute but **cannot forge** a malicious steward — only genuinely publisher-signed binaries install, and a pushed binary can only widen trust within the pinned root. This mirrors ADR-006's rule that the controller forwards signatures intact and never strips-and-re-signs.

---

## Consequences

**Positive**
- The compiled-URL security goal is delivered *more* robustly, by making CA pinning explicit and primary; the URL is free to scale behind a single hostname.
- Self-hosting becomes Salt-like **and** high-assurance via install-pinning — no per-operator build or signing pipeline for the common case.
- One codebase serves SaaS, self-hosted, lab, and sovereign deployments; the difference is a build/install flag, not a fork.
- The root-domain constraint hardens the compromised-controller case in the threat model.

**Costs / boundaries**
- TOFU carries a first-contact window; it is the lowest-assurance mode and is for labs / lowest-friction only.
- Sovereign operators accept a build+sign step (correct for a separate trust root).
- CFGMS must obtain and operate a code-signing identity for community releases (a separate operational story).

**Deferred (designed-for, not built now)**
- The signed root-constrained **update channel** (§4) — lands with the SaaS-cluster epic (#2051); a single hostname + DNS/LB does not need it to go live.
- The **code-signing pipeline** (§5) and signed official releases — separate story; compile-pinning (§3) works without it.
- The controller-side **enrollment-bundle UX** (`cfg controller ca-fingerprint` / bundle emit) for the install-pinned path — operators can fetch the CA manually in the interim.

**Immediate scope (#1517).** The re-scoped story is the **steward install + compile options** only: the trust-source abstraction (§3) with `--controller-url` + `--controller-ca` install flags and compile-time bake flags, TOFU pin-on-first-contact with protected immutable storage, and a **regression guard that today's manual-unsigned-compile + registration dev flow is unchanged** (the new abstraction defaults to current behavior when no new flags are given). #2051 depends on it. Everything in "Deferred" above is explicitly out of scope for that story.
