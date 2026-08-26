# ADR-010: Steward-Side Provisioning Enrollment — Controller-Supplied Join Token, IP-Trust Admission, Media Cleanup

**Status:** Accepted

**Date:** 2026-06-19

**Deciders:** Founder, Architecture

**Related:** [009](009-hyperv-vm-provisioning-from-install-media.md) (VM-from-ISO provisioning; this resolves its §8 enrollment question), [001](001-central-provider-compliance-enforcement.md) (secrets provider). Issues: #1851 (epic), #2077 (the gap this closes), #1694 (IP-trust evaluator), #2050 (completion reconciler / CorrelationID).

---

## Context

The VM-from-ISO provisioning feature (ADR-009, epic #1851) is built and deployed in the maintainer's validation lab. The live E2E surfaced #2077: the answer-file render reads enrollment secrets (`hyperv/enroll/regtoken`, `…/user-password-crypted`) from the **steward's local** SecretStore — an OS-native-encrypted store for the steward's own keys, with **no operator/remote write path**. So a real provision can't render. This forced the open design question from ADR-009 §8: **where is the answer file rendered, and how is the join token handled?**

Two facts decided it:

1. **What's actually sensitive is minimal.** The only genuinely-sensitive value in either answer file is the **tenant join token**. The Debian local-account password is eliminable (the steward is the management path), and the Windows `ppkg-path-key` is a host *path*, not a secret.

2. **The operator threat model already absorbs a join token.** CFGMS's deployment posture carries the registration-token equivalent in a boot script and gates admission by **source IP** (a known tenant WAN IP auto-approves; otherwise manual approval). The whole automation posture **assumes endpoint compromise** — careful what is trusted *from* an endpoint and what secrets are exposed *to* it (CLAUDE.md threat model). Under that posture a tenant join token is a **low-value secret**: worst case it admits one device into a tenant, where nothing sensitive is trusted to or exposed to endpoints. A Hyper-V host is additionally always-on and among the least-likely-compromised hosts.

A core CFGMS principle also applies: **stewards run without the controller.** Rendering the answer file on the controller would couple *provisioning* to controller availability.

## Decision

### 1. Render the answer file steward-side

The HV steward renders the preseed/autounattend locally so it can create and install a VM without depending on the controller (autonomy). Because the only sensitive value is a low-value join token (per the threat model), the "render controller-side to protect secrets" argument does not apply.

### 2. The controller supplies the tenant join token via existing config/secret sync

The join token the steward bakes into the answer file is the **tenant's current join token**, provided by the controller through the **existing controller→steward sync** (config/secret DNA) — set once per tenant, not injected per-steward. The render reads it as a controller-provided value. This eliminates #2077's blocker (the SecretStore had no operator write path) without building a new secret-distribution mechanism: the token rides the channel the steward already syncs.

### 3. Registration admission uses the IP-trust evaluator (#1694)

A provisioned VM's steward is admitted via the existing IP-trust gate — the same source-IP admission CFGMS already uses: registration from the HV host's known tenant network auto-approves; otherwise it requires manual approval. No new admission mechanism is introduced; #1694 is the gate (#2082 verifies and wires this path).

### 4. Minimize the answer file

The answer file carries only: hostname, steward install, controller URL + CA (non-secret), the CorrelationID (non-secret), and the low-sensitivity tenant join token. Concretely:
- **Drop** the Debian `user-password-crypted` secret — randomize it or disable interactive login.
- **Reclassify** the Windows `ppkg-path-key` as plain config (it is a path, not a secret value).

### 5. Clean up seed media after enrollment

The seed VHDX (which holds the rendered answer file + token) is already detached at `finalizing`; **delete it once the host advances past finalizing / the steward has enrolled**, and add a TTL sweep for any staged ppkg/answer media. This bounds the on-disk token window.

### 6. CorrelationID-based provenance is optional future hardening, not baseline

The CorrelationID baked into the answer file plus the #2050 reconciler already correlate the registering steward to the HV steward's provisioning record. Operators who want more than the IP-trust gate can *optionally* tighten admission later — validating the registering VM against what the HV steward reported (or DNA both can read), per the founder's longer-term "realtime coordination" vision. This is layered on top; it is **not** required for the baseline and needs no rework of §1–§5.

## Consequences

**Positive**
- Matches the operator's proven source-IP-gated, assume-compromise operating posture.
- Preserves steward autonomy (provision without the controller online to *start*).
- Closes #2077 by routing the token through the existing config sync — no new secret-distribution machinery, no per-steward manual injection.
- Reuses #1694 for admission; reuses CorrelationID/#2050 as the optional provenance foundation.
- Token on-disk exposure is bounded by media cleanup.

**Negative / risks (accepted)**
- A low-value tenant join token sits briefly on the HV host's seed media. Blast radius if leaked: it admits one device into the tenant, where nothing sensitive is trusted to or exposed to endpoints (mitigated further by cleanup + the assume-compromise model + HV hosts being low-risk).
- A shared tenant token has broader validity than a per-VM token if leaked — acceptable under the model; per-VM short-lived tokens remain available as future hardening (deferred from ADR-009 §8) and compose with the §6 provenance layer.

## Alternatives considered

- **Controller-side rendering.** Rejected — couples provisioning to controller availability (violates steward autonomy), and is unnecessary once the only secret is a low-value join token.
- **Provenance-first / token-less registration.** Deferred to optional hardening (§6) — more complex than warranted; the IP-trust gate + low-value token matches the proven RMM model and is sufficient now.
- **Per-steward manual secret injection / new `cfg secret set` tooling.** Rejected — spreads secrets and adds an operator workflow; the token rides existing config sync instead.
