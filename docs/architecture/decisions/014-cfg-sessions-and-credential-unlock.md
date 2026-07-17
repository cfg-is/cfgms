# ADR-014: cfg Admin Sessions and Credential Storage (Zero Standing Privilege)

**Status:** Accepted

**Date:** 2026-06-28

**Deciders:** Founder, Architecture

**Related:** Epic #2213 (cfg install + zero-standing-privilege controller sessions). [006](006-module-packaging-and-distribution.md) and [013](013-steward-controller-trust-and-distribution.md) (admin/trust model — the admin mTLS bundle this ADR puts behind a session). Auth-tier policy epic #1419 (session principals must be consistent with its tiers). Central provider system (`pkg/secrets`) — the storage seam reused here.

---

## Context

`cfg` is a **stateless, invoke-and-exit** admin CLI (the kubectl/gh class): each subcommand independently resolves an API client and makes HTTPS calls to the **controller's REST API**, managing the controller and managing stewards **only through the controller**. It has no resident process between invocations.

Today, authentication is the admin **mTLS bundle**, auto-discovered from disk (`--bundle` flag → `CFGMS_ADMIN_BUNDLE` → `os.UserConfigDir()/cfgms/admin.bundle.yaml` → system path). This works, but it means **using `cfg` at all silently exercises the long-lived admin credential on every invocation** — the credential is standing, always-usable authority. For a tool that pushes config, modules, and scripts to endpoints through the controller, an admin credential that is silently usable for its entire lifetime is a large blast radius if the workstation, account, or controller is compromised.

The operator goals (epic #2213) are: install `cfg` on PATH; have it *remember* the controllers it knows; reconnect in a later session without re-importing the bundle or relying on out-of-band notes; and keep the active connection discoverable (including by an AI assistant working in the repo). The security goal layered on top: **zero standing privilege** — the long-lived credential is never silently usable; using a controller requires an explicit, auth-gated `cfg connect` that establishes a short-lived, controller-revocable session.

Two facts constrain the design:

1. **`cfg` is stateless.** There is no daemon to hold a session in memory across invocations. Anything that must persist between two `cfg` commands has to live on disk, in the OS-native secret store, or in the process environment.
2. **No cleartext secrets on disk** is a zero-tolerance rule (CLAUDE.md), in dev as in prod.

These two together rule out the naive answer (drop a bearer token in a file) and the tempting answer (run an agent that holds the token), and point at the OS-native secret store.

---

## Decision

### 1. Zero standing privilege via an explicit, short-lived session

There is no path by which `cfg` uses the long-lived admin credential without an explicit `cfg connect`. `connect` unlocks the credential **once** to authenticate to the controller, which mints a short-lived session token; the **session token is the only standing authorization artifact**, and it is bounded and revocable. Token renewal never re-reads the long-lived credential. `cfg disconnect` (and idle/absolute expiry) ends the session and re-locks the credential.

### 2. Controller-issued rolling session token

On a valid connect (admin mTLS), the controller mints an opaque token: **32 bytes from `crypto/rand`, base64url** (≥256-bit entropy), non-JWT for v1. Each authenticated request carries `Authorization: Bearer <token>`; each authenticated response returns a freshly-TTL'd replacement in the **`X-Session-Token`** header, so continuous use stays valid. The controller stores **`SHA-256(token)`**, never the raw token, and **never logs token values** (`logging.SanitizeLogValue`). The session store is **in-memory for v1** (controller restart ⇒ re-auth).

**Addendum (story #2736, epic #2735):** A durable `session.Store` implementation backed by SQLite (`pkg/storage/providers/sqlite.SQLiteSessionTokenStore`) is now available. When wired via `server.SetDurableSessionStore`, both the CLI session manager and the web session manager share the same store, enabling sessions to survive controller restarts with no re-authentication. Nodes in a cluster that share the same SQLite file can validate each other's sessions (cache miss → store lookup) and detect cross-node revocation (store record deleted on revoke; the next Validate on any node sees ErrSessionNotFound). The SHA-256(token) key invariant is maintained: the raw token is never written to the durable store.

### 3. Lifecycle: idle TTL + absolute cap + immediate revocation

Defaults: **idle TTL 15m**, **absolute cap 8h** (measured from the original connect — caps even a continuously-active session), **grace window 30s**. An idle gap beyond the TTL lapses the session. Revocation takes effect within **≤ 1 token TTL**. The revoke endpoint accepts **either a valid session token or an admin mTLS cert**, so a client holding an already-expired token can still clean up server-side. The grace window is **time-only** for v1 (the prior token stays valid for 30s after a renewal, tolerating concurrent/racing requests from a stateless CLI); consume-on-first-use-after-renewal is a documented future hardening.

### 4. Credential access behind a pluggable `CredentialUnlocker` seam

Credential access goes through a `CredentialUnlocker` interface (`pkg/credential`). The **default implementation is machine-bound and non-interactive** — it wraps `pkg/secrets/providers/steward`'s platform encryptor (DPAPI on Windows, machine-key AES-256-GCM on Linux/macOS) — so it requires **no passphrase prompt and no TTY**, and automation/remote sessions keep working. The unlock method is selectable **per-connection** (`ConnectionEntry.UnlockMethod`, default `"machine"`), so OS-native / hardware / passphrase unlockers slot in later as additional providers — **additively, and never as a mandatory-interactive requirement**.

### 5. Storage: no cleartext secret ever on disk, via the central `pkg/secrets` system

- **Session token (~32 bytes)** → the **OS-native secret store**, via a new `pkg/secrets/providers/oskeychain` provider: **Windows Credential Manager / macOS Keychain / Linux Secret Service**, with the kernel keyring (`keyctl`) as a headless fallback. The token is **never written to a file**. Because `cfg` is stateless, "the session goes away" is delivered by the controller's idle TTL + `cfg disconnect` (and, on the Linux keyring fallback, by the login session's lifetime) — **not** by a resident agent and not by a terminal binding.
- **Admin credential (multi-KB mTLS bundle)** → a machine-bound **encrypted file** (`os.UserConfigDir()/cfgms/credentials/<name>.enc`, dir 0700 / file 0600) via the existing `pkg/secrets/providers/steward` encryptor. It is **ciphertext, not cleartext**, so the rule holds. A file rather than the secret store because a full bundle exceeds Windows Credential Manager's small per-entry blob limit.
- **Connection metadata** (`connections.json`: name, URL, admin identity, last-used, unlock-method) → non-secret; plaintext is fine.

No bespoke crypto: all secret handling goes through `pkg/secrets`; `pkg/credential` imports no `crypto/*` directly.

### 6. CLI surface

`cfg connect [<name>] [--bundle <path>] [--url <url>]`, `cfg disconnect`, `cfg connections list`, `cfg connections current`. After connect, every `cfg` admin command works with no `--bundle`/`--url` flags in a fresh shell until the session ends. `--bundle` / `--api-url` remain supported as **one-shot, no-session overrides** (the path for CI/automation without a secret store). `cfg connect` **requires HTTPS** for the controller URL (no `http://` for non-loopback; it does not inherit the legacy `http://localhost:9080` default).

### 7. Relationship to auth-tier policy (#1419)

Session-token principals are **RBAC-equivalent to API-key principals**. This model does **not** hard-depend on the (open) auth-tier epic #1419; when #1419 lands, it gates sensitive operations requiring step-up using the session token as the base credential — additively, with no change to the session-issuance contract defined here.

---

## Alternatives Considered

- **Plaintext `session.json` at mode 0600.** Simplest persistence for a stateless CLI, justified as "short-lived and revocable." **Rejected** — a bearer token is a secret, and a cleartext token file violates the zero-tolerance no-cleartext-on-disk rule (exposed to backups, disk images, snapshots, cloud-sync, permission drift, forensic recovery).
- **Per-terminal agent / daemon holding the token in memory** (ssh-agent style, scoped to the terminal). Gives true ephemerality and nothing on disk. **Rejected** — it turns a standalone stateless utility into a client/daemon pair, which is not what `cfg` is; it is the most novel, least-proven, highest-surface option (cross-platform IPC, parent-death detection) for a marginal gain over the secret store.
- **Passphrase / PBKDF2-derived key (`CFGMS_CREDENTIAL_PASSPHRASE`) as the default unlock.** **Rejected as the default** — an env-var passphrase is exposed via `/proc/<pid>/environ` to same-user processes, and an interactive prompt breaks automation. Retained as a future *selectable* unlock method behind the same seam.
- **Storing the admin credential in the OS secret store too** (one mechanism for both). **Rejected for the credential** — a full mTLS bundle exceeds Windows Credential Manager's per-entry blob limit; the credential stays a machine-bound encrypted file. The tiny token uses the secret store.
- **Consume-on-first-use grace window** (mark the prior token spent on first presentation after renewal). Eliminates grace-window replay but needs extra per-session state. **Deferred** — v1 uses a tightly-bounded (30s) time-only window; upgrade path documented.
- **JWT / self-describing session tokens.** **Rejected for v1** — an opaque token plus a server-side store gives immediate revocation without token-introspection complexity.

---

## Consequences

**Positive**

- The long-lived admin credential is never silently usable: zero standing privilege by construction. The standing artifact is a bounded, revocable session.
- No cleartext secret on disk — the rule holds with no carve-out.
- Reuses the central `pkg/secrets` system and the existing steward encryptor; the OS-native store is a normal new provider, not a bespoke seam.
- The non-interactive machine-bound default keeps automation and remote sessions working; the `CredentialUnlocker` seam allows hardware/keychain/passphrase unlock to be added later without rework.
- `--bundle` / `--api-url` one-shot overrides preserve the existing scripted/CI path unchanged.

**Negative / costs**

- The `pkg/secrets/providers/oskeychain` provider is **net-new, security-sensitive, and per-platform** (Credential Manager / Keychain / Secret Service / keyring). Each backend is only fully testable on its OS; Windows is the priority backend and is live-validated on the Windows e2e host rather than in a Linux container — it must not merge as never-run code.
- The in-memory controller session store drops all sessions on restart. Resolved by story #2736 (see §2 addendum): `SetDurableSessionStore` wires a SQLite-backed store so sessions survive restarts and validate across nodes.
- The time-only 30s grace window is a bounded replay surface; documented, with consume-on-first-use as the upgrade.
- The machine-bound credential is non-portable between hosts — intended (per-host "remember this controller"), but it means the encrypted credential cannot be copied to another machine; re-import the bundle there.
