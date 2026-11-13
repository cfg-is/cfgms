# Operator and Service Credential Reference

Command-specific enrollment, signing-credential, renewal, revocation and account
contracts. The [operator guide](../deployment/cfg-operator-guide.md) owns the
setup/reconnect walkthrough; this reference preserves the distinct operations
previously buried in the development command catalog. Current CLI definitions
under `cmd/cfg/cmd` own flags; accepted identity/session ADRs own security decisions.

## Signing Credential Management

`cfg credential` subcommands manage payload-signing credentials — a purpose distinct
from the mTLS admin bundle covered under [Connection Management](../deployment/cfg-operator-guide.md#2-first-connect-bootstrap-bundle--one-time-only).

### cfg credential request-signing-cert (Issue #3693)

Generate an ECDSA P-256 keypair locally and request a signed payload-signing
certificate from the controller. This is the primary — and, since `CFGMS_API_KEY`
was removed (Issue #3688), the only — CLI path to a signing credential: there is no
`--api-key` alternative.

```bash
cfg credential request-signing-cert

cfg credential request-signing-cert \
  --cert-out ~/.config/cfgms/signing-cert.pem

# store under an explicit name instead of the active connection's default
cfg credential request-signing-cert --signing-credential ops-laptop
```

The private key is generated on the operator's machine and never transmitted —
only the PEM-encoded public key crosses the wire, in a `POST
/api/v1/signing-credential/request` request body that carries no other field. The
controller signs the submitted public key (never generating or seeing a private
key for it) and returns a certificate carrying the CFGMS payload-signing marker —
not the admin marker used by mTLS transport bundles, so the two credential types
remain distinguishable by construction. The certificate also names the owning account
in an account-binding extension; the `CommonName` is display-only and is never used for
authorization. The resulting keypair signs `operatorpayload.Envelope`s; it is never used
for mTLS session authentication.

**Who can sign.** Every signer traces to an account. The request is refused
(`ACCOUNT_BINDING_REQUIRED`) for a principal with no account — the bootstrap mTLS admin
or a CLI session with no bound account — and such a principal cannot sign an operator
payload. When a command is submitted, the controller requires that the certificate's
account is the account of the authenticated session (a credential issued through a CLI
session works from a web session of the same account), and that the account is enabled
and still holds `operator-payload:sign`; disabling the account or removing the grant takes
effect on the next request, not at certificate expiry. The steward independently accepts
the signature only when the controller's signed signer roster lists the certificate under
an account that holds the grant and whose tenant covers the steward. A payload-signing
certificate issued before the binding existed is refused everywhere; request a new
credential with `cfg credential request-signing-cert`.

**Per-connection credentials:** a signing credential (key plus certificate) belongs to
one controller connection, so an operator who works with more than one connection or
account keeps a separate credential for each. With a live session the key is stored
in the credential store as `signing-key.<connection>` (the connection name `cfg
connect` registered) and the certificate is written to
`<user config dir>/cfgms/signing-cert.<connection>.pem`. `--signing-credential
<name>` stores the key as `<name>` instead, with the certificate at
`signing-cert.<name>.pem` (a `<name>` of the form `signing-key.<x>` uses
`signing-cert.<x>.pem`, matching the derived form). `--cert-out` and
`CFGMS_SIGNING_CERT` override only the certificate path. The command prints the
selector to use.

**Consumers (Issue #3696):** `cfg steward run-command`, `cfg steward exec` and the
signed steward actions (`cfg steward service`, `cfg steward process`) sign the
operator envelope with this credential. The credential is resolved in this order:

1. the `--signing-credential <name>` flag, accepted by all of these commands;
2. `signing-key.<connection>` for the active session's connection;
3. with no session (for example bundle-only use), the legacy `signing-key`.

Key and certificate are loaded together and the certificate's public key must match
the private key, otherwise signing is refused — a `CFGMS_SIGNING_CERT` from another
account cannot be paired with this key. If the selected credential does not exist the
error names the selector (or the derived name) and `cfg credential
request-signing-cert`; `cfg` never falls back to a different account's key.

**Legacy `signing-key`:** a credential stored before credentials were scoped per
connection is unchanged on disk (key `signing-key`, certificate `signing-cert.pem`).
It keeps signing when no session is active, and is selected explicitly with
`--signing-credential signing-key` under a session. With a session and no selector it
is not used silently, because it may belong to a different account; the error says so.

Neither command reads the admin bundle's key for this signature: the
admin bundle (or an active
session) is still required to authenticate the API connection itself, but the
controller never holds the payload-signing private key at any point — the
zero-custody property this credential exists for is enforced end-to-end only once
these commands stop accepting an admin-bundle-signed envelope, which this story
completes. Run `cfg credential request-signing-cert` once per connection
before using these commands; a missing credential fails fast with an error naming
the command to run.

All three enforcement points on this path require the same credential type, so an
admin bundle is not a substitute at any of them: the CLI signs with the
payload-signing credential, `POST /api/v1/runs/command` rejects a submission whose
signing certificate lacks the payload-signing marker
(`validatePublicBetaCommandSignature`), and the steward re-verifies the marker
independently when the command is delivered (`verifyOperatorCert`).

The endpoint is gated by the `signing-credential:request` permission at
`AssuranceStrong` plus a fresh user-presence proof, so this command requires an
authenticated admin mTLS bundle or session (see [Connection
Management](../deployment/cfg-operator-guide.md#2-first-connect-bootstrap-bundle--one-time-only)). CLI-driven presence assertion is not
currently supported (see [Step-Up Authentication](../security/architecture.md#auth-tier-policy)),
so this command fails fast with an actionable error when the controller demands a
presence gesture — complete the presence-gated action from the controller web UI
instead.

**Where the private key is kept:** the generated key is stored encrypted at rest in
the machine-bound credential store — `<user config dir>/cfgms/credentials/signing-key.<connection>.enc` (`signing-key.enc` for the legacy name),
the same store `cfg connect` uses for the admin bundle's private key — not as a
cleartext PEM file. Mode 0600 alone is access control, not encryption at rest: it
does not protect the key from another process running as the operator, from a
backup, or from a cloud-synced config directory. Only the certificate, which
carries no secret, is written to `--cert-out`.

A cleartext export is available for development interop, but only on explicit
opt-in: `--key-out` without `--export-plaintext-key` is refused with an error
rather than silently writing an unencrypted key. With the opt-in, the encrypted
copy is still written, the export is mode 0600, and the command prints a warning
naming the exported path.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-out` | `<user config dir>/cfgms/signing-cert.<connection>.pem` (`signing-cert.pem` for the legacy `signing-key`) | Path to write the issued certificate PEM (mode 0600) |
| `--signing-credential` | `signing-key.<active connection>`; `signing-key` with no session | Name the encrypted signing key is stored under; pass the same flag to the signing commands to select it. Replaces the removed `--credential-name` |
| `--export-plaintext-key` | false | Also export the private key as a cleartext PEM (development only); required to use `--key-out` |
| `--key-out` | `<user config dir>/cfgms/<signing credential name>.pem` | Path for the cleartext key export; ignored unless `--export-plaintext-key` is passed, and an error if passed without it |
| `--url` | — | Controller REST API URL (env: `CFGMS_API_URL`). Use the controller's configured API listener address (`--listen-api-addr`, `CFGMS_HTTP_LISTEN_ADDR` or the config file; default port `9080`). Examples below write it as `https://<controller-api>`. |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |

### Credential store errors

`cfg` keeps the admin bundle and the signing key encrypted under
`<user config dir>/cfgms/credentials/<name>.enc`. Every blob starts with a format
version header. When `cfg` cannot read an entry it reports one of three errors, and the
message names the entry:

| Message | Meaning | Remedy |
|---------|---------|--------|
| `credential store entry "<name>" was written by an older cfg format and is not migrated; re-run cfg connect or cfg credential request-signing-cert` | The file has no format header, so an older `cfg` wrote it (for example before the move to user-scope DPAPI on Windows). | Re-run `cfg connect` for a connection, or `cfg credential request-signing-cert` for the signing key. |
| `credential store entry "<name>" is protected for a different user or machine; run cfg as the user who stored it, or store it again here` | The file is intact but this user and machine cannot decrypt it. On Windows, DPAPI cannot tell a different user from a different machine, so the message covers both. | Run `cfg` as the user who stored the entry, or store the entry again on this machine. |
| `credential store entry "<name>" is corrupt or unreadable; remove it and store it again` | The file is empty, truncated, altered or has an unknown format version. | Remove the `.enc` file and store the entry again. |

Older-format entries are not decrypted by a fallback and are not migrated; the entry
has to be stored again. The messages contain no key material, entropy or platform
error text. A missing entry is reported separately as a locked credential and
asks you to store it with `cfg connect` or `cfg credential enroll`.

## Enrolment Tokens and the Pending Credential-Request Queue (Issue #3717)

Story #3717 (Epic #3711 — browser-authenticated CLI enrolment) adds the first half of
zero-custody operator enrolment: an administrator mints a short-lived, single-use
enrolment token and hands it to a machine out of band (e.g. read over a phone call, or
pasted into a terminal). That machine, holding no certificate yet, spends the token to
lodge a certificate signing request carrying only a public key. The request lands in a
durable pending queue that administrators can list and deny. Story #3718 adds the
approval decision, and story #3719 adds the single-use collect call that signs the
certificate and binds it to an account. Story #3720 (below) adds the `cfg` CLI commands
that drive both halves — minting/revoking from the administrator's workstation, and the
headless machine's own enrolment. Story #3721 (below) adds the interactive
counterpart, `cfg login`: no token to hand out of band, no certificate to mint — an
operator with a browser completes a passkey login and the CLI ends with a session.
Story #3724 (below) adds a further CLI command, `cfg credential renew`, for the step
after collection: keeping an already-issued credential current without a human
present. The REST reference for every endpoint these commands call follows the CLI
sections.

### cfg credential enrolment-token mint / revoke (Issue #3720)

Run by the **administrator**, from an already-authenticated workstation (an admin mTLS
bundle or an active session — see [Connection Management](../deployment/cfg-operator-guide.md#2-first-connect-bootstrap-bundle--one-time-only)).

```bash
cfg credential enrolment-token mint --tenant-id root/msp-a/client-1
```

Mints a single-use, one-hour token and prints the raw value **exactly once** — it cannot
be retrieved again afterward, only its non-secret prefix (in a future list command, or
in audit events). Hand that value to the enrolling machine out of band, then have its
operator run `cfg credential enrol` there. Requires `enrolment-token:mint` at
`AssuranceStrong`.

```bash
cfg credential enrolment-token revoke <id>
```

Revokes an unspent token before it is used. A token that has already been spent cannot
be revoked — its one use is already consumed, and the command reports the server's `409`
as an error naming that condition. Requires `enrolment-token:revoke` at
`AssuranceStrong`.

**Flags (both subcommands):**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller REST API URL (env: `CFGMS_API_URL`) |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |

`mint` additionally requires `--tenant-id` (no default — a tenant-scoped caller may only
mint within its own subtree).

### cfg credential enrol (Issue #3720)

Run by the **operator on the headless machine** — the one with no `cfg` credential yet.

```bash
cfg credential enrol --token <token> --url https://<controller-api>
cfg credential enrol --token <token> --url https://<controller-api> --name prod
```

Generates an ECDSA P-256 keypair locally, builds a certificate signing request over the
public half, and lodges it authenticated by `--token` — the private key never leaves
this machine, and never appears in the request body (only the CSR, which carries the
public key alone). On success the command prints, together and prominently:

```
Credential request lodged (id: cr-...)
Public key fingerprint: AB12-CD34-EF56-7890
Compare this fingerprint with the administrator before they approve the request.
Approval endpoint (an administrator lists and approves pending requests here): https://<controller-api>/api/v1/credential-requests
Expires: 2026-08-28T11:00:00Z
```

**The fingerprint comparison is the actual security check** — read it to the
administrator (phone, chat, in person) before they approve. `public_key_fingerprint_short`
is a deterministic function of the public key alone, so the value the administrator sees
next to the pending request in their own tooling must match what this command printed;
approving a request whose fingerprint was never compared is a bare row click on a
credential the approver is about to mark admin-capable.

The command then polls the collect endpoint (`--poll-interval`, default 5s) until an
administrator decides, printing `Waiting for administrator approval...` between polls,
and exits with one of four distinct outcomes — the first three leave no credential file
anywhere on disk:

| Outcome | What happened | Message |
|---|---|---|
| Denied | An administrator denied the request | `credential request was denied by an administrator` |
| Expired | No decision arrived within the request's one-hour lifetime | `credential request expired before it was approved` |
| Interrupted | The operator pressed Ctrl-C while waiting | `enrolment interrupted; no credential was stored` |
| Collected | Approved, and this command already collected it (should not normally occur — see below) | `credential request was already collected` |
| **Success** | Approved and collected | `Enrolled as "<name>" (expires ...)` |

On success the command collects the signed certificate, then finishes the same way
`cfg connect --bundle` does on first import: it registers the connection in the local
registry, stores the certificate and private key through the encrypted credential store
(never cleartext), builds an mTLS client from them, exchanges the certificate for a
session via `POST /api/v1/sessions`, and stores that session token in the OS keychain.
The next ordinary `cfg` command against this controller works without any further step.

The collect secret the lodge call returns is held only in a local variable for the life
of the process — it is never written to disk and never appears in this command's output,
at any verbosity.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | — | Enrolment token minted by an administrator (env: `CFGMS_ENROLMENT_TOKEN`); required |
| `--url` | — | Controller HTTPS URL; required, and must be HTTPS for any non-loopback address (same rule as `cfg connect`) |
| `--name` | derived from URL host | Connection name to register |
| `--hostname` | this machine's hostname | Display-only text sent with the request (shown to the administrator alongside the fingerprint) |
| `--label` | — | Display-only label sent with the request |
| `--platform` | — | Display-only platform sent with the request |
| `--purpose` | `cli enrolment` | Display-only purpose sent with the request |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |
| `--poll-interval` | 5s | Interval between collect polls |

None of these flags select the certificate's markers (admin, payload-signing, root
scope) — that set is decided entirely by the administrator at approval time, never by
the requesting machine.

### Login and reconnect

Run by an **operator who already has a browser** but no `cfg` credential yet — the
default, everyday way to obtain a session. Where `cfg credential enrol` (above) is the
headless path, `cfg login` is the interactive one: no bundle file, no private key
transfer, no shell on the controller.

```bash
cfg login --url https://<controller-api>
cfg login --url https://<controller-api> --name prod
```

The command generates a random verifier locally (never written to disk, never placed in
a URL, sent to the controller only once — as a bearer credential at collect time), lodges
a login request over its own connection, and prints:

```
Code: AB3D-7FQK
Approve this login by visiting: https://<controller-api>/login/confirm?request_id=cli-login-...
Expires: 2026-08-28T11:05:00Z
```

It then opens the approval URL in the default browser (skip this and only print the URL
with `--no-browser`) — best-effort; if opening fails (a headless SSH session, an
unsupported platform) the command prints a notice and the operator copies the URL to any
browser, on any machine. Complete a passkey login there and confirm the same code this
command printed — **the code comparison is the actual security check**, and applies
uniformly regardless of the account's scope: `cfg login` succeeds the same way for a
root-scoped account as for a tenant-scoped one, and the resulting session carries
whatever scope the approving account has.

**No bundle, no relay, no listener.** `cfg login` never opens a local listening socket.
The session token is handed to this command exactly once, in the response body of the
collect call this command itself makes to the controller — the browser never talks to
this machine, and the token never appears in any URL, query string, fragment, redirect
target, log line, or output stream.

**A tenant-scoped account needs the `cli-login:approve` permission** (granted like any
other RBAC permission) before it can log in this way — `cfg login` reuses the existing
session-creation path (`POST /api/v1/sessions`) for the approving account, gated by its
own `cli-login:approve` permission rather than the `session:create` permission that path
normally requires; it does not mint through a separate route.

The command then polls the collect endpoint (`--poll-interval`, default 3s, bounded by
`--wait-timeout`, default 5m) until the browser confirms, printing `Waiting for browser
approval...` between polls, and exits with one of four distinct outcomes — none of which
leave a session on disk:

| Outcome | What happened | Message |
|---|---|---|
| Denied | The browser session declined the confirmation | `login request was denied by an administrator` |
| Timed out | The wait-timeout elapsed, or the login request's own short lifetime expired first | `timed out waiting for browser approval; run 'cfg credential enrol' for headless enrolment instead` |
| Interrupted | The operator pressed Ctrl-C while waiting | `login interrupted; no session was stored` |
| Already collected | This request was already collected (should not normally occur) | `login request was already collected` |
| **Success** | Confirmed in the browser and collected | `Logged in as "<name>" (expires ...)` |

On success the command registers the connection in the local registry (`unlock_method:
browser` — there is no bundle to later reconnect from; run `cfg login` again for a fresh
session) and stores the session token in the OS keychain, exactly as `cfg connect` does.
The next ordinary `cfg` command against this controller works without any further step.

If a previous session for this controller is already stored, `cfg login` checks it before
starting the browser flow and, if it is no longer usable, prints which of two distinct
reasons applies — both surface as the same `401` from the controller, so the command
never collapses them into one generic message:

```
Note: your previous session was revoked — this usually means the account was disabled. If a fresh login also fails, contact an administrator.
Note: your previous session expired. Logging in again...
```

This is informational only; the fresh browser login proceeds either way.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller HTTPS URL; required, and must be HTTPS for any non-loopback address (same rule as `cfg connect`) |
| `--name` | derived from URL host | Connection label to register |
| `--tls-insecure` | false | Skip TLS certificate verification (development only, env: `CFGMS_TLS_INSECURE`) |
| `--server-name` | — | Override the TLS server name used for certificate verification |
| `--poll-interval` | 3s | Interval between collect polls |
| `--wait-timeout` | 5m | Maximum time to wait for browser approval |
| `--no-browser` | false | Never attempt to open a browser automatically; only print the URL |

### cfg credential revoke-by-token / cancel-request / list-orphaned / revoke-orphaned (Issue #3725)

Run by the **administrator** when an enrolment token or an enrolled host is believed
compromised. Minting (above) and un-minting ship together: this is the containment
half. All four subcommands require `--force` or an interactive `y` confirmation
(`confirmDestructive`, the same guard `cfg account revoke-cert` and `cfg account
delete` use).

```bash
cfg credential revoke-by-token <token-id>
```

Revokes every certificate already issued from one enrolment token and blocks every
still-`pending`/`approved` request under that token from ever producing one. Prints a
per-request outcome (`contained` / `already_contained` / `error`) rather than an
all-or-nothing result. A token with no lodged requests is reported as a failure (non-zero
exit) rather than a silent success — a mistyped or already-exhausted token ID should
never look like "nothing to do."

```bash
cfg credential cancel-request <request-id>
```

Cancels a request that is `approved` but not yet `collected` — this is a state
transition, not a certificate revocation, because collect (not approval) mints the
certificate. Refused with a distinct error for a request that is `pending` (not yet
approved — use `deny` instead), already `collected` (use `revoke-by-token` or
`revoke-orphaned` instead), or already `denied`.

```bash
cfg credential list-orphaned
cfg credential revoke-orphaned <serial>
```

`list-orphaned` finds `collected` enrolment-flow certificates whose bound account no
longer carries a matching binding — the on-demand equivalent of the background sweep
(below) for an administrator who wants to act immediately. Listing never revokes
anything; `revoke-orphaned` is a separate, explicit action on a serial the list
surfaced. It refuses (409) a serial that is still bound to an account (not orphaned) or
already revoked.

**Flags (all four subcommands):**

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller REST API URL (env: `CFGMS_API_URL`) |
| `--force` | false | Skip the interactive confirmation prompt (not on `list-orphaned`) |
| `--json` | false | Emit JSON output (`list-orphaned` only) |

### REST reference

The sections below document the endpoints the two commands above call. They remain
accurate for a direct API consumer that does not go through `cfg`.

### Minting and revoking an enrolment token

```
POST /api/v1/enrolment-tokens
{"tenant_id": "root/msp-a/client-1"}
```

Requires the `enrolment-token:mint` permission at `AssuranceStrong` (mTLS admin bundle or
a stepped-up web/CLI session — see [Connection Management](../deployment/cfg-operator-guide.md#2-first-connect-bootstrap-bundle--one-time-only)).
`tenant_id` is required; a tenant-scoped caller may only mint within its own subtree. The
response includes the raw token value **exactly once**:

```json
{
  "data": {
    "id": "et-<uuid>",
    "token": "<64-char hex — shown only here>",
    "token_prefix": "a1b2c3",
    "tenant_id": "root/msp-a/client-1",
    "created_at": "2026-08-28T10:00:00Z",
    "expires_at": "2026-08-28T11:00:00Z",
    "revoked": false
  }
}
```

Hand the `token` value to the enrolling machine out of band. It is single-use — spent the
moment a lodge succeeds against it, whether or not the resulting request is ever
approved — and expires on its own an hour after minting. Only `token_prefix` (its first 6
characters) is ever shown again, in logs or elsewhere; the full value cannot be retrieved
after this response.

To revoke an unspent token before it is used:

```
POST /api/v1/enrolment-tokens/{id}/revoke
```

Requires `enrolment-token:revoke` at `AssuranceStrong`. A token that has already been
spent cannot be revoked (409) — its one use is already consumed.

To list enrolment tokens for the tenants the caller can see:

```
GET /api/v1/enrolment-tokens
cfg credential enrolment-token list
```

Requires `enrolment-token:list` (no assurance floor — a read surface). Each row carries
`id`, `token_prefix`, `tenant_id`, `created_at`, `created_by`, `expires_at`, `status`
(`active`, `spent`, `expired` or `revoked`) and `spent_at`. The token secret is never
returned; only the short `token_prefix` identifies a token.

### Lodging a signing request

```
POST /api/v1/credential-requests/lodge
Authorization: Bearer <enrolment token>
{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...", "hostname": "laptop-01", "label": "sales laptop", "platform": "linux", "purpose": "cli enrolment"}
```

This is the one endpoint in the epic that carries no API key, mTLS certificate, or web
session — only the enrolment token as a bearer credential, exactly as `POST
/api/v1/register` is unauthenticated by design. An absent, unknown, revoked, expired, or
already-spent token all return `401` with an identical body, so no response ever
discloses which of those five conditions applied.

`csr_pem` must be a single PEM `CERTIFICATE REQUEST` block whose own signature verifies
against the public key it carries; a body that also contains any private-key PEM block is
rejected outright. `hostname`, `label`, `platform`, and `purpose` are display-only text —
they are never trusted for any authorization decision, and no caller-supplied field (a
`tenant_id`, `permission`, `account`, or similar claim slipped into the body) has any
effect: the tenant is always derived from the token record.

On success the response is returned **once**:

```json
{
  "data": {
    "request_id": "cr-<uuid>",
    "public_key_fingerprint": "<64-char hex SHA-256 over the public key>",
    "public_key_fingerprint_short": "AB12-CD34-EF56-7890",
    "collect_secret": "<64-char hex — shown only here>",
    "expires_at": "2026-08-28T11:00:00Z"
  }
}
```

`public_key_fingerprint_short` is a deterministic function of the public key alone — the
enrolling machine can compute and print the same value locally, so an administrator
reviewing the pending queue can visually match what is on screen against what the machine
printed before approving. `collect_secret` is consumed by a later story; only its hash is
persisted here.

Lodge is rate limited per source address and bounded by a per-tenant outstanding-pending
cap: once a tenant's queue is full, further lodges are refused (`503`) rather than
evicting older entries — the cap is a ceiling, not a queue-flush primitive.

### Listing and denying pending requests

```
GET /api/v1/credential-requests
```

Requires `credential-request:list`. Returns pending requests scoped to the caller's
tenant subtree (an unscoped mTLS admin sees all), including the fingerprint, its short
comparable form, source address, requested purpose, and expiry — never the CSR, the
collect-secret hash, or which token lodged it.

```
POST /api/v1/credential-requests/{id}/deny
{"reason": "unrecognized device"}
```

Requires `credential-request:deny`. Denial is terminal: a denied request can never later
be approved or collected, and denying it twice returns `409`.

### Expiry

Both unspent enrolment tokens and pending requests expire on a one-hour lifetime and are
removed by a background sweep that runs independently of any read — an expired record is
not merely hidden on the next list call, it is deleted. Spent tokens and denied requests
are left in place; the sweep only removes records that are still live but past their
expiry.

### Approving a pending request (Issue #3718)

Story #3718 adds the approval decision. **Approving signs nothing** — the shipped steward
registration path already works this way (`handleApproveRegistration`'s own doc comment:
"no cert is generated here, generate-on-claim") and this endpoint mirrors it: it validates
the approver's own authority, decides which certificate markers the eventual credential
will carry, selects or creates the account it will bind to, and records all three together
on the pending request before moving it to `approved`. No certificate exists at the end of
this call — signing the lodged public key and writing the account binding atomically is the
collect story that follows.

```
POST /api/v1/credential-requests/{id}/approve
{
  "fingerprint": "AB12-CD34-EF56-7890",
  "account_id": "<existing account UUID>",
  "grant_admin_marker": true,
  "grant_payload_signing_marker": false,
  "grant_root_scope_marker": false
}
```

`fingerprint` must match the fingerprint recorded at lodge time — full or short form both
accepted — or the call is rejected with `409`. This closes the window where a second lodge
re-sorts the queue between rendering the list and clicking approve.

Exactly one of `account_id` (select an existing account within the caller's tenant subtree)
or `new_account_username` (plus optional `new_account_tenant_id`, defaulting to the
request's own tenant) must be supplied. A headless host is represented by its own account,
created through the same durable account-persistence path `POST /api/v1/accounts` uses.

Each of the three certificate markers (Epic #3711 D3) is granted only when explicitly
requested **and** only when the approver holds the authority for it — the default is
nothing, and a marker the approver cannot grant refuses the whole call (`403`) rather than
silently dropping it:

| Marker | Requested field | Requires |
|---|---|---|
| `AdminMarkerOID` | `grant_admin_marker` | The approver is themselves a platform administrator (`Principal.ImplicitAdmin`) |
| `PayloadSigningMarkerOID` | `grant_payload_signing_marker` | The approver holds `signing-credential:request` at `AssuranceStrong` — the same gate `POST /api/v1/signing-credential/request` enforces on itself |
| `RootScopeMarkerOID` | `grant_root_scope_marker` | The approver's own request was authenticated by a certified, non-revoked root-scope-marked certificate (`Principal.RootScoped && Principal.CertSerial != ""`) — a session or a cookie can never satisfy this, however many permissions it holds |

An approver can therefore never mint a credential stronger than their own — which is also
what makes **self-approval safe**: approving one's own request (the selected or created
account is the approver's own) grants nothing the approver did not already have. The
approve endpoint records `self_approved` on the audit event so this is visible, not
something a reviewer has to infer.

Requires `credential-request:approve` at `AssuranceStrong` with a fresh user-presence
proof. The presence requirement is what actually confines the retained bootstrap admin
credential here ([ADR-021](../architecture/decisions/021-identity-assurance-levels.md)
Amendment 5): its `ImplicitAdmin` flag satisfies every permission-string check by
construction, but it resolves to no bound account, so no presence token can ever be minted
for it.

### Collecting the signed certificate (Issue #3719)

Story #3719 closes the loop: this is where the certificate is actually signed. The
machine that lodged the request, and only that machine, collects it — authenticated by
the `collect_secret` the lodge response returned exactly once, never by the request ID
or the public-key fingerprint (both are values an observer of the approval screen has
already seen). There is no API key, mTLS certificate, or web session on this call, and
no permission gate — the endpoint is not on the elevated-assurance surface at all,
exactly like lodge.

```
POST /api/v1/credential-requests/{id}/collect
Authorization: Bearer <collect secret>
```

The waiting machine polls this endpoint. Every response is one of:

| Response | Meaning |
|---|---|
| `404 REQUEST_NOT_FOUND` | Unknown ID, **or** a valid ID with the wrong (or absent) collect secret — the two are indistinguishable by design; the endpoint never confirms a request ID exists to an unauthenticated caller |
| `200 {"status": "pending"}` | Correct secret, but no admin decision yet — keep polling |
| `200 {"status": "denied"}` | The request was denied; it will never become collectible |
| `200 {"status": "expired"}` | The request (and its collect secret) passed its one-hour lifetime before it was collected |
| `410 Gone` | Already collected — by this machine's own earlier call, or by the winner of a concurrent race. There is never a second certificate for one request |
| `503` | Not the authoritative node for minting; the request is untouched — retry |
| `200` with a certificate body | Success (below) |

A successful collection returns:

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "serial_number": "...",
    "account_id": "<the account recorded at approval>",
    "granted_markers": ["admin"],
    "expires_at": "2027-08-28T10:00:00Z"
  }
}
```

The certificate is signed from exactly the marker set and account recorded at approval
— never recomputed, re-derived, or widened at collect, and never read from the bound
account's own attributes. There is no authenticated principal on this call to derive
anything else from. An approved request that is never collected leaves no certificate
in existence: nothing is signed until collect runs.

Collection is single-use, enforced as a conditional durable state transition
(`approved` → `collected`) that commits **before** the certificate is signed — so a
restart between the transition and the response can never produce a second
certificate, and the loser of a concurrent collect race always receives `410` rather
than a duplicate. The account binding is written **before** the certificate is
returned to the caller, and any failure after signing revokes the just-issued
certificate immediately: a signed certificate is never left observable in a state
where it resolves to no account (that state would otherwise fall through to the mTLS
middleware's bootstrap-fallback path and be granted implicit root).

Minting is leadership-gated, but only on the branch that actually mints: an approved
request found on a non-authoritative node returns `503` and stays `approved` untouched,
while every polling response above (`pending`/`denied`/`expired`/not-found) remains
available regardless of leadership — a waiting machine's poll loop does not stall
during a leadership change.

Collect is rate limited per source address, and the collect secret expires with the
request it belongs to (the same one-hour lifetime and the same background sweep
described above) — a captured secret has a bounded life.

### Revoking and containing enrolment-issued credentials (Issue #3725)

Story #3725 closes the loop on the other side: when an enrolment goes wrong, an
administrator can revoke every certificate already issued from one enrolment token,
cancel a request that was approved but never collected, and find — and, as a separate
explicit action, revoke — enrolment-issued certificates that exist with no account
binding. Minting and un-minting ship together.

```
POST /api/v1/enrolment-tokens/{id}/revoke-issued-credentials
```

Requires `enrolment-token:revoke-issued` at `AssuranceStrong`. Walks every credential
request lodged against the token and, per request:

- `collected`: revokes the issued certificate via the same fail-closed
  revoke-then-unbind ordering `POST /accounts/{username}/certs/revoke/{serial}` uses —
  a failure after the revoke leaves a revoked-but-still-bound certificate, never a live
  unbound one.
- `pending` or `approved`: transitions the request to `denied`, so it can never later be
  approved or collected — this is what makes the containment complete, not just a
  revoke of what has already been signed.
- `denied` already: no-op, reported as already contained.

The response reports one outcome per request rather than failing the whole call on the
first error:

```json
{
  "data": {
    "token_id": "et-<uuid>",
    "results": [
      {"request_id": "cr-<uuid>", "outcome": "contained"},
      {"request_id": "cr-<uuid>", "outcome": "already_contained"},
      {"request_id": "cr-<uuid>", "outcome": "error", "detail": "certificate revoked but binding removal failed"}
    ]
  }
}
```

```
POST /api/v1/credential-requests/{id}/cancel
```

Requires `credential-request:cancel` at `AssuranceStrong`. Cancels a request that is
`approved` but not yet `collected` — a state transition (`approved` → `denied`, the same
terminal status `deny` uses; there is no separate "cancelled" status), not a certificate
revocation, since collect — not approval — is what mints the certificate. Refuses (409)
with a distinct error code for every other status: `REQUEST_NOT_APPROVED` (still
`pending`), `REQUEST_ALREADY_COLLECTED` (a live certificate exists — use
`revoke-issued-credentials` or the orphaned-certificate endpoints instead), or
`REQUEST_ALREADY_DENIED`. Takes the same lock the collect endpoint's
approved→collected compare-and-set uses, so a cancel and an in-flight collect for the
same request can never both observe `approved`.

```
GET /api/v1/credential-requests/orphaned
```

Requires `credential-request:list-orphaned` (no assurance floor — a read surface,
mirroring `credential-request:list`). Lists `collected` requests whose recorded serial
does not appear in its bound account's `CertBindings` — the exact window the background
orphan sweep (above) closes on its own interval, surfaced on demand:

```json
{
  "data": [
    {
      "request_id": "cr-<uuid>",
      "tenant_id": "root/msp-a/client-1",
      "serial": "...",
      "account_id": "<the account recorded at approval>",
      "collected_at": "2026-08-28T10:00:00Z"
    }
  ]
}
```

```
POST /api/v1/credential-requests/orphaned/{serial}/revoke
```

Requires `credential-request:revoke-orphaned` at `AssuranceStrong`. Revokes a listed
serial — a separate explicit action from listing. Re-verifies the serial is still
orphaned immediately before revoking (409 `NOT_ORPHANED` if a binding now exists, 409
`ALREADY_REVOKED` if already revoked), so this endpoint can never be used as a side
channel to revoke a live, properly bound credential.

Every revocation and every cancel emits a durable audit event, and every mutating
handler here calls the same lease-backed leadership check the rest of this package
uses (`503` when not the authoritative node).

### Renewing an issued credential — cfg credential renew (Issue #3724)

Story #3724 closes the epic's last gap: a credential collected via #3719 renews
itself before it expires, with no human present, and cannot use renewal to gain
anything it did not already have.

```bash
cfg credential renew
cfg credential renew --unattended
cfg credential renew --bundle /etc/cfgms/admin.bundle.yaml --unattended
```

Renewal is authorised by presenting the **current, still-valid certificate itself**
over mutual TLS — there is no separate renewal credential, no bearer secret, and
nothing in the request body can name, select, or change which account the renewed
certificate binds to. The command reads the admin bundle (the same file `cfg
connect --bundle` imports and `cfg credential request-signing-cert` authenticates
with), generates a fresh keypair locally, and sends only the new public key as a
certificate signing request:

```
POST /api/v1/credential-renewal
{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----..."}
```

authenticated by presenting the bundle's own client certificate over mTLS. The
controller derives everything about the new certificate from that certificate: the
account it renews into (the one the presented serial is already bound to — a
presented certificate with no binding at all, the mTLS bootstrap-fallback case, is
refused rather than renewed into), and the exact marker set the presented
certificate carries, copied verbatim and never widened. A CSR that reuses the
current certificate's own public key is refused — a fresh keypair is required on
every renewal.

A successful renewal returns:

```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----...",
    "serial_number": "...",
    "account_id": "<the account the presented certificate is bound to>",
    "granted_markers": ["admin"],
    "expires_at": "2027-08-28T10:00:00Z"
  }
}
```

`cfg credential renew` writes the new certificate, its freshly generated private
key, and the CA certificate back into the same bundle file, preserving
`controller_url` and `audit_subject` — the file is fully usable for the next `cfg`
invocation with no further action. The old certificate is revoked and its binding
removed once the new one is confirmed bound; a failure earlier in that sequence
(before the new certificate is bound) leaves the old, still-valid certificate as the
working credential rather than none.

**The renewal window.** The controller refuses renewal outside a 30-day window
before expiry, for an already-expired certificate, and for a revoked serial — a
certificate with most of its life left has no reason to renew early. `--unattended`
is the flag for periodic/cron/systemd-timer invocation: it checks the bundle
certificate's expiry **locally**, before contacting the controller at all, and exits
`0` with no network call when renewal is not yet due — so a job scheduled to run
daily, or even hourly, generates no noise or load until renewal actually matters.
Without `--unattended`, renewal is attempted unconditionally and the controller's
own window check is authoritative.

**The off switch is the bound account, not a lifetime cap.** There is no
total-renewal-count limit and no maximum credential age — a credential may renew
indefinitely. To stop it, disable the bound account
(`POST /api/v1/accounts/{username}` with `disabled: true`, or the equivalent web UI
action): a disabled account's certificate can no longer even authenticate, so the
very next renewal attempt fails, and the host cannot reach the controller for
anything else either.

**When renewal fails.** The error message names the reason (`OUTSIDE_RENEWAL_WINDOW`,
`CERTIFICATE_EXPIRED`, `NO_ACCOUNT_BINDING`, `KEY_REUSE_REJECTED`, or a `401` for a
revoked or disabled-account certificate that never authenticated in the first
place):

- Outside the renewal window: not an error to act on — the certificate is not due
  yet; a scheduled `--unattended` run will pick it up once it is.
- Certificate already expired, or the bound account was disabled: there is no
  recovery through this command. An administrator must mint a fresh enrolment
  token ([above](#minting-and-revoking-an-enrolment-token)) and the host must
  re-enrol from scratch — renewal only ever extends a credential that is still
  alive, never resurrects one that is not.
- Any other failure (network, `503` from a non-leader node, a `5xx`): safe to
  retry: the old certificate is left intact until a new one is confirmed bound, so
  a failed or interrupted renewal never leaves the host without a working
  credential.

Renewal has no RBAC permission gate — the presented certificate is itself the
authorization, matching the "no separate renewal credential" design. It is
leadership-gated on the controller (a non-leader node returns `503`, and the old
credential is left untouched) and records a durable audit event naming the old
serial, the new serial, and the granted marker set.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--unattended` | false | Only contact the controller if the certificate is within its renewal window; exit `0` without renewing otherwise |
| `--url` | bundle's `controller_url` | Controller REST API URL override |
| `--tls-insecure` | false | Skip TLS certificate verification (development only) |
| `--server-name` | — | Override the TLS server name used for certificate verification |

`--bundle`, `--no-bundle`, and `CFGMS_ADMIN_BUNDLE` (the global bundle-discovery
flags — see [Connection Management](../deployment/cfg-operator-guide.md#2-first-connect-bootstrap-bundle--one-time-only)) select which bundle
file is renewed; renewal always uses the resolved bundle's own certificate, never a
session token, even if one happens to be active.

### Permissions

| Permission | Assurance floor | Notes |
|------------|------------------|-------|
| `enrolment-token:mint` | `AssuranceStrong` | Mints a single-use, short-lived token |
| `enrolment-token:revoke` | `AssuranceStrong` | Revokes an unspent token |
| `enrolment-token:list` | none | Read-only; lists tokens without their secret |
| `credential-request:list` | none | Read-only; outside the elevated-assurance surface |
| `credential-request:deny` | none | De-escalation action, mirrors `registration:deny` |
| `credential-request:approve` | `AssuranceStrong` + presence | Decides the marker set and account binding (Issue #3718); signs nothing |
| `enrolment-token:revoke-issued` | `AssuranceStrong` | Revokes every certificate issued from a token and blocks its outstanding requests (Issue #3725) |
| `credential-request:cancel` | `AssuranceStrong` | Cancels an approved-but-uncollected request (Issue #3725) |
| `credential-request:list-orphaned` | none | Read-only; outside the elevated-assurance surface |
| `credential-request:revoke-orphaned` | `AssuranceStrong` | Revokes a listed orphaned certificate (Issue #3725) |
| — (none) | — | `POST /api/v1/credential-renewal` (Issue #3724) has no permission gate; the presented certificate is itself the authorization |
| `osquery:list-catalog` | none | Read-only; lists osquery catalog ids and parameter schemas, never query text (Issue #5449) |

## cfg account — Account Lifecycle and Certificate Credentials (Issue #3582)

Manage web-admin account lifecycle and bound mTLS certificate credentials.
Account commands call the `/api/v1/accounts` REST endpoints. Certificate binding
commands call the `/api/v1/accounts/{username}/certs` endpoints.

Authentication is resolved via the standard session-or-bundle chain (same as all
other `cfg` commands). The server enforces the required permission on each verb.

### cfg account create

Creates a new web-admin account, or resets an existing one (upsert). On creation
a single-use enrollment magic link is printed once for the admin to share with the
account holder via a secure channel.

```
cfg account create --username <u> [--tenant-id <t> | --root-scope] [--permission <p>]... [--json]
```

Example:

```
cfg account create --username alice --tenant-id acme-corp
# Account provisioned: alice
#   ID:      <uuid>
#   Tenant:  acme-corp
#   ...
#   Enrollment link: deadbeef...
#   (shown once — share with the account holder via a secure channel)
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--username` | — | Account username (required) |
| `--tenant-id` | — | Scope account to this tenant |
| `--root-scope` | false | Grant cross-tenant root scope (mutually exclusive with `--tenant-id`) |
| `--permission` | — | Permission to grant (repeatable) |
| `--json` | false | Output as JSON (includes the enrollment link) |
| `--url` | env/bundle | Override controller URL |

### cfg account list

Lists all web-admin accounts visible to the caller's tenant scope.

```
cfg account list [--json]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--url` | env/bundle | Override controller URL |

### cfg account get

Gets account identity and status for a single web-admin account. Returns
`tenant_id`, `root_scope`, `permissions`, `disabled` state, and whether an
outstanding enrollment link exists.

```
cfg account get <username> [--json]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--url` | env/bundle | Override controller URL |

### cfg account update

Updates account permissions and/or disabled state, or resets its passkeys. All flags are optional —
omitted flags retain existing values.

```
cfg account update <username> [--permission <p>]... [--disabled=true|false] [--reset-credentials] [--json]
```

Example:

```
cfg account update alice --disabled=true
cfg account update alice --permission account:list --permission account:get
cfg account update alice --reset-credentials
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--permission` | — | Permissions to set (repeatable; replaces the full existing set) |
| `--disabled` | — | Set disabled state: `true` or `false` |
| `--reset-credentials` | false | Revoke the account's existing passkeys and issue a new enrollment link |
| `--json` | false | Output as JSON |
| `--url` | env/bundle | Override controller URL |

### cfg account delete

Deletes a web-admin account via the offboarding cascade: disable → revoke bound
certificates → revoke sessions → delete. Requires `--force` or interactive
confirmation (mirrors `cfg webauthn revoke`).

```
cfg account delete <username> [--force]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | false | Skip confirmation prompt |
| `--url` | env/bundle | Override controller URL |

### cfg account bind-cert

Binds an mTLS certificate serial to a web-admin account. A serial can be bound
to at most one account at a time.

```
cfg account bind-cert <username> --serial <s> [--label <l>] [--fingerprint <f>]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--serial` | — | Certificate serial number (required; 1-40 alphanumeric chars) |
| `--fingerprint` | — | Certificate fingerprint (optional; stored for audit correlation) |
| `--label` | — | Human-readable label for the binding |
| `--url` | env/bundle | Override controller URL |

### cfg account certs

Lists all mTLS certificate bindings for a web-admin account, including each
binding's last-used timestamp (Issue #3715) — the compensating control for
allowing credentials that renew themselves indefinitely: a host that no longer
needs its credential becomes visible because its binding stops accumulating
recent `Last used` activity.

```
cfg account certs <username> [--json]
```

Example:

```
cfg account certs alice

Certificate bindings for alice (2):

  [1] Serial:   12345
      Label:    primary laptop
      Bound at: 2026-08-01T00:00:00Z
      Last used: 2026-08-20T12:30:00Z

  [2] Serial:   67890
      Bound at: 2026-08-15T00:00:00Z
      Last used: never
```

`Last used` renders `never` when the binding has not yet been used to
authenticate — including every binding created before this story shipped.
This is an explicit value, not a blank line or a zero-value date: the
underlying `last_used_at` field is optional and is omitted from the JSON
response entirely until the certificate's first successful authentication.
The timestamp is recorded on a best-effort, coalesced basis (at most once
every few minutes per certificate) and is observational only — it never
affects whether a request is authorised.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as JSON |
| `--url` | env/bundle | Override controller URL |

### cfg account revoke-cert

Revokes an mTLS certificate via the controller CA and removes its binding.
This is irreversible — the certificate is added to the CRL. Requires `--force`
or interactive confirmation.

```
cfg account revoke-cert <username> <serial> [--force]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | false | Skip confirmation prompt |
| `--url` | env/bundle | Override controller URL |

### cfg account rotate-cert

Atomically binds a new certificate serial and revokes the old one in a single
resumable operation. Safe to retry if interrupted — a repeated call with the
same arguments completes the rotation without a second bind or revocation.

Rotation revokes the old serial through the CA, so it is irreversible in the
same way `revoke-cert` is and takes the same guard: `--force` or interactive
confirmation.

```
cfg account rotate-cert <username> <old_serial> --new-serial <s> [--force]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--new-serial` | — | New certificate serial number (required) |
| `--fingerprint` | — | New certificate fingerprint (optional; for audit) |
| `--force` | false | Skip confirmation prompt |
| `--url` | env/bundle | Override controller URL |

## Agent software authenticator

`cfg authenticator` manages software WebAuthn authenticators: P-256 keys bound to
one controller's RP ID and origin, for operators and agents that have no hardware
key or browser. This section covers creating, listing, deleting and registering
them; later steps (headless login) are documented under their own sub-headings
here as they ship.

```
cfg authenticator create <name> --url <controller URL> [--rp-id <id>] [--origin <origin>] [--ca-cert <file>] [--label <text>] [--key-provider platform|store]
cfg authenticator list [--json]
cfg authenticator delete <name> [--force]
cfg authenticator enroll <name> (--link-file <path> | --link-stdin)
cfg webauthn register --username <user> --authenticator <name> [--label <text>]
```

**`create`** generates a P-256 key and a random credential ID and stores the
authenticator as one encrypted record. Where the key itself lives depends on
`--key-provider` (see [Where the key lives](#where-the-key-lives)). Nothing is sent
to the controller, so a new authenticator is listed as not registered.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Controller URL (required, must be `https`) |
| `--rp-id` | host of `--url` | WebAuthn RP ID |
| `--origin` | `scheme://host[:port]` of `--url` | WebAuthn origin; must be `https`, with a host that is the RP ID or a subdomain of it |
| `--ca-cert` | — | PEM file with the CA certificate that signs the controller's TLS certificate; stored in the record |
| `--label` | — | Free-text label |
| `--key-provider` | `platform` on Windows, `store` elsewhere | `platform`: a non-exportable per-user key in the Windows platform key provider (Windows only; refused elsewhere). `store`: the key is kept in the encrypted credential store |

Names are 1-64 letters, digits, `.`, `_` or `-`, starting with a letter or digit.
`create` refuses a name that already exists and leaves the existing record
untouched; delete it first to replace it. `http://` for `--url` or `--origin` is
refused before anything is written. There is no option to skip TLS verification
and no way to export the key.

**`list`** shows name, RP ID, origin, credential ID (base64url), whether the
authenticator is registered, and its protection level (`platform`: a
non-exportable key in the Windows platform key provider; `store`: the key is in
the encrypted credential store). `--json` prints the same fields, plus the label and
controller URL, as a JSON array. Key material is never printed by any command.

**Registering with a controller.** A new authenticator is registered by one of two
paths. Either way the controller must allow software authenticators for the
account, and on success `cfg authenticator list` shows the record as registered and
the record holds the account's user handle. If the controller refuses (for example
HTTP 403 `SOFTWARE_AUTHENTICATOR_NOT_ALLOWED`), the record stays unregistered, the
command exits non-zero and prints the server's code.

- **`cfg authenticator enroll <name>`** completes first-passkey enrollment for the
  account an enrollment link was issued for (`cfg account create` prints the link).
  It runs the controller's `/api/v1/web/passkey/enroll/begin` and `/finish` routes,
  sending the token in the `X-Enrollment-Token` header, and verifies the controller
  with the record's `ca_cert_pem`. The link is a single-use bearer secret, so
  there is no flag that takes it as a value: give it with `--link-file <path>`,
  with `--link-stdin`, or in the `CFGMS_ENROLLMENT_LINK` environment variable
  (used when neither flag is given; the two flags cannot be combined). The link's
  scheme and host must match the authenticator's origin, otherwise `enroll`
  refuses before any network call. The token is never printed, logged or stored.
  The record's `--label`, if any, is stored on the credential.
- **`cfg webauthn register --username <user> --authenticator <name>`** registers the
  authenticator on an existing account through the admin register routes. It still
  needs the admin bundle (mTLS certificate); a Bearer session alone fails with the
  mTLS requirement error (ADR-021 §7). `--label` is passed through to the
  controller. Without `--authenticator` the command keeps refusing and points at
  browser enrollment.

**`delete`** removes the record after a confirmation prompt (`--force` skips it),
and for a `platform` authenticator first deletes its key from the platform key
provider. It does not contact the controller: the controller keeps listing the
credential until it is revoked with `cfg webauthn revoke <credential-id>`. A
record that cannot be read can still be deleted; `delete` then warns that any
platform key it named could not be located. A key that is already gone, or whose
provider is no longer available, does not stop `delete`. If the key exists but
cannot be deleted, or the record names a key that `cfg` never creates, `delete`
keeps the record and fails; with `--force` it deletes the record anyway, leaves
the key, and warns.

#### Where the key lives

**Windows (default, `platform`).** `create` makes the P-256 key in a CNG key
storage provider as a persisted, sign-only, per-user key (not a machine key) with
export policy none: the Microsoft Platform Crypto Provider (the TPM) when it can
hold a key, otherwise the Microsoft Software Key Storage Provider. The private key
bytes never exist in the `cfg` process or on disk; signing happens inside the
provider. The record stores only the provider name and key name. `create` prints
which provider holds the key. When no platform key provider is available at all,
`create` without `--key-provider` falls back to `store` and says so; an explicit
`--key-provider platform` fails instead. Moving an existing authenticator between
providers is not supported: delete it and create it again.

What non-exportable protects, and what it does not:

- It keeps the key out of `cfg`: the credential store, a copied record, a backup
  or a memory dump of `cfg` does not contain the key, and no CNG call returns it.
- With the Platform Crypto Provider the key never leaves the TPM, so it cannot be
  used from another machine.
- With the Software Key Storage Provider, export policy none is enforced by the
  provider, and the key is persisted in the user's profile under DPAPI. A process
  running as the same user with tooling that reads DPAPI-protected key files can
  still recover it. This is stronger than `store` against casual reads, but not
  hardware protection. `create` says when the TPM could not hold the key, and
  `list` shows which provider holds each key (the `KEY PROVIDER` column, and
  `key_provider` in `--json`).
- Neither provider stops a process running as the same user on the same machine
  from asking the provider to sign with the key. Treat the authenticator as a
  credential of that user, as with `store`.

**`store` (Linux, macOS, or `--key-provider store`).** The key is kept,
PKCS#8-encoded, inside the encrypted record.

**The record:** `<user config dir>/cfgms/credentials/authenticator.<name>.enc`,
a versioned JSON record (version, name, credential ID, the PKCS#8 key for `store`
or the provider and key name for `platform`, RP ID, origin, controller URL,
optional CA certificate, user handle, registered flag, protection) encrypted by
the same credential store as the signing key above. The directory is
private to the current user: mode 0700 on Linux and macOS, and an ACL for the
current user and SYSTEM on Windows. The record has no AAGUID field; every response
carries the fixed CFGMS AAGUID, and no flag, environment variable or config changes
it. A record with an unknown `version` is rejected with an error naming the version;
there is no migration, so delete the authenticator and create it again.

**On-disk protection of the record by OS** (for `store`, this is the protection
of the key itself):

| OS | Protection of the record file |
|----|----------------------------|
| Linux | AES-256-GCM, key derived from the machine ID (`/etc/machine-id`, or a per-directory identity file where it is absent) and a per-store salt; file mode 0600 in a 0700 directory |
| macOS | AES-256-GCM, key derived from the hardware platform UUID and a per-store salt; file mode 0600 in a 0700 directory |
| Windows | User-scope DPAPI, with entropy derived from the machine GUID and a per-store salt; protected ACL for the current user and SYSTEM |

**Limits:**

- On Linux and macOS (and on Windows with `--key-provider store`) the encryption
  key is derived from values any process running as the same user can read, so
  any such process can decrypt the key. The
  encryption protects against a copied file, a backup or a synced config directory,
  not against code running as the operator. Treat the authenticator as a credential
  of that user.
- On Linux and macOS the key is not moved to the TPM, Secure Enclave or OS
  keychain, so it works on headless hosts.
- A record decrypts only for the same user on the same machine; copy it elsewhere
  and `list` fails with the credential store's different-user-or-machine error;
  delete the authenticator and create it again there.
- The software authenticator's user-verified flag only shows that the holder can
  use the key; it does not verify a person.

### Running commands with `--authenticator`

With `--authenticator <name>` (or `CFGMS_AUTHENTICATOR=<name>`), every `cfg`
command that uses a session or admin bundle (everything except `cfg webauthn ...`,
which only ever uses the admin bundle) first logs in with that authenticator and
uses the resulting web session for the command:

```
cfg --authenticator agent-1 token list
CFGMS_AUTHENTICATOR=agent-1 cfg token list
```

The login is the controller's usernameless passkey login: `cfg` fetches the
pre-session CSRF token, begins the login, signs the challenge with the
authenticator's key, and finishes. The controller's session cookie and CSRF token
are held in memory only and sent over `https` to the controller the authenticator
is bound to. When the command ends, whether it succeeded or failed, `cfg` calls
`POST /api/v1/web/logout`, which revokes the session on the controller.

- **One session per command.** Nothing is cached: no session is written to disk,
  the OS keychain or the `cfg connect` session store, and the next command logs in
  again. A failed logout prints a warning that names no cookie or token value and
  does not change the command's result; the session then ends when it expires.
- **Exactly one credential.** `--authenticator` cannot be combined with `--bundle`
  or `--no-bundle`; the command fails before any network call with an error that
  says to provide exactly one credential. `--authenticator` takes the place of the
  active `cfg connect` session and the default admin bundle.
- **No TLS-skip.** The controller's certificate is always verified, against the CA
  certificate stored in the authenticator record or the system pool. `--tls-insecure`
  and `CFGMS_TLS_INSECURE=true` are refused with `--authenticator`.
- **Bound to one controller.** `cfg` connects to the controller URL in the record.
  `--url` or `CFGMS_API_URL` must be omitted or equal to it. A record whose
  controller URL is not `https` is refused.
- **Must be registered.** An authenticator that is not yet registered with its
  controller fails before any network call; the error names `cfg authenticator
  enroll`.
- **RP ID check.** The login is refused, and nothing is signed, when the
  controller's challenge names an RP ID different from the authenticator's.
