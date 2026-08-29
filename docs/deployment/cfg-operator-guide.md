# cfg Operator Guide: Setup to Reconnect

This guide walks through the complete operator workflow for the `cfg` CLI — from
installation through first connect, daily reconnect, checking the active session,
and disconnect — and explains the zero-standing-privilege session model that
governs every admin interaction with the controller.

**Three ways to obtain a credential.** `cfg login` — a browser passkey assertion —
is the ordinary way an operator obtains a credential, and is the path described
by "Reconnecting" and everything after it in this guide. The admin bundle
described in "First Connect" below exists for exactly one moment: the very
first credential on a controller that has no account yet to log in against.
`controller bootstrap-admin` generates that bundle's keypair itself and hands
you both halves in a file — the one CFGMS credential whose private key the
controller ever holds. It administers the controller, and it cannot approve a
credential enrolment or renew itself: both require a fresh passkey presence
assertion, which a bootstrap certificate can never obtain. It is *intended* also
to be unable to authorise code execution on a managed endpoint (see
[ADR-021 Amendment 5](../architecture/decisions/021-identity-assurance-levels.md));
read the gap note below before relying on that. The third path, "Headless
Enrolment" below, is for a machine that cannot open a browser: it still needs
an administrator who already holds a credential to mint it a token, so it is
not a second bootstrap route — only `bootstrap-admin` creates the very first
credential on a controller. Every credential after the first one should come
from `cfg login` or headless enrolment, not another bundle.

> **[GAP: the bundle's confinement against endpoint code execution is not yet
> enforced — see Epic #3711, Story #3696. Signer verification on both the steward
> (`features/steward/commands/execute_script.go`) and the controller
> (`features/controller/api/handlers_runs.go`) currently accepts any
> admin-marked certificate and does not require the payload-signing marker, so a
> bundle **can** today authorise code execution on a managed endpoint. Handle the
> bundle file as a credential that can run code across your fleet — protect it
> like a root SSH key, and revoke it if it is ever copied or exposed.]**

## Prerequisites

- A CFGMS controller is running and reachable over HTTPS.
- The controller has been initialised (`controller --init`) and the admin bundle
  has been written to the platform-default path or another location you know.
  The bundle file contains your mTLS client certificate, private key, and the
  controller CA — all inline in a single YAML file.
- `cfg` CLI is installed. See the [cfg Install Guide](cfg-install.md).

## 1. Installing `cfg`

See [cfg-install.md](cfg-install.md) for the full install procedure. The short
form:

**Linux/macOS:**
```bash
make build-cli && sudo bash scripts/install-cfg.sh
cfg version
```

**Windows:**
```
make build-cli && make install-cfg
cfg version
```

## 2. First Connect (Bootstrap Bundle — One Time Only)

The first time you connect from a workstation — before any account exists on
the controller — you import the bootstrap admin bundle and register the
connection locally. This is the bootstrap exception, not the ordinary path;
see the note at the top of this guide.

```bash
cfg connect --bundle /etc/cfgms/admin.bundle.yaml --url https://controller.acme-corp.example:9443
```

What this does:

1. Reads and validates the bundle file (mTLS cert + key + CA).
2. Registers a named connection in the local connection registry — by default
   the name is derived from the URL hostname (`controller.acme-corp.example`).
   Override with `--name <name>` if you prefer a shorter alias.
3. Encrypts the bundle credential and stores it in the OS-native secret store
   (Windows Credential Manager, macOS Keychain, Linux Secret Service or
   kernel keyring). The bundle is never written to a plain file after this step.
4. Authenticates with the controller using mTLS and opens a short-lived session.
5. Stores the resulting session token in the OS-native secret store — not on
   disk in any file.

**Successful output:**
```
Connected as "controller.acme-corp.example" (expires 2026-06-29T16:00:00Z)
```

The session is now active. All subsequent `cfg` subcommands in this shell will
use the stored session token automatically — you do not need to pass `--bundle`
to individual commands.

### Custom connection name

```bash
cfg connect --bundle /etc/cfgms/admin.bundle.yaml \
            --url https://controller.acme-corp.example:9443 \
            --name acme-prod
```

### Where the connection registry is stored

Non-secret connection metadata (name, URL, admin identity, last used) is
persisted in a plain JSON file. No credential or token material is ever written
here.

| Platform | Path |
|----------|------|
| Linux    | `$XDG_CONFIG_HOME/cfgms/connections.json` (default: `~/.config/cfgms/connections.json`) |
| macOS    | `~/Library/Application Support/cfgms/connections.json` |
| Windows  | `%APPDATA%\cfgms\connections.json` |

## 3. Browser Login (`cfg login`) — the Ordinary Way

This is how every operator after the very first one obtains a credential — no
bundle file, no private key transfer, no shell on the controller. Run it from
any workstation with a browser, whether or not the controller is reachable
from that same machine:

```bash
cfg login --url https://controller.acme-corp.example:9443
```

The command prints a short code and an approval URL, and opens that URL in
your default browser (pass `--no-browser` to only print it):

```
Code: AB3D-7FQK
Approve this login by visiting: https://controller.acme-corp.example:9443/login/confirm?request_id=cli-login-...
Expires: 2026-06-29T16:05:00Z
```

Complete a passkey login in the browser, confirm the same code shown there
against what this command printed, and the command ends holding a session:

```
Logged in as "controller.acme-corp.example" (expires 2026-06-30T00:05:00Z)
```

**The code comparison is the actual security check** — the same principle as
the fingerprint comparison in "Headless Enrolment" below. The token that
approval mints never travels through the browser to this command: it is
collected only over this command's own already-pinned TLS connection to the
controller, using a verifier this command generated locally and never
disclosed until that collection call. `cfg login` never opens a local
listening socket.

**The browser and the command do not need to be the same machine.** If a
browser cannot be opened automatically here — an SSH session, a headless
workstation — the command prints a notice and you copy the URL to a browser
anywhere else you can complete the passkey ceremony.

**A tenant-scoped account needs the `session:create` permission** (granted
like any other RBAC permission — see [cfg account](../development/commands-reference.md#cfg-account--account-lifecycle-and-certificate-credentials-issue-3582))
before it can log in this way. A root-scoped account needs nothing extra: the
session `cfg login` mints carries whatever scope the approving account
already has, the same way `POST /api/v1/sessions` always has.

From here on this connection behaves exactly like one that ran
`cfg connect --bundle` — see "Reconnecting", "Checking the Active Session",
and the rest of this guide — except that there is no bundle to later
reconnect from with `cfg connect <name>`; run `cfg login` again for a fresh
session against the same controller.

If a login is denied in the browser, times out before a decision arrives, or
you interrupt the waiting command with Ctrl-C, the command exits with a
distinct message (see the table in [the command
reference](../development/commands-reference.md#cfg-login--browser-authenticated-cli-login-issue-3721))
and leaves no session behind. A timeout names `cfg credential enrol` (below)
as the headless alternative.

## 4. Headless Enrolment (No Browser, No Bundle)

For a machine that cannot open a browser at all — headless, no display, `cfg
login` (above) is not an option — and does not hold a copy of the bootstrap
bundle, an administrator can mint a short-lived, single-use enrolment token
from their own already-connected
workstation and hand it to that machine out of band. See [Enrolment Tokens and
the Pending Credential-Request Queue](../development/commands-reference.md#enrolment-tokens-and-the-pending-credential-request-queue-issue-3717)
for the full command and flag reference; this section walks the happy path
end to end.

**On the administrator's own workstation** (already connected via `cfg connect`):

```bash
cfg credential enrolment-token mint --tenant-id root/msp-a/client-1
```

```
Enrolment token minted (id: et-..., tenant: root/msp-a/client-1, expires: 2026-06-29T17:00:00Z)
Token (shown once, cannot be retrieved again): 3f9a...c821
Hand this value to the enrolling machine out of band, then run there:
  cfg credential enrol --token <token> --url <controller-url>
```

Copy the token value out of band — read over a phone call, a chat message you
trust, or pasted directly into the target machine's terminal. It is a bearer
credential for the next hour: whoever holds it can lodge exactly one signing
request against it, so treat it the way you would a one-time password.

**On the headless machine**, with `cfg` installed but no credential yet:

```bash
cfg credential enrol --token 3f9a...c821 --url https://controller.acme-corp.example:9443
```

```
Credential request lodged (id: cr-...)
Public key fingerprint: AB12-CD34-EF56-7890
Compare this fingerprint with the administrator before they approve the request.
Approval endpoint (an administrator lists and approves pending requests here): https://controller.acme-corp.example:9443/api/v1/credential-requests
Expires: 2026-06-29T17:00:00Z
Waiting for administrator approval...
```

**Fingerprint comparison — do this before approving.** Read the printed
`Public key fingerprint` value back to the administrator (voice, a screenshot,
whatever channel you already trust for the token itself). The administrator
lists pending requests — today via `GET /api/v1/credential-requests`; a `cfg`
list/approve command is a later story in this epic — and confirms the
`public_key_fingerprint_short` shown there matches what the headless machine
printed, *before* approving. This comparison is the actual security boundary
of headless enrolment: the token proves someone holds the out-of-band secret,
not which machine lodged the request against it. Approving without comparing
the fingerprint is a bare row click on a credential about to be marked
admin-capable.

Once approved, the waiting `cfg credential enrol` command collects the signed
certificate on its next poll, registers the connection, exchanges the
certificate for a session, and finishes:

```
Enrolled as "controller.acme-corp.example" (expires 2026-06-29T17:00:00Z)
```

From here on the headless machine behaves exactly like one that ran
`cfg connect --bundle` — see "Reconnecting", "Checking the Active Session",
and the rest of this guide.

**If the administrator denies the request, it expires before a decision
arrives, or the operator interrupts the waiting command with Ctrl-C**, the
command exits with a distinct message (see the table in [the command
reference](../development/commands-reference.md#cfg-credential-enrol-issue-3720))
and leaves no credential file anywhere on this machine — safe to simply mint a
fresh token and re-run `cfg credential enrol`.

## 5. Containing a Compromised Enrolment

If an enrolment token or a headless-enrolled host is believed compromised —
the token leaked before the intended machine used it, or a device enrolled via
"Headless Enrolment" above needs its credential pulled — `cfg credential`
carries the containment commands to shut it down. See [Revoking and
Containing Enrolment-Issued Credentials](../development/commands-reference.md#revoking-and-containing-enrolment-issued-credentials-issue-3725)
for the full command and flag reference; this section is the procedure to
follow when you suspect a problem, on the administrator's own already-connected
workstation.

**The token itself was never used, or you want to stop it from being used
again.** If you minted a token and it has not yet produced a credential (or
you no longer trust the channel it was handed over), revoke the token
directly:

```bash
cfg credential enrolment-token revoke <token-id>
```

**A credential was already issued from the token (or you are not sure), and
you want every trace of it gone.** Revoke every certificate issued from the
token and block any of its requests still sitting in `pending` or `approved`
from ever producing one, in a single action:

```bash
cfg credential revoke-by-token <token-id>
```

This reports one outcome per affected request (`contained` /
`already_contained` / `error`) rather than an all-or-nothing result — read
every line before treating the containment as complete. If a certificate
proves too far along to unbind cleanly (an `error` outcome), re-run the same
command; the underlying revoke and unbind steps are both safe to retry.

**A request was approved but the machine never collected it** — the
administrator approved, but the headless machine's `cfg credential enrol`
never finished (network trouble, the operator walked away, or the request now
looks suspicious). Cancel it so it can never later be collected:

```bash
cfg credential cancel-request <request-id>
```

This does not revoke a certificate — approval signs nothing, so there is
nothing yet to revoke. It is a state transition that permanently blocks
collection. If a certificate has already been collected, use
`revoke-by-token` (above) or the orphaned-certificate commands (below)
instead — `cancel-request` refuses with a distinct error in that case.

**You suspect a certificate exists with no account behind it** — a controller
crash between signing and account-binding during collect leaves exactly this
state, closed automatically within a few minutes by a background sweep, but
you do not have to wait:

```bash
cfg credential list-orphaned
cfg credential revoke-orphaned <serial>
```

`list-orphaned` only reads; nothing is revoked until you separately run
`revoke-orphaned` against a serial it printed.

All of the mutating commands above are destructive and prompt for
confirmation — pass `--force` to skip the prompt in a script.

## 6. Reconnecting in a Fresh Shell

When you open a new terminal, or after your session has expired, reconnect by
name:

```bash
cfg connect acme-prod
```

If you have only one connection registered you can omit the name:

```bash
cfg connect
```

If you have more than one connection and omit the name, `cfg` presents a
numbered selection prompt:

```
Multiple connections available:
  1) acme-prod (https://controller.acme-corp.example:9443)
  2) lab (https://lab-controller.example:9443)
Select number:
```

On reconnect `cfg` decrypts the stored bundle using the machine-bound key
(no interactive passphrase), authenticates with the controller over mTLS,
and stores the new session token. The bundle itself is never re-imported.

## 7. Checking the Active Session

```bash
cfg connections current
```

Output when a session is active:

```
Connection: acme-prod
URL:        https://controller.acme-corp.example:9443
Session ID: sess-...
Expires:    2026-06-29T16:00:00Z
```

Output when no session is active (or the token has passed its absolute expiry):

```
no active session
```

## 8. Listing Registered Connections

```bash
cfg connections list
```

Tabular output:

```
NAME        URL                                         IDENTITY            LAST USED
acme-prod   https://controller.acme-corp.example:9443  admin@acme-corp     2026-06-29T08:00:00Z
lab         https://lab-controller.example:9443         admin@acme-corp     2026-06-27T14:30:00Z
```

For machine-parseable output:

```bash
cfg connections list --json
```

## 9. Disconnecting

```bash
cfg disconnect
```

What this does:

1. Revokes the active session on the controller (`DELETE /api/v1/sessions/{id}`).
2. Removes the session token from the OS-native secret store.
3. Locks the stored credential (no-op for machine-bound unlock; the encrypted
   bundle remains in the secret store for the next `cfg connect`).

Output:

```
Disconnected from "acme-prod".
```

If no session is active, `cfg disconnect` exits cleanly with:

```
No active session.
```

After disconnecting, any `cfg` subcommand that requires authentication will
return an error until you run `cfg connect` again.

## 10. One-Shot Use Without a Session

The session model is the default for interactive operator use. For scripted or
CI-style automation where storing a session is undesirable, every `cfg`
subcommand accepts a one-shot `--bundle` flag that bypasses the session entirely:

```bash
# Provide the bundle file directly on each invocation
cfg config list --bundle /etc/cfgms/admin.bundle.yaml

# Equivalently, via environment variable (e.g. in CI)
CFGMS_ADMIN_BUNDLE=/etc/cfgms/admin.bundle.yaml cfg config list --api-url https://controller.acme-corp.example:9443
```

`--bundle` / `CFGMS_ADMIN_BUNDLE` take precedence over any stored session token.
Use the session model for interactive operator access; use the one-shot bundle
for unattended scripts. `cfg` accepts only these two credentials — an admin mTLS
bundle or a session from `cfg connect` — never a bare API key (Issue #3688):
automation that used to export `CFGMS_API_KEY` should export `CFGMS_ADMIN_BUNDLE`
instead, as shown above.

## 11. Keeping an Unattended Host's Credential Current

A bundle used the one-shot way (§10) — on a CI runner, a headless automation host,
or anywhere else nobody is present to run `cfg connect` — still carries a
certificate with an expiry date. `cfg credential renew` is how that host keeps its
credential alive without a human: it presents the certificate it already holds
over mutual TLS to prove who it is, generates a brand-new keypair locally, and asks
the controller for a new certificate bound to the exact same account. Nothing
about the account is chosen by the request — the controller derives it entirely
from the certificate presented.

```bash
# Run periodically (cron, a systemd timer, or equivalent) against the bundle
# a headless host authenticates with:
cfg credential renew --unattended --bundle /etc/cfgms/admin.bundle.yaml
```

`--unattended` is what makes this safe to schedule frequently: it checks the
bundle certificate's expiry itself before contacting the controller, and exits `0`
having done nothing when renewal is not yet due. Point a timer at it daily, or even
hourly, and it stays quiet until the certificate is actually within its renewal
window (30 days before expiry) — then it renews, and the bundle file is updated
in place with the new certificate, the new private key, and the CA, ready for the
very next `cfg` invocation.

**The off switch is the bound account — there is no expiry-count ceiling.** A
renewed credential can renew again indefinitely; nothing here ever forces
re-enrolment on its own. To take an unattended host's access away, disable the
account it authenticates as (the same account `cfg credential renew` has been
quietly renewing into all along):

```bash
cfg account update <username> --disabled=true
```

A disabled account's certificate stops authenticating immediately — not just to
renewal, to everything — so the very next scheduled renewal attempt fails, and the
host cannot reach the controller again until an administrator re-enables the
account or issues it a fresh credential through a new enrolment token.

**If a scheduled renewal starts failing**, the certificate's own expiry is the
first thing to check:

- Still has time left, but outside the 30-day window: not a problem — a later
  scheduled run will pick it up once it is due.
- Already expired, or the account was disabled: `cfg credential renew` cannot
  recover this credential — renewal only extends one that is still alive. An
  administrator must mint a fresh enrolment token and the host must re-enrol from
  the beginning (see the enrolment-token flow in
  [Adding Operators](single-controller/walkthrough.md#adding-operators), or the
  `POST /api/v1/enrolment-tokens` reference in
  [Commands Reference](../development/commands-reference.md#renewing-an-issued-credential--cfg-credential-renew-issue-3724)).
- Anything else (a network blip, the controller mid-failover): safe to leave
  alone — the old certificate is never touched until a new one is confirmed
  bound, so a failed or interrupted renewal never costs the host its existing,
  still-working credential.

See [Commands Reference — cfg credential renew](../development/commands-reference.md#renewing-an-issued-credential--cfg-credential-renew-issue-3724)
for the full flag reference and the exact controller-side contract.

## 12. The Zero-Standing-Privilege Model

CFGMS admin sessions follow a zero-standing-privilege design: no long-lived
credential is ever exchanged between operator and controller. Each session is
short-lived, bound to one machine, and revocable server-side at any time.

### What "zero standing privilege" means in practice

| Concept | Implementation |
|---------|---------------|
| No persistent admin token | The mTLS credential (the bundle) never leaves the OS secret store after import. The controller never sees the raw private key outside of a TLS handshake. |
| Explicit connect per session | Running `cfg connect` is required at the start of each working session. A closed shell, a reboot, or a session expiry all require re-authentication. |
| Short-lived tokens | The controller issues a bearer token valid for a sliding idle window. The token is replaced on every successful API call (rolling-token model). |
| Machine-bound credential | The encrypted bundle is bound to the machine's secret store. Copying the secret-store entry to another machine does not produce a usable credential. |
| Controller-side revocation | The controller can revoke any session immediately (`DELETE /api/v1/sessions/{id}`). Revocation takes effect with zero stale window — the next request carrying the revoked token is rejected. |

### Session token lifecycle

```
cfg connect
    │
    ▼
Controller issues session token (expires at idle TTL or absolute cap)
    │
    ▼
Each cfg subcommand sends: Authorization: Bearer <token>
    │
    ├── Controller validates token
    ├── Resets idle TTL
    └── Returns new token in X-Session-Token header
              │
              ▼
        cfg stores new token (replaces old token in OS secret store)
              │
              └── Old token valid for grace window, then rejected
    │
    ▼
cfg disconnect  OR  session expires
    │
    ▼
Controller revokes session; token removed from OS secret store
```

### Token lifecycle parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Idle TTL | 15 minutes | Session expires if no command is issued within this window. |
| Absolute cap | 8 hours | Hard ceiling from the original connect, regardless of activity. |
| Grace window | 30 seconds | The prior token remains valid this long after a renewal, so concurrent or pipelined commands do not race on the token rotation. |

### What is stored where

| Item | Where | Secret? |
|------|-------|---------|
| mTLS bundle (cert + key + CA) | OS-native secret store (encrypted at rest) | Yes — never written to a plain file after `cfg connect --bundle` |
| Session bearer token | OS-native secret store | Yes — never written to a plain file |
| Connection metadata (name, URL, identity) | `connections.json` in user config dir | No — no credential material |

The OS-native secret stores in use:

| Platform | Store |
|----------|-------|
| Windows | Windows Credential Manager |
| macOS | macOS Keychain |
| Linux | Secret Service API (e.g., GNOME Keyring, KWallet) or kernel keyring |

### Why the controller only stores a token hash

The controller stores `SHA-256(token)`, not the token value itself. If the
controller's database is exfiltrated, the raw token values are not recoverable.
Token values are also sanitised from all controller log output.

## Quick Reference

| Task | Command |
|------|---------|
| Log in via browser passkey (operator, the ordinary way) | `cfg login --url <url>` |
| First connect (import bootstrap bundle — one time only, before any account exists) | `cfg connect --bundle <path> --url <url>` |
| Reconnect by name | `cfg connect <name>` |
| Reconnect (single connection) | `cfg connect` |
| Mint an enrolment token (administrator) | `cfg credential enrolment-token mint --tenant-id <id>` |
| Revoke an unspent enrolment token (administrator) | `cfg credential enrolment-token revoke <id>` |
| Enrol a headless machine (operator, on that machine) | `cfg credential enrol --token <token> --url <url>` |
| Revoke every credential issued from a token (administrator) | `cfg credential revoke-by-token <token-id>` |
| Cancel an approved-but-uncollected request (administrator) | `cfg credential cancel-request <request-id>` |
| List unbound enrolment-flow certificates (administrator) | `cfg credential list-orphaned` |
| Revoke a listed unbound certificate (administrator) | `cfg credential revoke-orphaned <serial>` |
| Check active session | `cfg connections current` |
| List all connections | `cfg connections list` |
| Disconnect | `cfg disconnect` |

## Related Docs

- [cfg Install Guide](cfg-install.md) — install the CLI binary
- [Single Controller Deployment](single-controller/walkthrough.md) — initial controller setup
- [Controller Operating Model](../architecture/controller-operating-model.md) — Admin Session Model internals
- [Steward Refresh Management](steward-refresh-management.md) — managing offline steward re-registration
- [Commands Reference: Enrolment Tokens and the Pending Credential-Request Queue](../development/commands-reference.md#enrolment-tokens-and-the-pending-credential-request-queue-issue-3717) — full flag and REST reference for headless enrolment
- [Commands Reference: Revoking and Containing Enrolment-Issued Credentials](../development/commands-reference.md#revoking-and-containing-enrolment-issued-credentials-issue-3725) — full flag and REST reference for containment
