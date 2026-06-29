# cfg Operator Guide: Setup to Reconnect

This guide walks through the complete operator workflow for the `cfg` CLI — from
installation through first connect, daily reconnect, checking the active session,
and disconnect — and explains the zero-standing-privilege session model that
governs every admin interaction with the controller.

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

## 2. First Connect (Bundle Import)

The first time you connect from a workstation you import the admin bundle and
register the connection locally.

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
or `--api-key` to individual commands.

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

## 3. Reconnecting in a Fresh Shell

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

## 4. Checking the Active Session

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

## 5. Listing Registered Connections

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

## 6. Disconnecting

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

## 7. One-Shot Use Without a Session

The session model is the default for interactive operator use. For scripted or
CI-style automation where storing a session is undesirable, every `cfg`
subcommand accepts one-shot credential flags that bypass the session entirely:

```bash
# Provide the bundle file directly on each invocation
cfg config list --bundle /etc/cfgms/admin.bundle.yaml

# Provide an API key and URL on each invocation
cfg config list --api-url https://controller.acme-corp.example:9443 \
                --api-key "$CFGMS_API_KEY"
```

These flags take precedence over any stored session token. Use the session model
for interactive operator access; use one-shot flags for unattended scripts.

## 8. The Zero-Standing-Privilege Model

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
| First connect (import bundle) | `cfg connect --bundle <path> --url <url>` |
| Reconnect by name | `cfg connect <name>` |
| Reconnect (single connection) | `cfg connect` |
| Check active session | `cfg connections current` |
| List all connections | `cfg connections list` |
| Disconnect | `cfg disconnect` |

## Related Docs

- [cfg Install Guide](cfg-install.md) — install the CLI binary
- [Single Controller Deployment](single-controller/walkthrough.md) — initial controller setup
- [Controller Operating Model](../architecture/controller-operating-model.md) — Admin Session Model internals
- [Steward Refresh Management](steward-refresh-management.md) — managing offline steward re-registration
