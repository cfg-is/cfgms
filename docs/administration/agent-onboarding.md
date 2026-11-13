# Agent Onboarding

How to give an automated agent its own account and software authenticator in one
client tenant, so it can log in and work without a person at a keyboard for every
request. The agent authenticates with a passkey whose private key `cfg` holds (a
*software authenticator*) instead of a browser or a hardware key.

This guide is the end-to-end sequence. The references it builds on own the detail:

- [Agent software authenticator](operator-credentials.md#agent-software-authenticator) —
  `cfg authenticator`, where the key lives, `--authenticator`, presence-protected actions.
- [Software authenticators](../security/SECURITY_CONFIGURATION.md#software-authenticators) —
  the controller policy, its refusals and the audit trail.
- [Tenant management](tenant-management.md#tenant-crossings) — break-glass.
- [Workflow operations](workflows.md#cfg-workflow-publish),
  [Steward management](steward-management.md#passkey-signed-exec) and
  [Module publishing](../operations/module-publishing.md) — what the agent then runs.

The examples use placeholders: `<controller-url>` for the controller's HTTPS URL,
`acme-corp` for the client tenant, `agent-1` for both the account and the local
authenticator name.

## What you get, and what it costs

One root-scope operator crosses into the client tenant **once** (break-glass) to create
the first account and set its flag. After that the agent logs in with its own
authenticator and acts inside its tenant with no further crossing and no operator
present, for the permissions you gave the account.

The setting is deliberately hard to widen. The tenant list lives in `controller.cfg`,
which has no API writer, so a phished administrator cannot enable it. Read
[Limits](#limits) before relying on it.

## Prerequisites

- A root-scope operator session on the controller (`cfg connect`, or `cfg login`),
  able to start a break-glass crossing. See the
  [operator guide](../deployment/cfg-operator-guide.md).
- Write access to `controller.cfg` on the controller host and the ability to restart
  the controller.
- The client tenant exists (`cfg tenant list`). It must not be the root tenant: the
  setting never applies there.
- The CA certificate that signs the controller's TLS certificate, as a PEM file, if it is
  not in the agent host's system pool. The software authenticator never skips TLS
  verification.

## The sequence

Order matters. The account flag (step 4) and the tenant list (step 5) must both be in
place **before** the enrollment link is redeemed (step 7); otherwise registration is
refused.

### 1. Create the authenticator on the agent host

Nothing is sent to the controller; the record is stored encrypted for the agent's user.

```bash
cfg authenticator create agent-1 --url <controller-url> --ca-cert ./controller-ca.pem --label acme-corp-agent
cfg authenticator list
```

`list` shows the record as not registered. The key is bound to this controller's RP ID
and origin. On Linux and macOS it is kept in the encrypted credential store; on Windows
the default is a per-user CNG key (see [Limits](#limits)).

### 2. Cross into the client tenant once (root break-glass)

A root-scope operator cannot act inside a client tenant without a crossing. Break-glass
is the audited, time-boxed way in. The window is fixed at 30 minutes, the tenant is
notified, and the controller may require a second root-scope operator to approve it
(`cfg tenant approve-break-glass`). Run steps 3 and 4 inside the window.

Pick the reason category that fits (`account_recovery`, `security_incident`,
`legal_request` or `billing_dispute`); the justification is recorded in the audit trail.

```bash
cfg tenant break-glass acme-corp --reason account_recovery --justification "First agent account for the tenant, ticket INC-1234"
```

### 3. Create the agent's account

Create it as a tenant-scoped account in the client tenant, holding only the permissions
the agent needs. A root-scope account is never the agent's identity here: see
[Root-scope accounts are excluded](#root-scope-accounts-are-excluded).

```bash
cfg account create --username agent-1 --tenant-id acme-corp \
  --permission steward:list \
  --permission steward:execute-scripts \
  --permission operator-payload:sign \
  --permission workflow:read \
  --permission workflow:list \
  --permission workflow:write \
  --permission workflow:publish \
  --permission account:create \
  --json
```

The command prints a single-use **enrollment link** once. The link is a
[bearer secret](#the-enrollment-link-is-a-bearer-secret): whoever holds it can register
a passkey on the account. Take it from the `--json` output into a file that only the
agent's user can read (`umask 077` first) and do not leave it in terminal scrollback,
shell history, chat or a log.

### 4. Set the account's software-authenticator flag

The flag is the account half of the policy. Setting it needs a root-scope caller, a
presence tap, and the crossing from step 2.

```bash
cfg account software-authenticator agent-1 --enabled=true
```

This only sets the flag. It has no effect until the tenant is listed in
`controller.cfg` (step 5).

### 5. List the tenant in `controller.cfg` and restart the controller

On the controller host, add the client tenant to `webauthn.allow_software_authenticators.tenants`:

```yaml
webauthn:
  allow_software_authenticators:
    tenants:
      - acme-corp
```

- **No `cfg` command writes this list.** It is an operator edit of `controller.cfg`.
  Tenant metadata is writable through the API, so it is deliberately not used.
- **It is read at controller startup.** The config loader has no hot reload, so the
  change needs a controller restart before it applies.
- **The list is an exact match.** A listed tenant does not cover its child tenants; list
  each one.
- An entry that is empty or has leading or trailing whitespace fails controller startup.

### 6. End the crossing

Nothing below needs it. List the crossing and end it early:

```bash
cfg tenant crossings acme-corp
cfg tenant end-crossing acme-corp <crossing-id>
```

### 7. Enroll the agent authenticator

Redeem the link on the agent host. Give it by file or standard input; there is no flag
that takes the link as a value.

```bash
cfg authenticator enroll agent-1 --link-file <link-file>
<secret-reader-command> | cfg authenticator enroll agent-1 --link-stdin
```

Use one of the two. `CFGMS_ENROLLMENT_LINK` is also read when neither flag is given,
but a file or standard input keeps the link out of the process environment. The link's
scheme and host must match the authenticator's origin. On success `cfg authenticator
list` shows the record as registered; delete the link file.

If the controller refuses (`403 SOFTWARE_AUTHENTICATOR_NOT_ALLOWED`), the record stays
unregistered and the link is not consumed. The cause is one of: the tenant is not in the
list or the controller was not restarted, the flag is not set, or the account is one of
the excluded shapes. Fix it and run `enroll` again.

### 8. Run as the agent

Every `cfg` command takes `--authenticator <name>` (or `CFGMS_AUTHENTICATOR`). `cfg`
logs in with the passkey, uses the session for that one command and logs out. Nothing
is cached on disk. The agent does not use `cfg connect` and cannot combine
`--authenticator` with `--bundle`.

```bash
cfg --authenticator agent-1 workflow list --url <controller-url>
cfg --authenticator agent-1 steward list acme-corp/all
cfg --authenticator agent-1 account create --username ops-user-1 --tenant-id acme-corp --permission steward:list
cfg --authenticator agent-1 steward exec acme-corp/web-01 --command "hostname" --shell bash --passkey
cfg --authenticator agent-1 workflow publish nightly-patch 1.2.0
```

- **Tenant users.** `account create` creates accounts in the agent's own tenant, within
  the permissions the controller lets it grant.
- **Sign-and-exec.** `--passkey` signs the command with the authenticator's passkey
  rather than an X.509 signing credential, so the agent needs no signing certificate.
  See [Passkey-signed exec](steward-management.md#passkey-signed-exec).
- **Workflow publish.** The version must already be stored on the controller; `publish`
  does not create or edit it. It signs the version with the passkey and prints the
  content hash; compare it with the hash you expect.

#### Module approval needs a root agent account

`module:approve` requires a fresh proof of presence for each request, and a tenant-scoped
account cannot give one: the presence routes need `webauthn:assert-presence`, which no
tenant account can hold. A tenant-scoped agent that runs `cfg module approve` is stopped
at the presence step (`403 INSUFFICIENT_PERMISSIONS`). Approving modules is the job of
the separate, more tightly limited
[root agent account](operator-credentials.md#agent-software-authenticator), which has its
own setting (`root_agent_accounts`) and its own authenticator:

```bash
cfg --authenticator root-agent-1 module list --status pending
cfg --authenticator root-agent-1 module approve acme-corp/custom-module@1.3.0
```

Review the `SIGNATURES` column of `cfg module list` before approving. See
[Module publishing](../operations/module-publishing.md).

## Limits

State these to whoever approves the setting. The policy governs the CFGMS-shipped
authenticator and makes its use visible. It is not a boundary against someone who already
has enrollment rights.

- **The AAGUID is self-asserted.** The controller requests no attestation, so it records
  whatever AAGUID the client reports. A credential that reports another AAGUID registers
  on the ordinary passkey path and receives no different trust, assurance or exemption.
  Anyone who can redeem an enrollment link can enroll any authenticator; the policy only
  controls where the CFGMS software authenticator is accepted and labels its use in the
  [audit trail](../security/SECURITY_CONFIGURATION.md#audit-trail-for-software-authenticators).
- **On Linux and macOS the key is encrypted at rest but not non-exportable.** The
  encryption key is derived from values any process running as the same user can read, so
  code running as the agent's user can recover the key. On Windows the default per-user
  CNG key is non-exportable and, where a TPM is present, never leaves it; neither
  provider stops a process running as the same user from asking it to sign. Treat the
  authenticator as a credential of the agent's user and protect the agent host
  accordingly.
- **The signature counter is always 0.** A software authenticator keeps no counter, so
  the controller cannot use counter regression to detect a cloned key.

### The enrollment link is a bearer secret

The link registers a passkey on the account without any other proof. Hand it over by
file or standard input, never argv, chat or logs. `cfg authenticator enroll` never
prints, logs or stores it. It is single-use and a refused registration does not consume
it, so a leaked link that has not been redeemed is a live credential. Revoke it with
`POST /api/v1/accounts/<username>/enrollment-link/revoke` (permission
`account:revoke-enrollment-link`; no `cfg` command wraps it) and issue a new one.

### Root-scope accounts are excluded

The tenant list never applies to a root-scope account, an account with an empty tenant or
an account in the root tenant. Registration for those is refused whatever the list or the
flag say. A root-scope account is judged by the separate root agent rules (own setting,
limited permission set, no bound admin certificate, software credentials only); see
[Root agent accounts](../security/SECURITY_CONFIGURATION.md#root-agent-accounts).

### Turning it off

Removing the tenant from the list (and restarting the controller), or clearing the flag,
makes the account's software credentials and sessions inert at the next request. Web and
CLI-login sessions that rest on them end, and a workflow publication they signed stops
verifying. The stored credential is not deleted and works again if the policy is turned
back on. To remove it for good:

```bash
cfg account software-authenticator agent-1 --enabled=false
cfg webauthn revoke <credential-id> --username agent-1
cfg authenticator delete agent-1
```

Clearing the flag needs a presence tap; a tenant administrator may do it for an account in
their tenant.

## Verify

After step 7, check that the agent can log in and that the policy is enforced:

```bash
cfg authenticator list
cfg --authenticator agent-1 workflow list --url <controller-url>
```

Then confirm denial: remove the tenant from `controller.cfg`, restart the controller, and
the second command fails at its next request. The refusal is audited with the reason
`software_authenticator_policy`.
