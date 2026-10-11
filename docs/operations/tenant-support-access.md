# Tenant Support Access, Break-Glass and Account Recovery

Operator guide to how root staff reach an MSP's data: MSP-issued support-access grants, the break-glass
elevation, and the procedure for recovering an MSP whose administrators are locked out. It implements
[ADR-025](../architecture/decisions/025-tenant-access-boundary.md) Decisions 2 and 4 and Amendment 8.

Examples use the placeholder tenant `msp-a`, an MSP, and the placeholder operators `alice` (root support) and
`bob` (a second root operator). Addresses use `example.com`.

**Who this is for**

| You are | Read |
|---------|------|
| An MSP administrator | [MSP workflow: grants](#2-msp-workflow-grants), [Auditing](#6-auditing) |
| A root support operator | [Root operator workflow](#3-root-operator-workflow), [Account recovery](#4-account-recovery-break-glass-procedure) |
| A controller operator | [Configuration](#5-configuration) |

## 1. The model in one page

A root operator reads an MSP's records only through a **crossing**. There are two kinds:

- **Support-access grant** (primary). An MSP administrator turns it on from the MSP's own console. It lasts a
  duration the MSP chooses, up to 24 hours.
- **Break-glass** (emergency). A root operator invokes it without the MSP, with a reason category and a
  written justification. It lasts 30 minutes. The MSP is told at once.

Without a crossing, a root operator:

- sees **MSP tenants only**. The name and path of an MSP's client tenants never appear in any API response or
  console screen shown to root. The only per-client handle root holds is an opaque label in the billing facts
  below;
- reads the always-visible set in the table below, and nothing else;
- gets a **crossing challenge** on a read of anything inside an MSP, and finds that a list contains no rows
  from inside an MSP.

### What is always visible

Root's own tenant records and the identity data for root's own principals (accounts, certificates and
registrations) need no crossing. For MSP tenants, exactly these categories are visible without one:

| Category | Source |
|----------|--------|
| Authentication failures, account lockouts and suspicious-login patterns on MSP administrator accounts | ADR-025 Decision 4 |
| The meta-log of crossings: grant created, used, revoked or expired; break-glass invoked, approved, ended or expired | Decision 4 |
| Abuse and resource-exhaustion signals: rate-limit trips, unusual API volume and similar platform-health indicators | Decision 4 |
| Billing and subscription state changes, including non-payment flags | Decision 4 |
| System and platform logs and metrics needed to run the deployment | Decision 4 |
| For each MSP: name and tenant ID, tech count, endpoint count and anonymized platform metrics; per-client endpoint and tech counts under opaque labels only | Amendment 6 (A6.1, A6.2) |

Not visible without a crossing: an MSP's stewards, accounts, certificates, registrations, configuration,
jobs, runs, rollouts, cases, entity graph, ordinary audit entries and every record owned by a client tenant.
The controller currently audits no rate-limit or resource-exhaustion signals, so that row is policy rather
than a populated feed. Growing the set is a founder decision.

### The crossing prompt

When a root operator opens something inside an MSP in the web console, a dialog titled **The MSP controls
access to this tenant** appears. It names the MSP, never a client tenant, and offers two paths:

1. **Ask the MSP for support access** (recommended). Nothing to fill in. Access opens by itself once the MSP
   turns it on.
2. **Break-glass**, "only in an emergency". A **Reason** list and a **Justification** box (10-1000
   characters). The dialog states that the MSP is told right away.

On the API the same state is a `401` with `WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="tenant-crossing"`
and a body naming the break-glass endpoint and the four reason categories. See
[REST API: Tenant Scope](../api/rest-api.md#tenant-scope).

## 2. MSP workflow: grants

An MSP administrator holds the grant, list and end permissions for the MSP's own tenant. A grant:

- takes a **duration only**, from 1 minute to 24 hours;
- **names no person**. While active, it admits every root-scoped support operator to the MSP and its
  descendants;
- is **audited by person**. The first read by each root operator under a grant writes a
  `tenant.crossing_grant_used` entry that names that operator;
- cannot be revoked by root. Only the MSP ends it, or it expires.

### Issue a grant

**Console.** Open **Support access**. Under **Give support access**, choose a duration (1 h, 4 h, 8 h or
24 h) and confirm. The page confirms "Support access given" and the grant appears in the list as
**Support access**, labelled "All root support".

**CLI.**

```bash
cfg tenant grant msp-a --duration 90m
```

`--duration` is a Go duration in whole minutes, between `1m` and `24h`. The command asks for confirmation
(skip with `--yes`) and for presence verification (step-up).

**API.**

```bash
curl -s -X POST https://<controller>/api/v1/tenants/msp-a/access-grants \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"duration_minutes": 90}'
```

A body with any other field is refused. `principal_id` returns `400 GRANT_PRINCIPAL_NOT_ALLOWED`; a duration
outside 1-1440 returns `400 INVALID_DURATION`. Grants cannot be issued by a root-scoped caller
(`403 ROOT_SCOPED_CANNOT_GRANT`).

### See active and past crossings, and end one

The **Support access** page lists the MSP's grants and break-glass elevations with kind, reason, start,
expiry and status, with a filter. Each row has an action:

| Row | Action | Effect |
|-----|--------|--------|
| Grant | **Revoke** | Root loses access to the MSP now |
| Break-glass, active | **End elevation** | Ends the elevation now |
| Break-glass, pending approval | **Deny** | Ends the pending request without opening access |

A break-glass elevation also appears as a banner at the top of the console and in the notification bell
while it is active, with a link to the Support access page.

CLI:

```bash
cfg tenant crossings msp-a                    # active crossings only
cfg tenant crossings msp-a --json             # includes expired, ended and pending records
cfg tenant end-crossing msp-a <crossing-id>   # revoke a grant or end a break-glass
```

API: `GET /api/v1/tenants/{id}/access-grants` lists every record (active, expired, pending and revoked);
`DELETE /api/v1/tenants/{id}/access-grants/{crossing_id}` ends one; `GET /api/v1/tenant-crossings/active`
is the live feed behind the banner. Ending a crossing that has already ended or expired is idempotent.

### Maintain the administrator contacts

Break-glass email goes to the MSP's **administrator contacts**. In the console, **Support access** shows the
**Emergency contacts** panel: add or remove addresses and save.

```bash
curl -s -X PUT https://<controller>/api/v1/tenants/msp-a/admin-contacts \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"contacts": ["ops@example.com", "security@example.com"]}'
```

At most 20 bare addresses (no display names); an empty list clears them. Only the MSP edits the list: a
root-scoped caller gets `403 ROOT_SCOPED_CANNOT_EDIT_CONTACTS`, even during a crossing. Keep at least two
addresses, held by people who are not the same administrators who could be locked out. Every change is
audited as `tenant.admin_contacts_updated`; the addresses are not written to the audit detail.

## 3. Root operator workflow

### Ask for a grant first

The grant is the normal way in. Ask an MSP administrator, by the channel you already use with the MSP, to turn
on support access for a stated duration. When it is on, your next read succeeds with no further step. Your
first read under the grant is recorded in the MSP's audit log under your name.

### When to use break-glass

Only when the MSP cannot grant access in time. Pick the one category that fits:

| Category | Use it when |
|----------|-------------|
| `account_recovery` | The MSP has lost access to its own administrator accounts and cannot issue a grant |
| `security_incident` | An active security incident needs root to look inside the tenant now |
| `legal_request` | A legal obligation requires access |
| `billing_dispute` | Records needed to settle a billing dispute are behind the boundary |

All four categories are equally loud. Once the MSP has working administrators again, further support goes
through a grant, not a second break-glass.

### Write the justification

The justification is 10-1000 characters of plain text and is shown to the MSP in its console and audit log.
Include:

- the ticket or case reference;
- the specific action you will take, and why the MSP cannot grant access;
- for `account_recovery`, who asked, through which channel, and how their identity was confirmed.

Never put in secrets, credentials, enrollment links or personal data.

Good:

```text
INC-4821: msp-a lost all administrator passkeys. Request came by phone from the MSP owner, identity
confirmed by call-back to the number on the contract. Resetting credentials for one administrator account.
```

Insufficient (accepted by the 10-character minimum, but it gives the MSP nothing to check and will be
questioned in review):

```text
need access to fix stuff
```

### Invoke, work, end

**Console.** In the crossing prompt choose a reason, write the justification and submit. The elevation opens
for 30 minutes from activation.

**CLI.**

```bash
cfg tenant break-glass msp-a --reason security_incident \
  --justification "INC-4821: active credential stuffing against msp-a admin logins, reviewing session records"
```

Both flags are required. The command prints what it will do and asks for confirmation (`--yes` skips it; with
no terminal and no `--yes` it refuses), then asks for presence verification. It prints the crossing ID and
expiry. There is no duration flag.

**API.** `POST /api/v1/tenants/{id}/break-glass` with `{"reason_category": "...", "justification": "..."}`.
`403 NOT_ROOT_SCOPED` and `403 ROOT_TENANT_NOT_CROSSABLE` are the refusals specific to this endpoint.

**Ending early.** A break-glass is personal: you can end only your own. Use **End session** on the console
banner, or:

```bash
cfg tenant crossings msp-a
cfg tenant end-crossing msp-a <crossing-id>
```

An MSP administrator can also end it. It otherwise expires after 30 minutes and cannot be extended; invoke
again, with a fresh justification, if more time is needed.

### What the second-approver setting changes

When `tenant_admin.break_glass_requires_second_approver` is `true`, an invocation is created **pending** and
admits nothing. The console shows "Waiting for a second approver". A different root-scoped operator approves
it:

```bash
cfg tenant approve-break-glass msp-a <crossing-id>
```

The invoker cannot approve their own request (`403 SAME_APPROVER`), and a crossing that is not pending
returns `409 NOT_PENDING`. The 30-minute window starts at approval, and the MSP is notified at approval, not
at the request. A pending request that nobody approves expires after 30 minutes.

## 4. Account-recovery break-glass procedure

Use this when an MSP cannot grant access because none of its administrators can sign in.

### Preconditions

All three must hold before you invoke:

- [ ] The MSP has no available administrator able to issue a grant (every administrator locked out, or no
      passkey and no certificate that works).
- [ ] The requester's identity is verified **out of band**: a call-back to a number held on the contract, not
      to a number or address supplied in the request.
- [ ] A ticket is recorded with who asked, when, by what channel, and how identity was verified.

You need an operator holding `tenant:crossing-break-glass` and the permission to update accounts. If the
second-approver setting is on, a second root operator must be available.

### Procedure

1. **Check the MSP's contacts.** Ask the MSP to confirm the addresses on its administrator contact list, or
   confirm the MSP has none. The MSP is told by three channels (email if configured, console banner, audit).
   If there are no contacts or email is not configured, plan to tell the MSP out of band yourself, in step 6.
2. **Invoke break-glass with the `account_recovery` category.** Reference the ticket and the verification.

   ```bash
   cfg tenant break-glass msp-a --reason account_recovery \
     --justification "TKT-1042: MSP owner requested admin access recovery by phone; identity confirmed by call-back to contract number. Resetting credentials for one administrator."
   ```

   Note the crossing ID the command prints. The window is 30 minutes.
3. **Get approval if required.** If the command prints "Approval pending", the second operator runs:

   ```bash
   cfg tenant approve-break-glass msp-a <crossing-id>
   ```

   Nothing is readable or changeable until this completes.
4. **Confirm the elevation is active.**

   ```bash
   cfg tenant crossings msp-a
   ```

   The table lists the crossing with kind, reason `account_recovery` and an expiry.
5. **Perform the recovery.** Reset the locked-out administrator's credentials with the existing account flow.
   This revokes their passkeys and issues a new single-use enrollment link, valid for 72 hours:

   ```bash
   cfg account list --json            # find the administrator's username
   cfg account update <username> --reset-credentials
   ```

   The command prints an enrollment link once. It is not stored and cannot be shown again. Pass it to the
   administrator over a channel the MSP has confirmed, never in the ticket or the justification. If it goes to
   the wrong person, revoke it with `POST /api/v1/accounts/{username}/enrollment-link/revoke`. Touch only the
   account that was requested.
6. **Verify with the MSP over a second channel.** Ask the administrator, on a different channel from the
   request, to enroll and sign in, and confirm the MSP can now see its **Support access** page and the
   break-glass entry. If no contacts or email were configured, this call is how the MSP first hears about the
   elevation, along with the banner and audit entry they will see on sign-in.
7. **End the elevation.** Do not wait for the 30-minute expiry once the MSP is working.

   ```bash
   cfg tenant end-crossing msp-a <crossing-id>
   cfg tenant crossings msp-a        # confirm: "no active crossings"
   ```

8. **Review the audit trail.** In the root audit log, filter for `tenant.crossing_*` and confirm the sequence
   `tenant.crossing_break_glass_invoked` (or `_requested` then `_approved`),
   `tenant.crossing_break_glass_notified` with its `outcome`, and `tenant.crossing_break_glass_ended`.
   Ask the MSP to confirm the matching entry in its own audit log, with the justification and every action
   taken under the elevation. Record the outcome on the ticket. If `outcome` was `no_contacts`,
   `not_configured` or `failed`, add that the MSP was told out of band, and ask the MSP to add contacts.

## 5. Configuration

### Second approver

`tenant_admin.break_glass_requires_second_approver` in the controller config. Default `false`; read at
startup, so restart after changing it. See [config schema](../reference/config-schema.md#tenant_admin).

```yaml
tenant_admin:
  break_glass_requires_second_approver: true
```

Turn it on when you have at least two root operators who can approve each other, and the cost of a mistaken
or coerced single break-glass outweighs the delay. Leave it off for a one-operator root, or an incident
response model where waiting for a second person is the bigger risk: with it on and only one root operator, a
break-glass can never open.

### Email delivery

Controller-wide, one SMTP configuration, under `notifications.email`. Only the non-secret settings are in the
config file:

```yaml
notifications:
  email:
    host: smtp.acme-corp.example
    port: 587
    from: cfgms@acme-corp.example
    username: mailer
    tls_mode: starttls             # or implicit_tls; there is no plaintext mode
    password_secret_key: notifications.email.password
```

Setting `host` requires `from` and `password_secret_key`. The settings are listed in the
[config schema](../reference/config-schema.md#notifications). The SMTP password is **write-only** through the
credential endpoint. All three endpoints need `notification:configure`, a root-scoped principal and strong
assurance (API keys are refused):

```bash
# store the password; the body is limited to 4 KiB and the password is never returned
curl -s -X PUT https://<controller>/api/v1/notifications/email/credential \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"password": "<smtp-password>"}'

# read the non-secret settings: check "configured" and "credential_present" are both true
curl -s https://<controller>/api/v1/notifications/email -H "Authorization: Bearer <token>"

# send a fixed test message to the configured "from" address (the body must be empty)
curl -s -X POST https://<controller>/api/v1/notifications/email/test -H "Authorization: Bearer <token>"
```

`409 EMAIL_NOT_CONFIGURED` means the settings or the credential are missing. A failed test returns
`delivered: false` with a sanitized `failure_reason`. See [REST API: Email Delivery](../api/rest-api.md#email-delivery).

**An unconfigured email channel does not block break-glass.** The elevation still starts, the console banner
and the audit entries still fire, and the email outcome is recorded as `not_configured`. Configure email
anyway: it is the only channel that reaches an MSP whose administrators are not signed in.

## 6. Auditing

Each crossing event writes **two** entries with the same action name: one in the affected tenant's audit scope
(the MSP sees it, with the justification) and one in root's own audit scope (the meta-log, without the
justification). Root reads the meta-log without a crossing.

| Action | When |
|--------|------|
| `tenant.crossing_grant_created` | An MSP issues a grant |
| `tenant.crossing_grant_used` | A root operator first reads under a grant; names that operator |
| `tenant.crossing_grant_ended` | A grant is revoked |
| `tenant.crossing_grant_expired` | A grant reaches its expiry unrevoked (written by a sweep within about a minute) |
| `tenant.crossing_break_glass_requested` | A break-glass is created pending (second approver on) |
| `tenant.crossing_break_glass_invoked` | A break-glass is created active (second approver off) |
| `tenant.crossing_break_glass_approved` | A second operator approves a pending break-glass |
| `tenant.crossing_break_glass_notified` | The announcement ran; `outcome` is `sent`, `partial`, `failed`, `not_configured` or `no_contacts` |
| `tenant.crossing_break_glass_ended` | A break-glass is ended early |
| `tenant.crossing_break_glass_expired` | A break-glass expires, including a pending one that was never approved |
| `tenant.admin_contacts_updated` | The MSP changes its contact list |

Query with `GET /api/v1/audit/entries`; the carve-out rules for what root sees are in
[REST API: Audit entries read by a root-scoped caller](../api/rest-api.md#audit-entries-read-by-a-root-scoped-caller).
An MSP administrator sees its own tenant's entries, including every action a root operator took under a
crossing while it lasted.

## 7. Troubleshooting

| Symptom | Cause and action |
|---------|------------------|
| A read returns `401` with `tenant_crossing_required`, or the crossing prompt opens | There is no active crossing for that MSP. Ask the MSP for a grant, or break-glass if you meet the criteria in [section 3](#when-to-use-break-glass). |
| The grant is on but the read still gets the challenge | The grant expired or was revoked. Run `cfg tenant crossings msp-a`: an empty list means none is active. Use `--json` to see its status (`expired` or `revoked`). Ask the MSP to issue a new one. Also check the grant is on the MSP that owns the data, not a sibling. |
| Break-glass is stuck `pending` | The second-approver setting is on. A different root-scoped operator must run `cfg tenant approve-break-glass`. The invoker cannot (`SAME_APPROVER`). Unapproved requests expire after 30 minutes; the MSP can **Deny** one. |
| `approve-break-glass` returns `NOT_PENDING` | It was already approved, ended, or expired while pending. Check `cfg tenant crossings msp-a --json`. |
| `403 NOT_CROSSING_OWNER` on end | You are ending another operator's break-glass. Only its invoker, or an MSP administrator, can. |
| `403 ROOT_SCOPED_CANNOT_END_GRANT` | Root cannot revoke a grant. Only the MSP can. |
| `INVALID_REASON_CATEGORY`, `REASON_CATEGORY_REQUIRED` or `JUSTIFICATION_REQUIRED` | The reason must be one of the four categories, and the justification 10-1000 characters. |
| No email received | Look at `outcome` on the `tenant.crossing_break_glass_notified` entry. `no_contacts`: the MSP has no administrator contacts. `not_configured`: email settings or the credential are missing; check `GET /api/v1/notifications/email`. `failed` or `partial`: run the test-send endpoint and read `failure_reason`. The break-glass was not blocked in any case. |
| The Support access page is empty | Nothing is active. Expired and ended records drop out of the active view; use the filter or `--json` for history. |
