# Email Delivery: Platform Sender and MSP Senders

The controller sends operational and security mail through one of two senders. This guide says what each
sender is for, which mail uses which, how an MSP administrator sets up their own, what is audited, and how to
read the audit entry to see which sender carried a message.

## 1. Two senders

| | Platform sender | MSP sender |
|---|---|---|
| Owner | The controller operator | One MSP tenant |
| Where it is set | `notifications.email` in the controller config, plus a credential endpoint | The MSP's own record, by REST API or `cfg tenant email-sender` |
| Who can change it | A root-scoped operator with `notification:configure` | An administrator of that MSP with `notification:configure-msp` |
| Scope | The whole controller | The MSP and its client tenants |
| Used for | Security notices the platform owes an MSP, and the fallback for every other mail | Operational mail about the MSP's own tenants and stewards |

There are no other senders. A client tenant (a tenant below an MSP) has no sender of its own: its mail goes
through the owning MSP's sender, or the platform sender. SMTP is the only provider.

An MSP sender is **MSP-controlled**. The MSP can point it at any mail server, misconfigure it, or remove it.
It therefore cannot carry a security notice the platform owes the MSP: those notices always use the platform
sender, so a broken or replaced MSP sender cannot stop them.

If the owning MSP has no sender, or its sender is incomplete (no stored password), the mail falls back to the
platform sender. If the platform sender is not configured either, the mail is not sent and the outcome is
recorded as `not_configured`. A send that fails on the MSP sender is **not** retried on the platform sender.

## 2. Which mail uses which sender

| Mail | Sender |
|------|--------|
| Steward tamper alert | Owning MSP sender, else platform |
| Steward locked-admission notice | Owning MSP sender, else platform |
| Pending script change notice | Owning MSP sender, else platform |
| Steward repair-contested notice | Owning MSP sender, else platform |
| Break-glass crossing notice | Platform, always |
| Controller test send (`POST /api/v1/notifications/email/test`) | Platform |
| MSP test send (`POST /api/v1/tenants/{id}/email-sender/test`) | The MSP sender; never the platform sender |

"Owning MSP" is the MSP that is the ancestor of the tenant the notice is about.

## 3. The platform sender

Set under `notifications.email` in the controller config; only the non-secret settings are in the file. See the
[config schema](../reference/config-schema.md#notificationsemail) for every field.

```yaml
notifications:
  email:
    host: smtp.example.com
    port: 587
    from: cfgms@example.com
    username: mailer
    tls_mode: starttls             # or implicit_tls; there is no plaintext mode
    password_secret_key: notifications.email.password
```

Setting `host` requires `from` and `password_secret_key`. The password is **write-only** through the
credential endpoint. The three endpoints need `notification:configure`, a root-scoped principal and strong
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
`delivered: false` with a sanitized `failure_reason`. See
[REST API: Email Delivery](../api/rest-api.md#email-delivery).

## 4. Set up an MSP sender

The MSP administrator needs the `notification:configure-msp` permission (administrators of an MSP hold it
implicitly) at strong assurance; API keys are refused. The sender exists only on an MSP tenant. A client tenant,
a missing tenant, or another MSP's tenant is reported as not found.

### By CLI

```bash
# set or replace: the request replaces every setting, so pass all the settings you want to keep
printf '%s\n' "$SMTP_PASSWORD" | cfg tenant email-sender set msp-a \
  --host smtp.example.com --port 587 --tls-mode starttls \
  --from alerts@msp-a.example.com --username alerts --password-stdin

cfg tenant email-sender show msp-a      # settings and "password: present" or "password: absent"
cfg tenant email-sender test msp-a      # one fixed message to the sender's own from-address
cfg tenant email-sender remove msp-a    # asks for confirmation; --yes skips the prompt
```

- The password is never a flag value. Use `--password-stdin` (one line on standard input), or run `set` in a
  terminal and type it at the no-echo prompt.
- When a password is already stored, leaving it out keeps the stored one. A first-time sender needs a password.
- `--host` and `--from` are required. `--port 0` (the default) uses the server default for the TLS mode.
  `--tls-mode` defaults to `starttls`.
- `test` prints each recipient as accepted or rejected and the failure reason, and exits non-zero when the
  message was not delivered.
- Without a terminal and without `--yes`, `remove` refuses and exits non-zero.
- Every command accepts `--json` to print the response data as received.

### By API

```bash
# set or replace; the body is limited to 8 KiB and unknown fields are rejected
curl -s -X PUT https://<controller>/api/v1/tenants/msp-a/email-sender \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"host": "smtp.example.com", "port": 587, "tls_mode": "starttls",
       "from": "alerts@msp-a.example.com", "username": "alerts", "password": "<smtp-password>"}'

# read the settings; "configured" and "password_present" must both be true for mail to use it
curl -s https://<controller>/api/v1/tenants/msp-a/email-sender -H "Authorization: Bearer <token>"

# send one fixed test message (the body must be empty)
curl -s -X POST https://<controller>/api/v1/tenants/msp-a/email-sender/test -H "Authorization: Bearer <token>"

# remove the sender and its password; mail falls back to the platform sender
curl -s -X DELETE https://<controller>/api/v1/tenants/msp-a/email-sender -H "Authorization: Bearer <token>"
```

The full contract, including every error code, is in [REST API: MSP Email Sender](../api/rest-api.md#msp-email-sender).
The password is never returned by any route; `password_present` only says whether one is stored.

### Limits on an MSP sender

| Rule | MSP sender | Platform sender |
|------|------------|-----------------|
| Port | Empty, `465` or `587` only | Any valid port; the default is `587` for `starttls` and `465` for `implicit_tls` |
| TLS | `starttls` or `implicit_tls`; no plaintext mode | Same |
| Certificate verification | Always on | Always on |
| Private, loopback, link-local and unspecified hosts | **Refused** at connect time, so an MSP-supplied host cannot be aimed at internal services | Not refused; the operator sets the host in the config file |
| `from` | A bare address of at most 254 bytes, no display name | Set by the operator |
| Password | At most 1024 bytes, no control characters, write-only | Write-only through the credential endpoint |

Port `465` goes with `implicit_tls` and `587` with `starttls`. A host that only resolves to a private address
(an internal relay) cannot be used as an MSP sender; ask the platform operator to carry that mail through the
platform sender.

## 5. Assurance and audit

Changing, removing and testing an MSP sender all require strong assurance, and so does reading it. A
root-scoped operator with an active crossing on the MSP may read the sender but cannot change, remove or test
it (`403 ROOT_SCOPED_CANNOT_EDIT_EMAIL_SENDER`): the sender is what tells the MSP about root's own access.

Each change to an MSP sender is audited in the MSP's tenant scope, at high severity, naming the acting
principal:

| Action | When |
|--------|------|
| `tenant.email_sender_updated` | A sender is set or replaced |
| `tenant.email_sender_removed` | A sender is removed |
| `tenant.email_sender_tested` | A test send was attempted; `result` is `success` when delivered and `failure` otherwise |

`updated` and `removed` carry the host, port, TLS mode and `from` address. No entry carries the password or the
username. A test request refused before a send is attempted (a `409` or an invalid body) is not audited.

## 6. Read `sender` on an audit entry

Three audit entries record which sender carried the notice they describe. Read them with
`GET /api/v1/audit/entries`:

| Action | Notice | `sender` values |
|--------|--------|-----------------|
| `steward_tamper_alarm` | Steward tamper alert | `msp`, `platform`, `none` |
| `steward_locked_admission_notified` | Steward locked-admission notice | `msp`, `platform`, `none` |
| `tenant.crossing_break_glass_notified` | Break-glass crossing notice | `platform`, `none` |

| `sender` | Meaning |
|----------|---------|
| `msp` | The owning MSP's own sender carried, or was tried for, the notice |
| `platform` | The controller-wide sender was used: no MSP sender was complete, or the notice is platform-only |
| `none` | No sender was available, so nothing was sent |

Read it with the entry's outcome field (`notification` on the first two entries, `outcome` on the break-glass
entry): `sent`, `partial` (some recipients refused), `failed`, `not_configured` (`sender` is `none`),
`no_contacts` (the tenant has no administrator contacts), or `cooldown` (an earlier notice for the same
steward was sent recently).

The pending script change notice and the steward repair-contested notice write no audit entry for the send.
They log it at INFO, with `outcome` and `sender` fields, in the controller log. A failure on an MSP sender is
logged as an error naming the MSP tenant and a fixed failure kind (`timeout`, `canceled`,
`server_certificate_verification`, `server_rejected` or `delivery_failed`); the raw error text and the
password are never logged.

## 7. Troubleshooting

| Symptom | Cause and action |
|---------|------------------|
| `cfg tenant email-sender set` fails with `INVALID_EMAIL_SENDER` | A field failed validation: a port other than 465 or 587, a plaintext TLS mode, a `from` with a display name, or a first-time sender with no password. Fix the field and run `set` again; the request replaces every setting. |
| `show` reports `configured: no` or `password: absent` | The MSP sender is incomplete, so mail falls back to the platform sender. Run `set` with a password. |
| `test` returns `409 EMAIL_NOT_CONFIGURED` | The MSP has no sender record or no stored password. The test never falls back to the platform sender. |
| `test` reports `delivered: false` with `delivery failed` and the host is an internal relay | A host that resolves to a loopback, private, link-local or unspecified address is refused for an MSP sender. Use a public mail host. |
| `test` reports `server certificate verification failed` | The mail server's certificate does not verify; certificate verification cannot be turned off. Correct the host name or the server certificate. |
| `test` reports `mail server rejected the message` or `recipient not accepted` | The mail server refused the message or the `from` address. Check the credentials and that the server accepts the `from` address. |
| A tamper alert did not arrive | Read `sender` and `notification` on the `steward_tamper_alarm` entry (section 6). `none` and `not_configured`: neither an MSP sender nor the platform sender is complete. `no_contacts`: the tenant has no administrator contacts. `failed`: run the test for the sender named in `sender`. |
| A break-glass notice did not arrive | `sender` is always `platform` (or `none`). Check the platform sender with `GET /api/v1/notifications/email` and the test send. An MSP sender never affects it. See [tenant support access](tenant-support-access.md#email-delivery). |
| `403 ROOT_SCOPED_CANNOT_EDIT_EMAIL_SENDER` | A root-scoped caller tried to change, remove or test an MSP sender. Only an administrator of that MSP can. |
| `404 TENANT_NOT_FOUND` for an existing tenant | The tenant is not an MSP (a client tenant has no sender), or it is outside the caller's subtree. |

## 8. In the web console

An administrator of an MSP manages the MSP sender from **Email delivery** in the sidebar (`/email-delivery`),
below **Support access**. The page needs the same permission and assurance as the API and CLI
(`notification:configure-msp`, strong assurance), and it asks for a passkey confirmation when it needs one.

| Part of the page | What it does |
|------------------|--------------|
| **Sender** | Shows the MSP's own sender (mail server, port and TLS mode, `from` address, username) and a **Password saved** chip, or **No sender: using the platform sender** when the MSP has none or its sender has no stored password. |
| **Set sender** / **Replace** | Opens the form: mail server, TLS mode, port, `from` address, optional username and password. The port is a choice of `587` or `465` and follows the TLS mode (`587` for STARTTLS, `465` for implicit TLS). Saving replaces every setting and takes a passkey confirmation. |
| **Remove** | Asks for confirmation, then deletes the settings and the stored password. Mail falls back to the platform sender. |
| **Send a test** | Sends the one fixed test message to the sender's own `from` address and lists each recipient as **Accepted** or **Not sent**, with the failure reason shown as plain text. A test never uses the platform sender. |
| **What uses this sender** | Lists which mail uses the MSP sender and which always uses the platform sender (section 2). |

The password field is write-only. It is empty whenever the form opens, it goes to the controller only in the
save request, and the page clears it as soon as the save finishes, whether the save worked or not. Afterwards the
page shows **Password saved** and nothing else about it. To change other settings and keep the stored password,
leave the field empty. A first-time sender needs a password.

If the passkey confirmation is cancelled, nothing is changed and the page says so; type the password again and
save. A validation error from the controller (for example a port other than `465` or `587`) is shown above the
save button.

A root-scoped operator sees the standard tenant-access prompt first. With a crossing on the MSP, the page is
read-only: **Replace**, **Remove** and **Set sender** are hidden and **Send test** is disabled, because the
controller refuses all three for root (`403 ROOT_SCOPED_CANNOT_EDIT_EMAIL_SENDER`, section 5). A user without
`notification:configure-msp` sees that the sender cannot be viewed.
