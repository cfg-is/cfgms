# Security Configuration

Select the procedure for the boundary being configured. Canonical boot configs
and [the configuration schema](../reference/config-schema.md) own exact fields;
this page does not define another security-settings hierarchy.

| Task | Procedure/contract |
|---|---|
| Initialize controller trust and protected secret material | [Single-controller setup](../deployment/single-controller/walkthrough.md), [ADR-030](../architecture/decisions/030-controller-secret-material-at-rest.md) |
| Install a steward with verified controller trust | [Fleet enrollment](../deployment/fleet/walkthrough.md) |
| Enroll an operator or unlock a CLI connection | [Operator guide](../deployment/cfg-operator-guide.md) |
| Configure authorized tenant support or recover accounts | [Support/recovery](../operations/tenant-support-access.md) |
| Select cluster CA and signing identities | [Cluster CA](../operations/cluster-ca.md), [signing migration](../operations/cluster-signing-migration.md) |
| Rotate an execution-signing certificate | [Certificate rotation](certificate-rotation.md) |
| Admit module publishers and content | [Module publishing](../operations/module-publishing.md) |
| Set script signing/trust | [Script reference](../modules/script-module.md#signing-policies) and canonical schema |
| Review browser sessions/CSRF/CORS and assurance requirements | [Security architecture](architecture.md) and registered API route policy |
| Permit a CFGMS software authenticator for a tenant's accounts | [Software authenticators](#software-authenticators) |

## Credentials and scope

Use OS-native operator credential storage and the configured encrypted controller
secret provider. Systemd sealed credentials, an environment binding and an
application secret reference are different mechanisms; an environment variable
is not intrinsically encrypted. Never retain plaintext secrets in an `.env`,
unit file, example, shell history, log or repository.

API keys/sessions carry their own scope and permission contracts. Do not treat
an environment key, successful TLS handshake or root/ancestor relationship as
permission to read arbitrary tenants or execute code on endpoints. Verify the
specific route's required permission, assurance, tenant cut and operator proof.

Keep public HTTPS/QUIC listeners separate from the private metrics listener.
Respect canonical public-beta signing/trust requirements; disabling certificate
verification or reducing a signing floor is not a recovery procedure. Cross-origin
or session changes require the current browser-session/CSRF contract, not a copied
wildcard CORS example.

After changes, verify intended access and denial cases, safe failure reporting,
credential renewal/revocation and the affected runtime path. A valid YAML file
or an accepted ADR is not end-to-end release evidence.

## Software authenticators

A CFGMS software authenticator is a passkey whose private key is held by `cfg`
rather than a hardware or platform authenticator. For a tenant-scoped account the
controller registers one only when both of these hold:

1. The account's tenant is listed in `webauthn.allow_software_authenticators.tenants`
   in `controller.cfg`.
2. The account carries the software-authenticator flag.

A root-scope account follows a separate, stricter path, described under
[Root agent accounts](#root-agent-accounts).

```yaml
webauthn:
  allow_software_authenticators:
    tenants:
      - client-1
    root_agent_accounts: false   # default; see Root agent accounts
```

- **Default is off.** The key is absent by default and an empty list is valid;
  neither permits any registration. The list is not writable through any API:
  tenant metadata is API-writable, so it is deliberately not used.
- **Exact match.** A listed tenant does not cover its child tenants; list each one.
- **Validation.** An entry that is empty, or has leading or trailing whitespace,
  fails controller startup. The list is checked even when no `rp_id` is set.
- **Refused regardless of the tenant list or the flag:** an account with an empty
  tenant (and no root scope) and an account in the root tenant. A root-scope account
  is not covered by the tenant list at all; it is judged by the root agent rules
  below. When the root tenant cannot be resolved the controller refuses every
  tenant-path software registration with `503`.
- **Refusal.** Registration fails with `403 SOFTWARE_AUTHENTICATOR_NOT_ALLOWED`
  before anything is stored, on both the admin register route and the
  enrollment-token route, and the controller writes an
  `account.passkey_registration_denied` audit event naming the account, its tenant
  and the AAGUID. An enrollment token is not consumed by a refusal.
- **Reset.** Resetting an account clears the flag.
- **The AAGUID is a claim.** The controller requests no attestation, so a credential
  that reports any other AAGUID registers on the ordinary path and receives no
  different trust, assurance or exemption.

The same decision is applied every time a registered software credential is used.
When it stops being true (the tenant is removed from the list, the account flag is
cleared, or the account is or becomes an empty-tenant or root-tenant account, or it
becomes a root-scope account that fails the root agent rules, or the root tenant
cannot be resolved) the credential is ignored at once:
it cannot log in, step up, give presence, sign an operator payload, publish a
workflow or authorize a run command. Web and CLI-login sessions that rest on it end
on their next request. A workflow publication it signed stops verifying, and a
steward roster manifest no longer lists it. The stored credential is not deleted: it
is still listed and can be revoked, and it works again when the policy is turned back
on. A credential with any other AAGUID on the same account is unaffected. An account
whose only credential is a software credential reports no usable authenticator while
the policy is off; that does not reopen first-passkey enrollment, because the stored
credential still counts as enrolled.

### Root agent accounts

A dedicated root-scope agent account may hold a software authenticator (ADR-021
Amendment 11). It is off by default and needs its own setting:

```yaml
webauthn:
  allow_software_authenticators:
    root_agent_accounts: true
```

Like the tenant list the setting has no API writer. Changing it is an edit of
`controller.cfg` on the controller host and a controller restart, so a phished
administrator cannot widen it. The controller logs the effective value at startup
when it is on.

A root-scope account is permitted a software authenticator only when all of these hold:

- the setting is on;
- the account is root-scope and carries the software-authenticator flag, set by
  `PUT /accounts/{username}/software-authenticator` (root-scope caller, Strong
  assurance and a presence tap; refused with `400` for `cfgms-admin`, for an account
  with a bound admin certificate, and while the setting is off);
- the account is not `cfgms-admin` and holds no bound admin certificate;
- every credential the account holds is a CFGMS software credential.

The same rules run at registration, at flag-set time (the name and certificate rules)
and at every use. A registration refusal is `403 SOFTWARE_AUTHENTICATOR_NOT_ALLOWED`;
the `account.passkey_registration_denied` event carries `root_scope: true` and a
`reason` naming the failed condition (`root_agent_setting_off`,
`root_agent_flag_unset`, `root_agent_system_admin`, `root_agent_cert_bound`,
`root_agent_non_software_credential`). Turning the setting off, clearing the flag or
adding a non-software credential makes the controller ignore the software credentials
at the next request; the stored credential is not deleted.

**Limited authority.** A session for a root-scope account that carries the flag does
not receive full administrator breadth. It holds only 16 permissions:
`webauthn:assert-presence`, `webauthn:elevate`, `tenant:create`, `tenant:list`,
`tenant:read`, `account:create`, `steward:list`, `steward:read`,
`steward:read-scripts`, `steward:execute-scripts`, `operator-payload:sign`,
`workflow:publish`, `workflow:read`, `workflow:list`, `module:approve` and
`module:list-approvals`. Everything else is refused with `403`, including credential,
role, API-key, trust and tenant-crossing administration, and the refusal is audited
(`authorization.root_agent_denied`) with the software-authenticator marker,
`root_scope: true` and a `reason`. The limit follows the flag, not the credential
used and not the setting: a human credential added later, or the setting being turned
off, does not return the account to full administrator. Clearing the flag does, and
needs another root caller and a presence tap; a flagged account cannot clear its own
flag. `account:create` is limited to creating a new tenant-scoped account (no
`root_scope`, no existing username, no `reset_credentials`).

Tenant crossing is unchanged: the account acts below root only through a crossing
grant or break-glass, and it cannot create one.

**Key protection is an operator obligation the controller cannot verify.** The
controller requests no attestation. It records the AAGUID and the attestation format
`none`, and the CFGMS software AAGUID is the same whether the key sits in a platform
key provider or in the encrypted credential store; both are self-asserted. Create a
root agent account's authenticator with `--key-provider platform` so the key is
non-exportable. Within the allowlist the account has fleet-wide reach below the
root-to-MSP boundary, and whoever controls the agent host can use the key for every
presence-gated action the account holds.

### Audit trail for software authenticators

Every use of a registered credential that is audited carries these detail fields, so
a reviewer can pick every software-authenticator action out of the trail:

| Field | Value |
|-------|-------|
| `software_authenticator` | `true` when the credential's recorded AAGUID is the CFGMS AAGUID, `false` for every other credential |
| `aaguid` | the credential's recorded AAGUID, hex-encoded |
| `credential_id` | the credential ID, base64url-encoded (hex-encoded on `operator_payload.dispatch`, which has always recorded it that way) |
| `root_scope` | `true`, present only when the account is root-scope (a root agent account), which tells its use from tenant use |

The events are `web.passkey.login.success` and `.failure`, `web.presence.success`,
`web.stepup.success`, `workflow.publish`, and `operator_payload.dispatch` (the sign
ceremony's finish and a WebAuthn-proved run command). The fields are present only when
the credential named by the request is one of the account's, so an event never claims a
marker for a credential it cannot identify. `software_authenticator` is a label from a
self-asserted AAGUID, not proof of what produced the credential.

A use that does not succeed is audited too. A failed login is audited whichever
credential it names. For presence, step-up, sign finish, workflow publish and a
run-command proof, a failed use is audited only when the credential is a software
authenticator (`web.presence.failure`, `web.stepup.failure`, `workflow.publish.failure`,
and `operator_payload.dispatch` with a failed result); what those ceremonies record for
other credentials is unchanged. When the policy refuses the use, the event's result is
`denied` and its reason is `software_authenticator_policy` (`reason` on login, presence,
step-up and publish events; `rejection_reason` on `operator_payload.dispatch`).

The audit manager's redaction (`pkg/audit` `RedactedKeys`) matches `auth` and `credential`
as substrings, so it exempts the exact keys `software_authenticator` and `credential_id`;
both are stored with their values. Similar keys such as `credential_ids` stay redacted.
