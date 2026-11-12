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
rather than a hardware or platform authenticator. The controller registers one only
when both of these hold:

1. The account's tenant is listed in `webauthn.allow_software_authenticators.tenants`
   in `controller.cfg`.
2. The account carries the software-authenticator flag.

```yaml
webauthn:
  allow_software_authenticators:
    tenants:
      - client-1
```

- **Default is off.** The key is absent by default and an empty list is valid;
  neither permits any registration. The list is not writable through any API:
  tenant metadata is API-writable, so it is deliberately not used.
- **Exact match.** A listed tenant does not cover its child tenants; list each one.
- **Validation.** An entry that is empty, or has leading or trailing whitespace,
  fails controller startup. The list is checked even when no `rp_id` is set.
- **Refused regardless of the list or the flag:** a root-scope account, an account
  with an empty tenant, and an account in the root tenant. When the root tenant
  cannot be resolved the controller refuses every software registration with `503`.
- **Refusal.** Registration fails with `403 SOFTWARE_AUTHENTICATOR_NOT_ALLOWED`
  before anything is stored, on both the admin register route and the
  enrollment-token route, and the controller writes an
  `account.passkey_registration_denied` audit event naming the account, its tenant
  and the AAGUID. An enrollment token is not consumed by a refusal.
- **Reset.** Resetting an account clears the flag.
- **The AAGUID is a claim.** The controller requests no attestation, so a credential
  that reports any other AAGUID registers on the ordinary path and receives no
  different trust, assurance or exemption.

This policy applies at registration. It does not change credentials already
registered.
