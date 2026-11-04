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
