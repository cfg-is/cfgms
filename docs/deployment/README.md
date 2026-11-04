# Deploying CFGMS

Choose one procedure. Boot configs and delivered resource desired state are
different contracts; the [config schema](../reference/config-schema.md) owns fields.

| Task | Procedure |
|---|---|
| Bring up one controller and its local steward | [Single controller](single-controller/walkthrough.md) |
| Run the hardened controller container | [Container deployment](container/README.md) |
| Enroll remote endpoints and verify convergence | [Fleet walkthrough](fleet/walkthrough.md) |
| Add shared-store controller peers and endpoint routing | [Controller cluster](controller-cluster/walkthrough.md) |
| Install/connect an operator client | [CLI install](cfg-install.md), then [operator guide](cfg-operator-guide.md) |
| Prepare an enrolled machine for cloning | [Image preparation](steward-image-preparation.md) |
| Re-admit an offline/expired identity | [Registration refresh](steward-refresh-management.md) |
| Verify binaries | [Release artifact verification](release-artifact-verification.md) |

Copy the [controller boot config](controller.cfg) or [steward boot config](steward.cfg)
only for the relevant process. Canonical public-beta definitions select
`security_profile: public-beta` and require signed ad-hoc execution. Provision
CA/signing material through the supported installer/initialization path; removing
these controls is not a startup repair.

Controller passkeys need durable secret storage. Use the selected backend and
sealed-credential procedure in [Tier 1 bring-up](../operations/tier1-controller-bringup.md)
and [ADR-030](../architecture/decisions/030-controller-secret-material-at-rest.md).
Do not use an ephemeral secret store or embed a production token/key in a YAML
example. The [OpenBao provider](../../pkg/secrets/providers/openbao/README.md)
owns its provider-specific development setup; a dev-mode token is not a production credential.

Check [platform support](platform-support.md) before assuming a module works on
all steward OS targets. [Role recipes](../examples/role-configs/README.md) are
starting points for governed resources, not steward boot configs.

For upgrades and day-2 work, use the [operations index](../operations/README.md).
