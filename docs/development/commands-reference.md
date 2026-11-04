# Development Command Map

Use this page to choose an owner, not as a second copy of CLI/Makefile help.
Current target definitions and source-adjacent instructions govern exact flags
and prerequisites. Old measured or estimated run durations are not defaults.

## Building

```bash
make build-controller
make build-steward
make build-cli
```

Use the current `Makefile` for aggregate/cross-platform targets and protocol
generation, and [web/README](../../web/README.md) for frontend scripts. The
[platform matrix](../deployment/platform-support.md) distinguishes build targets,
native checks and module coverage.

## Testing

- [Validation map](../testing/testing-strategy.md): affected packages, commit/story
  gates and infrastructure/native/live evidence.
- `make test`: repository Go/script aggregate; not one equivalent `go test` command.
- `make test-commit`: commit prerequisites defined in Makefile.
- `make test-complete` / `make test-agent-complete`: respective completion paths;
  report omitted Docker checks in agent mode.
- [E2E setup](../testing/e2e-testing-guide.md): actual fixtures and ownership.

## Developer workflow

[Git workflow](git-workflow.md), [story checklist](story-checklist.md),
[commit/PR standards](commit-and-pr-standards.md) and the actual `.claude/commands/`
entry points own their mechanics. Planning roles load
[product planning](product-planning.md). Pipeline commands remain in the pinned
`.claude/tooling` repository; do not copy a competing pipeline manual here.

## Product administration

Use the CLI's current `--help` and focused operator references:

- [Install/connect/login](../deployment/cfg-operator-guide.md)
- [Selectors](../administration/cli-selectors.md), [stewards](../administration/steward-management.md), [tenants](../administration/tenant-management.md)
- [Controller upgrades](../operations/controller-upgrade.md), [cluster upgrades](../operations/rolling-cluster-upgrade.md), [steward upgrades](../deployment/fleet-upgrades.md)
- [Module publishing](../operations/module-publishing.md), [backend migration](../operations/backend-migration.md)
- [M365 connections](../M365_INTEGRATION_GUIDE.md)

A command name appearing in a design proposal is not proof the binary implements
it. Verify the command definition and a bounded invocation before adding examples.

[Operator/service credentials](../administration/operator-credentials.md) owns
command-specific enrollment/account/signing details. [Workflow operations](../administration/workflows.md)
owns run/status/cancel procedures; these are operator references, not additional
developer command inventories.
