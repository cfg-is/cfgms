# Operations

Runbooks and operator references for running CFGMS in production.

## Upgrades

The four upgrade documents cover distinct scopes; start here to pick the right one.

- [Upgrade Lifecycle Runbook](upgrade-lifecycle.md) - Operator reference for the upgrade pipeline: lifecycle states and audit events
- [Controller Upgrade Runbook](controller-upgrade.md) - Upgrading a single production controller with the blue/green cutover
- [Rolling Cluster Upgrade Runbook](rolling-cluster-upgrade.md) - Zero-downtime rolling upgrade of a controller cluster
- [Fleet Upgrades](../deployment/fleet-upgrades.md) - Upgrading steward binaries across a fleet with the `cfg` CLI

## Cluster Configuration

- [Cluster CA Trust Anchor Configuration](cluster-ca.md) - Sourcing the controller CA from a shared OpenBao secret store in cluster mode
- [Cluster Storage Configuration](cluster-storage-config.md) - Shared external backends required by `ha.mode: cluster`
- [Tier 1 Controller Bring-Up](tier1-controller-bringup.md) - Source of truth for `scripts/tier1-bootstrap.sh`
- [Backend Migration](backend-migration.md) - Operator guide to the `cfg migrate` and `cfg storage migrate` verb shape

## Hyper-V

- [Hyper-V Host Onboarding](hyperv-host-onboarding.md) - Registering a Windows Server Hyper-V host with CFGMS
- [Hyper-V Cluster-Management Access Onboarding](hyperv-cluster-access-onboarding.md) - Granting the LocalSystem steward failover-cluster management rights
- [Adding an Unattended-Install Profile](hyperv-profile-authoring.md) - Provisioning a new OS edition without code changes
- [Hyper-V Host Role](../deployment/hyperv-host-role.md) - Targeting Hyper-V hosts by tag with the `hyperv-host` role
- [Hyper-V live-validation runbooks](../testing/README.md#hyper-v-live-validation) - Cascade and role-promotion runbooks under testing

## Pipeline and Automation

- [Agent Dispatch](agent-dispatch.md) - Operational reference for the `agent-dispatch.sh` lifecycle: environment, containers, credentials
- [cfg-agent PAT Scopes](agent-pat-scopes.md) - Scopes held by the `cfg-agent` automation token, rationale, and rotation guidance
- [Pipeline Substrate Migration](pipeline-substrate-migration.md) - Moving the pipeline from labels to GitHub Projects V2

## General

- [Production Runbooks](production-runbooks.md) - Production operations runbook
- [Monitoring Guide](../monitoring.md) - Tracing, logging, metrics, and third-party integration
- [Trivy Rollback Runbook](../runbooks/trivy-rollback.md) - What to do if the pinned Trivy release is compromised
