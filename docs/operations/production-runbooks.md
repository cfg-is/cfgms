# Production Operations

Start with the symptom or planned change below. Focused procedures own commands,
prerequisites and recovery; this page does not maintain another copy of them.

| Task | Owner |
|---|---|
| Controller/steward cannot connect, authenticate or sync | [Connectivity diagnosis](../troubleshooting/connectivity.md) |
| Determine readiness versus liveness | [Monitoring](../monitoring.md) |
| Upgrade/recover one controller | [Controller upgrade](controller-upgrade.md) |
| Roll through cluster nodes | [Cluster upgrade](rolling-cluster-upgrade.md) |
| Publish/approve/dispatch steward binaries | [Fleet upgrades](../deployment/fleet-upgrades.md) |
| Understand upgrade history and retention limits | [Lifecycle reference](upgrade-lifecycle.md) |
| Move persistent backends | [Backend migration](backend-migration.md) |
| Configure shared stores or CA/signing identities | [Cluster storage](cluster-storage-config.md), [CA](cluster-ca.md), [signing migration](cluster-signing-migration.md) |
| Manage endpoint lifecycle or tenant access | [Steward management](../administration/steward-management.md), [tenant support/recovery](tenant-support-access.md) |
| Respond to a copied endpoint identity | [Clone incident response](../runbooks/steward-identity-clone.md) |
| Verify/approve a module | [Module publishing](module-publishing.md) |
| Review runtime invariants before changing behavior | [Operating model](../architecture/operating-model.md) |

## Before a change

Record the affected tenant/device/controller scope, authorized actor and intended
outcome. Retain a verified prior binary and backend-appropriate recoverable backup
when applicable. Changing an executable does not restore migrated data, and
copying a live database directory is not automatically a consistent backup.

## During an incident

Capture redacted errors, timestamps, relevant revision/config source and the
failed boundary before modifying the environment. Keep observation separate from
remediation. Use the required approvals and tenant scope even for urgent changes;
a generic incident checklist does not grant cross-tenant access.

## Verify recovery

Check durable-storage readiness, authenticated operations, endpoint reconnect,
configuration delivery and affected resource outcomes as applicable. Retain
failures/partial results in the operational record. Do not infer recovery from
a running process, a successful HTTP write or matching DNA hashes alone.

There are no universal timing, capacity or recovery-point promises in this page.
Define them from the deployed environment's measured requirements and validate the
corresponding failure scenario. Deployment-specific contacts, credentials, backup
schedules and host topology belong in that deployment's operations system.
