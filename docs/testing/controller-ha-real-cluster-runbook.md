# Real-Host Controller Cluster Validation

Use this page to plan a current shared-store/lease cluster validation and interpret
the earlier real-host evidence without treating it as a current release result.
[ADR-031](../architecture/decisions/031-controller-cluster-service-model.md) owns the
current service model; the earlier experiment used a Raft-based implementation.

## Current reproduction path

1. Start from [single-controller setup](../deployment/single-controller/walkthrough.md)
   or [Tier 1 bring-up](../operations/tier1-controller-bringup.md).
2. Provision backend-consistent shared PostgreSQL, blob storage and protected
   secret/trust material using [cluster storage](../operations/cluster-storage-config.md),
   [cluster CA](../operations/cluster-ca.md) and
   [signing migration](../operations/cluster-signing-migration.md).
3. Follow the [cluster deployment](../deployment/controller-cluster/walkthrough.md)
   with stable node IDs, configured endpoint routing and appropriate remaining capacity.
4. Verify readiness and an authenticated read/write on each node. Observe shared
   state and lease/fencing authority through actual current telemetry/logs.
5. In a controlled test environment, distinguish loss of the lease holder,
   loss of the node serving a steward, shared-backend failure and routing failure.
   Record request results, reconnects/heartbeats and error recovery separately.
6. Verify a connected steward can receive configuration and perform an authorized
   live query across the intended failure/recovery. A leader change with its
   serving connection intact does not prove serving-node failover.
7. Exercise the [rolling upgrade](../operations/rolling-cluster-upgrade.md) and
   backend-consistent recovery path appropriate to this revision. Do not replay
   old Raft-log deletion, term-fence or membership instructions on the lease model.

Use a named revision and platform/backend matrix; record measured times and failure
outcomes rather than copy an old timing assertion. Native failures, the public
endpoint and the intended proof/tenant gates need evidence, not only library tests.

## Historical measurements

The former multi-story runbook recorded these **past** results on three real
hosts. Its observation dates and Raft scenario are essential limits on reuse:

| Scenario | Recorded outcome |
|---|---|
| Process-kill election, 2026-08-15 | 14.02 s |
| Host-kill re-election, 2026-08-15 | 16.02 s |
| Isolated-minority step-down, August 2026 runs | Within the 30 s test bound, remained down during 45 s observation |
| Partition heal | 2.01 s initially; 2.007 s in the recorded follow-up |
| Leader change with serving connection intact, 2026-08-20 | 0 reconnects and 0 missed heartbeats; not a serving-node outage test |

These are not re-measured on the current lease implementation and are not
production SLA values. The
[full original evidence at the retained Git revision](https://github.com/cfg-is/cfgms/blob/17425cd580a6253f884c3b4e71b82cd076327a59/docs/testing/controller-ha-real-cluster-runbook.md)
contains environment, per-story observations, limitations and later credential/
fence experiments. That link identifies the record revision, not one uniform
binary revision for every experiment. Preserve the record for provenance; do not
keep its obsolete commands as competing current deployment instructions.

## Evidence to record for a new run

Record the source/binary revisions, node/backends/routing shape, protected
credential mechanism, exact scenario and commands, actual success/failure/skip
results, relevant redacted logs, observation windows and restoration checks.
Use the [release checklist](release-validation-checklist.md) and
[HA suite](../../test/integration/ha/README.md) for bounded acceptance evidence.
No new cluster run was performed by the documentation cleanup itself.
