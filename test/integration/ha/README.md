# HA Integration Tests

Source-adjacent setup and scope for the controller/steward HA suites. These tests
are scenarios, not a production capacity/failover certificate. Some fixtures and
test names originate in older cluster designs; the current production contract
is [ADR-031](../../../docs/architecture/decisions/031-controller-cluster-service-model.md).

## Select a scenario

- `cluster_formation_test.go`, `leader_election_test.go`, `node_restart_test.go`:
  formation, election and restart behavior under the selected fixture.
- `failover_test.go`, `network_partition_test.go`, `geographic_test.go`:
  process, routing and partition scenarios. Geographic labels are local simulation.
- `steward_ha_test.go`, `configuration_continuity_test.go`,
  `authentication_workflow_test.go`: actual steward connection/config/auth behavior.

Read each test's body, assertions and skips. A surviving connection through a
leader change is not the same scenario as reconnecting after its serving node dies.

## Infrastructure ownership

[`docker_helper.go`](docker_helper.go) uses the root `docker-compose.test.yml`
with the `ha` profile. It names controllers `controller-east`, `controller-central`,
`controller-west` and separately manages support services. Shared TimescaleDB,
S3-compatible blob storage and OpenBao/CA initialization must satisfy the helper's
preconditions. Reuse infrastructure according to that helper instead of creating
colliding globally named containers or removing another run's shared volumes.

`git-server-ha` is retained by configuration-continuity fixtures; it is not the
current production storage backend or inter-controller replication mechanism.
Current cluster state lives in shared durable stores with lease-backed authority.

## Run and report

```bash
go test -v ./test/integration/ha -run '^TestClusterFormation$'
go test -v ./test/integration/ha -run '^TestConfigurationPushContinuity$'
```

Inspect [setup_test.go](setup_test.go) for current secret/transport prerequisites
and skip handling. Provision the required keys through the supported test helpers;
never write production keys into Compose files. These commands require the
scenario's real infrastructure; they are not asserted to run on an empty workstation.

Timing limits in assertions and fixture environment variables are test-specific.
Do not copy old accelerated-election/heartbeat values into production or claim
speedup percentages without measured comparable runs. Record command, revision,
fixture, elapsed result and skips separately. Use the
[product E2E guide](../../../docs/testing/e2e-testing-guide.md) for shared hygiene.
