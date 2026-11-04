# Product Integration and E2E Tests

Run the suite that crosses the changed product boundary. Read its fixtures,
`TestMain` and prerequisite checks before provisioning anything; the directory
name does not prove that a test is infrastructure-free or that it contacts a live service.

## Suite map

| Boundary | Source and setup |
|---|---|
| Local standalone resources | `test/integration/standalone/` and its current tests/fixtures |
| Control/data transport, registration, config and DNA | `test/integration/transport/` |
| Controller integration | `test/integration/controller/` |
| Multi-controller behavior | [HA suite](../../test/integration/ha/README.md), `test/integration/cluster/` and `test/e2e/ha/` |
| Steward binary upgrades | [Fleet E2E](e2e-fleet.md), `test/e2e/fleet/` |
| Hyper-V lifecycle/provisioning | Native Windows `test/e2e/hyperv/` and [live-validation index](README.md#hyper-v-live-validation) |
| Microsoft 365 | [Credential/live testing](../../features/workflow/modules/m365/TESTING.md) |

## Local procedure

1. Install the toolchain pinned by `go.mod`; use the repository's current build
   targets for binaries/images expected by the suite.
2. Inspect the selected test's required environment, ports, certificate/secret
   setup, Compose project and cleanup ownership. `docker-compose.test.yml` is the
   common fixture entry, but profiles/services vary by scenario.
3. Run only infrastructure you own. Do not use broad `down -v --rmi all` cleanup
   against shared databases/vaults or another test project's containers.
4. Run the specific Go package/scenario and retain its actual output. For example:

   ```bash
   go test -v ./test/integration/transport -run '^TestHeartbeat$'
   ```

5. Check skips and per-scenario outcomes, then remove only the state created for
   that run. Capture redacted logs and failed boundaries before cleanup on error.

A real database, vault or credential-gated service may be necessary even when the
test uses a local transport harness. Do not manufacture missing secrets or
replace real components with mocks to report a pass.

## Interpret results

A Compose fixture, test name or old completion checklist is not evidence the
scenario ran on this revision. Record actual controller/steward identity,
connection, request and error outcomes for the changed boundary. A local simulated
region does not measure geographic latency. Re-run native OS paths on their native
platform; successful cross-compilation is different evidence.

Current transport uses [gRPC over QUIC](../../ARCHITECTURE.md#communication-architecture),
while installer/binary distribution uses HTTPS. Test these paths separately where
necessary. For current release outcomes and limits use the
[release checklist](release-validation-checklist.md), not old numbered quick-start tiers.
