# Steward Compatibility Harness

The compat harness runs a steward built from a past release tag against the
controller built from the change under test. It proves that a command the
current controller sends is still verified and executed by the oldest steward the
platform supports (Issue #6314).

## What it proves today

Five scenarios against the support floor. The first, in
`test/e2e/compat/floor_steward_test.go` (`TestFloorStewardSharedCommand`):

1. The floor steward registers with the controller and reaches the connected state.
2. The version the controller holds for the steward equals the floor tag, and the
   steward binary in the image prints the same version. The binary is the real
   build; it is not a stand-in.
3. A config upload (`PUT /api/v1/stewards/{id}/config`) triggers a `sync_config`
   command. The steward applies it (the declared file appears with the declared
   content) and the command's delivery record ends `delivered` — not `rejected`.

If the controller signs a command in a payload version the floor steward cannot
verify (the negotiation added in Issue #6311), the record ends `rejected`, the
file never appears, and step 3 fails.

The other two are in `test/e2e/compat/connect_no_rejection_test.go`:

- `TestNoSignatureRejectionAfterConnect` waits for the controller's Info event
  `command_not_sent_peer_unsupported` (the on-connect hooks skipped a command type
  the floor steward does not support), then asserts the floor steward's log holds
  no `signature does not match data` and no `unauthenticated command` entry. This
  is the observable form of "unsupported is not a signature failure" for a steward
  that cannot be changed.
- `TestSharedTypeAfterConnect` sends a `sync_config` after that point and asserts
  it executes, is delivered, and draws no rejection in the steward log.

The last two are in `test/e2e/compat/upgrade_from_floor_test.go`. They run after
the scenarios above, because they change the steward:

- `TestUpgradeFromFloor` runs the floor steward under the launcher the floor
  release shipped, builds the steward from this tree (`make build-steward`, version
  `v99.0.0-compat-current`, which sorts above the floor), then publishes it and
  dispatches the upgrade through the controller API as the upgrade-test API key
  (the steward-binary publish and dispatch routes accept a machine principal and
  refuse the admin client without a presence tap). The compat controller's test
  mode records the approval, bound to the SHA-256 of the stored bytes, at publish;
  the explicit approve route needs a human presence tap, and dispatch refuses a
  binary without an approval. It asserts the upgrade record reaches `committed`, the launcher
  switches to the new version, the steward restarts and the controller holds the
  new version for the same steward ID, with no command rejection in the steward log.
- `TestCommandsVerifyAfterUpgrade` asserts that, after the upgrade, the first
  on-connect command (`advertise_transport_address`, which the floor steward was
  never sent) is sent and completed, a `sync_config` executes and is delivered, and
  the controller's durable capability record for the steward is `declared` with
  the current signing payload version and the on-connect command type.

The launcher passes the registration token to its child in the form the current
steward takes (`--regtoken-file`); the floor takes `--regtoken`. The harness bridges
that for the floor version only, with a two-line adapter in the launcher layout that
starts the unmodified floor binary. Broken-binary rollback is covered by the fleet
tests (`test/e2e/fleet/launcher_upgrade_test.go`), not here.

Out of scope here: sending an unsupported command type to the floor steward (no
operator route does so without an operator-signed envelope, which the harness
does not have; the controller-side refusal is covered by controller tests),
and Windows and macOS legs. The harness is Linux only; a Windows or macOS regression in
compatibility is not caught by it.

## The support floor

`test/compat/steward-support.yaml` is the one place the floor is defined:

```yaml
floor: v0.10.5
stewards:
  - tag: v0.10.5
    profile: floor
```

- `floor` is the oldest release the current controller must keep serving.
- Each `stewards` entry names a release `tag` and the capability `profile` its
  steward is expected to run under: `floor` (predates capability declaration) or
  `declared` (declares its capabilities). Only the floor tag has profile `floor`.
- Entries are explicit. There is no computed "latest tag"; supporting a new
  release is an edit to this file.
- No entry may sort below `floor` by semantic version. `TestRepositoryManifest`
  and `TestParseManifest` enforce syntax, a listed floor, unique tags, known
  profiles and that ordering. They need neither git nor Docker.

## How a tag is built

`scripts/compat/build-tag-steward.sh <tag> <outdir>`:

1. fails if the tag is missing from the local clone;
2. extracts the tag with `git archive` into a fresh temporary directory;
3. runs the tag's own recipe there:
   `make build-steward build-steward-launcher VERSION=<tag>`;
4. copies `cfgms-steward` and `cfgms-steward-launcher` to `<outdir>`.

The script never composes `go build` flags. The version, publisher-key default and
other linker flags come from the tag's `Makefile`; a plain `go build` of the tag
reports the source default (`0.5.0-dev`), not the release version. The optional
environment variables `STEWARD_CONTROLLER_URL` and `STEWARD_PUBLISHER_KEY` are
passed to the tag's recipe as make variables.

```bash
git fetch --tags
scripts/compat/build-tag-steward.sh v0.10.5 /tmp/floor
/tmp/floor/cfgms-steward --version     # prints v0.10.5
```

Under the steward launcher the steward needs `CFGMS_STEWARD_LAUNCHER_MANAGED=1`;
the launcher sets it itself. The floor scenarios run the steward directly; the
upgrade scenarios run it under the launcher.

## Running it

```bash
make test-e2e-compat
```

The target reads the floor from the manifest, builds the floor steward with the
script above, stages it with `test/compat/Dockerfile.steward` (which only copies
the prebuilt binaries), starts the `compat` profile of `docker-compose.test.yml`
and runs `./test/e2e/compat/...` with `CFGMS_COMPAT_TEST=1`. Without that
variable the scenario skips, because it needs the Docker stack and a floor build.
Container logs are dumped on failure and the stack is torn down either way.

| Service | Container | Port | Role |
|---------|-----------|------|------|
| `compat-controller` | `compat-controller` | 8091 (HTTP API), 4438/udp | Controller built from this tree |
| `compat-steward-floor` | `compat-steward-floor` | none | Steward built from the floor tag |

The compat services have their own names, ports, volumes and network
(`cfgms-compat`), so they can run beside the fleet services. The floor steward
takes its registration token as `--regtoken` (the floor release predates
`--regtoken-file`), holds the same test publisher key as the controller in
`CFGMS_TEST_STEWARD_PUBLISHER_KEY`, and receives the controller CA from the
harness before it registers.

The scenario reuses the controller-facing helpers of `test/e2e/fleet/fleetkit`.
The fleetkit helpers that take a container name allowlist the `fleet-*` names, so
the container-side steps are in `test/e2e/compat`.

## CI

The `steward-compat-e2e` job in `.github/workflows/steward-compat-e2e.yml` runs
`make test-e2e-compat` on `merge_group` and `workflow_dispatch`. It is a separate
workflow from `fleet-e2e.yml`, so it has no relationship to `fleet-e2e-tests`, a
20-minute job timeout, a 600-second `go test` timeout, and checks out with
`fetch-depth: 0` so the release tags are present. The PR-side stub for the same
context is the `steward-compat-e2e` job in `fleet-e2e-pr-stub.yml`; it runs on
`pull_request` only and never on `merge_group`.

The job is advisory when it lands. It is not in the ruleset's required contexts;
requiring it is a separate change made after a green merge-queue history. The
scenario runs for real first in the merge queue — a pull request run shows only
the stub.

### Proving a harness change before merge

Dispatch the workflow on the branch, then check the `steward-compat-e2e` job:

```bash
gh workflow run steward-compat-e2e.yml --ref <branch>
```

The dispatch run executes only the compat job. It creates no `fleet-e2e-tests`
check run on the branch head, because that job stays in `fleet-e2e.yml`, which
triggers on `merge_group` only. The job log shows `--- PASS` for
`TestFloorStewardSharedCommand` and each subtest.

### Controller certificate

`compat-controller` mounts `test/compat/controller.cfg`, not the fleet config.
The controller auto-generates its public API certificate from
`certificate.server.dns_names`, and refuses to start when the host of
`CFGMS_EXTERNAL_URL` is not one of them. `TestCompatControllerCertCoversExternalURL`
(`test/compat/controller_cfg_test.go`, part of the default suite) fails when the
compose mount and the config drift apart.
