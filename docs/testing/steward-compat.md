# Steward Compatibility Harness

The compat harness runs a steward built from a past release tag against the
controller built from the change under test. It proves that a command the
current controller sends is still verified and executed by the oldest steward the
platform supports (Issue #6314).

## What it proves today

One scenario, in `test/e2e/compat/floor_steward_test.go`
(`TestFloorStewardSharedCommand`), against the support floor:

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

Out of scope here: unsupported-command and upgrade scenarios, and Windows and
macOS legs. The harness is Linux only; a Windows or macOS regression in
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
the launcher sets it itself. The compat scenario runs the steward directly.

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

The `steward-compat-e2e` job in `.github/workflows/fleet-e2e.yml` runs
`make test-e2e-compat` on `merge_group`. It has no `needs:` on `fleet-e2e-tests`,
a 20-minute job timeout, a 600-second `go test` timeout, and checks out with
`fetch-depth: 0` so the release tags are present. The PR-side stub for the same
context is the `steward-compat-e2e` job in `fleet-e2e-pr-stub.yml`; it runs on
`pull_request` only and never on `merge_group`.

The job is advisory when it lands. It is not in the ruleset's required contexts;
requiring it is a separate change made after a green merge-queue history. The
scenario runs for real first in the merge queue — a pull request run shows only
the stub.
