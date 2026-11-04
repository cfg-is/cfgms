# Selecting CFGMS Validation

Choose checks for the changed contract and record what actually ran. The
[testing standards](../development/standards/testing-standards.md) own test quality;
this page owns the execution map. The Makefile and CI rulesets own exact gate
composition, not a copied duration or “equivalent go test” table.

| Task | Starting point |
|---|---|
| Develop one Go component | Its source-adjacent tests, including material failure/tenant boundaries |
| Run the repository aggregate | `make test` (Go groups and script checks; not just `go test -short ./...`) |
| Validate a commit | `make test-commit`; inspect its prerequisites in Makefile |
| Complete an interactive story | `make test-complete` and the story-complete review process |
| Complete in the agent environment | `make test-agent-complete`; explicitly identify Docker-dependent checks deferred to CI |
| Exercise real controller/steward traffic | [E2E guide](e2e-testing-guide.md), focused transport/fleet suites |
| Validate native Windows/macOS behavior | Native platform suites/jobs and the affected module tests |
| Prepare a release | [Release validation](release-validation-checklist.md) |

`make test-complete-full` adds infrastructure-dependent validation. No target
name alone proves it exercised every backend, platform, credential-gated test or
user journey. Read the current Makefile and output before reporting coverage.
Timeouts detect hangs; they are not performance promises or expected runtimes.

## Evidence

Tie results to a revision, environment, command and scenario. Distinguish tests
present, tests passed, skipped/unavailable tests, observed runtime behavior and
released behavior. A process that exits zero after skipping all relevant live
checks is not live integration evidence. Current roadmap acceptance may require
multiple platform/integration scenarios beyond a unit-test aggregate.

Keep test-specific setup beside suites. Use
[cluster benchmark](cluster-benchmark.md), [fleet upgrades](e2e-fleet.md) and the
[testing index](README.md) for bounded scenarios. Do not maintain a second CI
pipeline policy in product testing documentation.
