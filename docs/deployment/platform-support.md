# Platform Support

## Build targets and validation

The [Makefile](../../Makefile) defines these cross-platform binary targets:

| Component | Operating system | Architecture |
|-----------|------------------|--------------|
| Steward | Linux | AMD64, ARM64 |
| Steward | Windows | AMD64 |
| Steward | macOS | AMD64, ARM64 |
| Controller | Linux | AMD64 |
| Controller | Windows | AMD64 |

These are build/deployment targets, not proof that every module works on each
platform. Windows, macOS and Linux endpoints are early-beta requirements in the
[product vision](../product/vision.md). Module support depends on its platform
implementation and native integration results.

The [PR build workflow](../../.github/workflows/cross-platform-build-pr.yml)
contains cross-compilation and native Windows/macOS test jobs. The
[queue workflow](../../.github/workflows/cross-platform-build.yml) covers Linux
and PostgreSQL-backed checks. Linux ARM64 and macOS AMD64 cross-compilation do
not establish native runtime validation on those architectures. Inspect actual
job results for the revision being evaluated.

## Modules and operating-system behavior

Consult each module's README, manifest and platform implementation before
promising coverage. For example, the [firewall module](../../features/modules/stdlib/firewall/README.md)
has a Linux executor and a non-Linux stub; it does not establish Windows Firewall
or macOS packet-filter management. The [package module](../../features/modules/stdlib/package/README.md)
has separate platform backends. Shared interfaces do not imply identical features
or behavior on every operating system.

Native service installation uses systemd on Linux, Windows Service on Windows,
and launchd on macOS. The source contract is
[`cfgms-steward install`](../../cmd/steward/main.go) and its
[service managers](../../cmd/steward/service/). Installation requires the
appropriate elevated privileges. Use `--regtoken-file` with the required
platform access controls. The legacy `--regtoken` argument has been removed. Do not hand-create service definitions that bypass installation
and trust setup.

## Deployment and release instructions

- [Single controller](single-controller/walkthrough.md): initialization, trust and service setup.
- [Fleet walkthrough](fleet/walkthrough.md): remote enrollment and convergence.
- [Controller cluster](controller-cluster/walkthrough.md): clustered topology and constraints.
- [Fleet upgrades](fleet-upgrades.md): signed distribution and upgrade tracking.
- [Release artifact verification](release-artifact-verification.md): current release/signature limits.
- [Canonical steward configuration](steward.cfg): boot paths and settings.

Use the walkthrough that matches the topology and trust mode. A development
platform or a cross-compiled binary is not a supported production deployment
claim. Self-hosting product work is deferred while SaaS takes priority; existing
operator procedures remain available for development and deployment validation.

## Quality and capacity

This page makes no measured fleet-capacity, CPU, memory or recovery-time claim.
Release decisions require evidence for installation, upgrade/reconnect and the
shipped modules on each supported platform. Record the revision, environment,
workload and observed result rather than treating a target or a successful build
as a benchmark. See [Product Planning](../development/product-planning.md).
