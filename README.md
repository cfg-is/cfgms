# CFGMS

CFGMS is an open-source configuration, automation, and infrastructure management
platform built for managed service providers and IT teams.

It is designed to manage large, multi-tenant fleets across Windows, Linux, and
macOS from a single control plane, combining desired-state configuration, policy
enforcement, drift detection, workflow automation, live endpoint telemetry, and a
historical model of the systems it manages.

CFGMS is being built to connect an affected device or application to its
dependencies and recent changes, identify the likely cause, and safely remediate
it—not merely report that something is wrong.

[![Build Status](https://github.com/cfg-is/cfgms/workflows/Cross-Platform%20Build%20Validation/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![Security Scan](https://github.com/cfg-is/cfgms/workflows/Security%20Scanning%20Workflow/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![CodeQL](https://github.com/cfg-is/cfgms/workflows/CodeQL%20Security%20Analysis/badge.svg)](https://github.com/cfg-is/cfgms/security/code-scanning)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cfg-is/cfgms/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

## What CFGMS provides

- Desired-state configuration and policy-as-code
- Configuration drift detection and enforcement
- Workflow and event-driven automation
- Hierarchical multi-tenancy for MSPs and their clients
- Endpoint inventory, live telemetry, and historical state
- An entity graph for modeling systems and their relationships
- Microsoft 365, Active Directory, endpoint, and infrastructure integrations
- Mutual TLS, role-based access control, signed modules, and encrypted secrets
- A `cfg` CLI and REST API; a controller-served web UI is in early development

Digital Employee Experience (DEX) capabilities — experience signals, fleet
baselines, root-cause analysis, predictive insight, and remediation through the
same configuration and workflow system — are planned on this foundation. See the
[roadmap](docs/product/roadmap.md).

## Architecture

CFGMS uses three cooperating components:

- **Controller** — the central control plane for configuration, orchestration,
  workflows, fleet state, APIs, and multi-tenant administration.
- **Steward** — the agent that observes and manages a Windows, Linux, or macOS
  endpoint.
- **Outpost** — a planned local proxy and discovery component for networks and
  devices that cannot run a Steward.

Internal control and data-plane communication uses gRPC over QUIC with mutual
TLS. External integrations use HTTPS and the REST API.

## Project status

CFGMS is in early development. Its core architecture and a growing set of
components are implemented, but it should not yet be treated as a finished
production product. Interfaces and deployment procedures may change.

Direction and progress are tracked in the [roadmap](docs/product/roadmap.md) and
on the [project board](https://github.com/orgs/cfg-is/projects/1).

## Build from source

Prerequisites: Go and Git. See [`go.mod`](go.mod) for the required Go version.

```bash
git clone https://github.com/cfg-is/cfgms.git
cd cfgms
make build
```

Binaries land in `bin/`. Both the controller and the steward need configuration
before they will start: the controller initializes its CA and admin credential
bundle with `--init --config`, and stewards join using a registration token it
issues. The [single-controller walkthrough](docs/deployment/single-controller/walkthrough.md)
is the shortest path to a working deployment; see
[platform support](docs/deployment/platform-support.md) for supported
architectures and [deployment docs](docs/deployment/) for other topologies.

## Security

CFGMS is designed around the assumption that endpoints—and occasionally
administrator accounts—may be compromised. Internal communication requires
mutual TLS, secrets are encrypted, executable modules are signed, authorization
is tenant-aware, and security-relevant activity is audited.

Do not report vulnerabilities through a public issue. See
[SECURITY.md](SECURITY.md) or email
[security@cfg.is](mailto:security@cfg.is).

## Open source and licensing

CFGMS is licensed under the
[GNU Affero General Public License v3.0](LICENSE). It can be self-hosted and used
by MSPs to manage client environments under the AGPL. A separate commercial
license is available for incorporating CFGMS into proprietary products.

See [LICENSING.md](LICENSING.md) for the complete terms and FAQ. For commercial
licensing, hosted deployments, or support, contact
[licensing@cfg.is](mailto:licensing@cfg.is).

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), which
covers the development workflow. Contributors must sign the
[Contributor License Agreement](docs/legal/CLA.md) and add themselves to
[CONTRIBUTORS.md](CONTRIBUTORS.md).

[Open an issue](https://github.com/cfg-is/cfgms/issues/new) for bugs and feature
requests. Issues labelled `internal` are locked automated pipeline items, not
closed to contribution — see
[issue classes](CONTRIBUTING.md#issue-classes--why-some-issues-are-locked).

- [Documentation](docs/)
- [Development setup](docs/development/)
- [Architecture](docs/architecture/)
