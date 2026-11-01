# CFGMS

> CFGMS manages your clients' Windows, Mac, Linux, and Microsoft 365 estates from one place, keeps every setting where you said it should be, auto-investigates problems, and answers questions about the whole fleet in seconds.

CFGMS is an open-source current-state intelligence and configuration
management platform for managed service providers (MSPs). It stands on two
pillars: zero-trust configuration management for Windows, macOS, Linux, and
Microsoft 365, and live query and execution across every endpoint in the
fleet. You declare how each client's devices and Microsoft 365 tenant should
be set up. CFGMS makes them match and keeps them matching. And when you need
to know what is true right now, you ask the fleet and get a live answer.

[![Build Status](https://github.com/cfg-is/cfgms/workflows/Cross-Platform%20Build%20Validation/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![Security Scan](https://github.com/cfg-is/cfgms/workflows/Security%20Scanning%20Workflow/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![CodeQL](https://github.com/cfg-is/cfgms/workflows/CodeQL%20Security%20Analysis/badge.svg)](https://github.com/cfg-is/cfgms/security/code-scanning)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cfg-is/cfgms/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

## How it works

Every managed object has a **DNA** record: its exact state, versioned over
time. CFGMS links those records into a **knowledge graph**: which server an
application depends on, which policy set a registry key, what changed on a
device last Tuesday. Three engines draw on that graph:

- **Live fleet query and execution.** Ask the fleet a question and get a live
  answer from every endpoint at once: which machines run a given software
  version, who is logged in, which service is down. Then act on the answer at
  the same speed when a fix cannot wait for a scheduled rollout.
- **The reactor.** A device drifts, a user is added, a certificate nears
  expiry. The reactor matches each event against the reactions you declared
  and runs them.
- **The workflow engine.** Multi-step processes built once and run for every
  tenant: onboard a user, decommission a laptop, rotate a secret across a
  client.

Other tools make a technician browse to the problem. CFGMS is being built to
bring the assembled case to them: the affected device, its dependencies, its
recent changes, the likely cause, and a fix through the same engine. The [product vision](docs/product/vision.md) says why; the
[roadmap](docs/product/roadmap.md) says when.

## What CFGMS provides

- Desired-state configuration and policy-as-code for Windows, macOS, Linux,
  and Microsoft 365
- Configuration drift detection and enforcement
- Live fleet query and execution across every managed endpoint
- Event-driven reactions and multi-step workflow automation
- Hierarchical multi-tenancy, with each client's data and access kept apart
- Endpoint inventory, live telemetry, and historical state
- Microsoft 365, Active Directory, endpoint, and infrastructure integrations
- Zero-trust internals: mutual TLS on every internal connection, role-based
  access control, publisher-signed modules, and encrypted secrets
- A `cfg` CLI, REST API and web UI

## Architecture

CFGMS uses three cooperating components:

- **Controller.** The central control plane for configuration, orchestration,
  workflows, fleet state, APIs, and multi-tenant administration.
- **Steward.** The agent that observes and manages a Windows, Linux, or macOS
  endpoint.
- **Outpost.** A planned local proxy and discovery component for networks and
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

CFGMS assumes that endpoints, and sometimes administrator accounts, will be
compromised. Internal communication requires
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
closed to contribution; see
[issue classes](CONTRIBUTING.md#issue-classes--why-some-issues-are-locked).

- [Documentation](docs/)
- [Development setup](docs/development/)
- [Architecture](docs/architecture/)
