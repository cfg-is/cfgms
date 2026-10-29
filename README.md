# CFGMS

CFGMS is an open-source, multi-tenant management and monitoring platform for
managed service providers (MSPs), with a hosted SaaS service as the current
delivery priority. Declarative configuration, extensible modules, workflows and
the DNA knowledge graph provide its foundation.

The product goal is trustworthy current-state visibility and fast investigation
across endpoints, SaaS resources, directories, users and groups. The API-first
platform prioritizes the web operator experience; full CLI parity, self-hosting
product work and standalone steward product work are deferred.

[![Build Status](https://github.com/cfg-is/cfgms/workflows/Cross-Platform%20Build%20Validation/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![Security Scan](https://github.com/cfg-is/cfgms/workflows/Security%20Scanning%20Workflow/badge.svg)](https://github.com/cfg-is/cfgms/actions)
[![CodeQL](https://github.com/cfg-is/cfgms/workflows/CodeQL%20Security%20Analysis/badge.svg)](https://github.com/cfg-is/cfgms/security/code-scanning)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cfg-is/cfgms/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cfg-is/cfgms)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

## How it works

**Stewards** observe and manage endpoints; **controller-side modules** interact
with SaaS and directory APIs. DNA records observed state with source and freshness
information, including resources whose configuration is not managed. The
controller stores observations and their relationships in a knowledge graph.
Steward heartbeat hashes support detection of missed DNA synchronization.

Stored DNA supports controller-side queries; live endpoint connections support
queries and execution when current observations are needed. Declarative
configuration governs desired state, while workflows compose operations.

## Implementation and product direction

The repository includes configuration and execution infrastructure, DNA/graph
storage and synchronization, catalog-based live OSquery dispatch, workflow
execution and approvals, and web fleet and cockpit components. Implementation
coverage and remaining work are linked in the [roadmap](docs/product/roadmap.md).

The early-beta goal includes Windows, macOS and Linux endpoints, Microsoft 365
integration, an iterative query workspace and a general read-only investigation
agent. Existing fleet views, evidence cards and M365 modules provide foundations;
they do not establish the complete beta experience. Directory inventory and
management have existing planned work; launch licensing and PSA workflows need
further scope and integration coverage.

The intended cockpit accepts operator input through one chat-like input and
presents agent output as structured evidence, hypothesis, action and open-question
cards. Agentic investigation and its complete input/tool loop remain delivery
work. HaloPSA and PAX8 are launch integration priorities, not claims of working
connectors. See the [product vision](docs/product/vision.md) for the full contract.

## Architecture

The architecture has two implemented component roles and a future third role:

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
in [public issues](https://github.com/cfg-is/cfgms/issues). The
[project board](https://github.com/orgs/cfg-is/projects/1) requires access; deferred
security work may remain private.

## Build from source

Prerequisites: Go, Git, GNU Make and the shell/build tools described in
[DEVELOPMENT.md](DEVELOPMENT.md). See [`go.mod`](go.mod) for the Go language
version and toolchain. Frontend development has separate Node/npm requirements.

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
