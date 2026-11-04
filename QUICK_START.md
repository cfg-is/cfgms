# CFGMS Quick Start

Choose the task you need and follow its maintained procedure. CFGMS is currently
focused on an MSP SaaS launch; the deployment paths below also support local
operator and development environments.

## Understand the product

Start with the [README](README.md), [product vision](docs/product/vision.md) and
[roadmap](docs/product/roadmap.md). The roadmap distinguishes shipped foundations
from beta/launch requirements; an existing module or screen does not establish
complete end-to-end delivery.

## Set up a controller and endpoints

1. Choose [single-controller](docs/deployment/single-controller/walkthrough.md)
   or [hardened container](docs/deployment/container/README.md) deployment.
2. [Enroll an operator and connect the CLI](docs/deployment/cfg-operator-guide.md).
3. Follow the [fleet walkthrough](docs/deployment/fleet/walkthrough.md) to register
   endpoints, deliver desired state and verify convergence.
4. Use the [module reference](docs/modules/README.md) for actual resource fields.

The [deployment index](docs/deployment/README.md) links canonical boot configs,
platform requirements and cluster prerequisites. Desired-state resources are a
separate document shape from controller/steward startup configuration.

## Develop CFGMS

Use [DEVELOPMENT.md](DEVELOPMENT.md) for workstation/build setup and
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements. The
[architecture entry](ARCHITECTURE.md) routes you to component contracts.

Standalone steward execution remains available through `cfgms-steward --config
PATH`; it is distinct from a managed steward reconnecting with stored identity.
Consult the [steward operating model](docs/architecture/steward-operating-model.md)
and current binary help for its lifecycle. Self-hosting product work, standalone
product expansion and full CLI parity are deferred priorities, not new launch gates.

## Diagnose or upgrade

- [Connectivity and configuration delivery](docs/troubleshooting/connectivity.md)
- [Operations index](docs/operations/README.md) for controller, cluster and fleet upgrades
- [Registration refresh](docs/deployment/steward-refresh-management.md) for expired/offline identity admission
- [Image preparation](docs/deployment/steward-image-preparation.md) before cloning an enrolled endpoint

Do not disable certificate verification or remove identity/trust storage as a
shortcut around a failed connection. Use the relevant procedure to identify the
cause and verify the corrected outcome.
