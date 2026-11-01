# Documentation boundaries: product docs vs. private-deployment docs

## The rule

**Product documentation** describes CFGMS — its behaviour, configuration model,
APIs, and operational procedures — in terms that apply to any deployment. It
belongs in this repository.

**Private-deployment documentation** describes one specific installation of
CFGMS — particular hostnames, IP addresses, cluster names, SSH key names, or
environment-specific topology details that are only meaningful in that
installation. It does not belong in this repository.

When a document describes what CFGMS does, it is a product document.
When it names a specific machine or network that CFGMS is running on, that
portion is private-deployment detail.

## How to tell

Ask these questions about a document (or a passage within it):

| Question | Product doc | Private-deployment doc |
|----------|-------------|------------------------|
| Could a different operator follow this using their own cluster? | Yes | No — names or IPs are hard-coded |
| Does it name specific hostnames, node names, or SSH key names? | No | Yes |
| Does it contain non-RFC-5737 IP addresses? | No | Yes |
| Would redacting the hostnames/IPs make the document meaningless? | No | Yes |
| Does the text only make sense for one environment's topology? | No | Yes |

## What stays in the repository

- Architecture decision records (ADRs) — written in terms of CFGMS components,
  not specific machines
- API reference, CLI reference
- Operational runbooks — using placeholder node names and RFC 5737 documentation
  IPs (`192.0.2.x`)
- Deployment walkthroughs — using generic node names (`ctrl-node-01`,
  `ctrl-node-02`, `ctrl-node-03`) and placeholder cluster names (`example-cluster`)
- Test runbooks — using placeholder host names (`HV-HOST-01`, `HV-HOST-02`,
  `HV-HOST-03`) and `lab.example.com` as the DNS domain
- Configuration examples — using vendor-a / acme-corp / example values

## What does not belong here

- Actual hostnames, cluster names, or node names of a real deployment
- Real internal IP addresses or subnets outside the RFC 5737 documentation ranges
- SSH key names tied to a specific environment — use a generic placeholder such
  as `cfgms_ed25519`
- Documented secrets, environment files, or credential paths from a live system
- Operational inventories or runbooks written for one specific environment

## Placeholder conventions

Use these placeholders when writing examples or runbooks:

| What | Placeholder |
|------|-------------|
| Controller cluster name | `example-cluster` |
| Controller node 1 | `ctrl-node-01` |
| Controller node 2 | `ctrl-node-02` |
| Controller node 3 | `ctrl-node-03` |
| Data-service VM | `datasvc-vm` |
| Hyper-V host 1 | `HV-HOST-01` |
| Hyper-V host 2 | `HV-HOST-02` |
| Hyper-V host 3 | `HV-HOST-03` |
| SSH key name | `cfgms_ed25519` |
| DNS domain | `lab.example.com` |
| Documentation IPs | `192.0.2.x` (RFC 5737) |
| Cluster subnet | `192.0.2.0/24` |

## Verification

```sh
make check-docs-boundary        # or: bash scripts/check-docs-boundary.sh
```

The gate scans `docs/` — tracked *and* untracked files, so a brand-new document
is covered before it is ever staged — and exits non-zero naming each offending
file. It fails closed (exit 2) if the scan itself cannot run, rather than
reporting a clean tree.

**The denylist of identifiers lives in exactly one place: the script.** This
document deliberately does not restate it. Repeating the pattern here would
reinstate, in a single world-readable file, every identifier the sweep removed
from the other thirteen — the exposure the convention exists to prevent. If you
need the pattern for an ad-hoc grep, ask the script for it:

```sh
git grep -nE "$(scripts/check-docs-boundary.sh --print-pattern)" -- 'docs/'
```

Stated structurally, the gate rejects host and node names, the DNS domain, the
SSH key name, and the internal subnet of the maintainer's private validation
environment. You do not need to know any of them to stay clear of all of them:
writing to the [placeholder conventions](#placeholder-conventions) above — RFC
5737 addresses, `example.com`-family domains, role-shaped node names — passes
the gate by construction.

The gate runs as part of `scripts/test-scripts.sh`, which `make test` invokes,
so a document reintroducing an identifier fails pre-commit validation. No new
CI workflow or required check was added for it (Issue #3417).

## Operational gap closure (AC#4)

The former `docs/operations/lab-secrets-inventory.md` documented private
environment-specific credential paths. That document was removed from this
repository. The underlying operational gap it recorded — cleartext
`EnvironmentFile=` paths referencing `ha-secrets.env` in the cluster bootstrap
script — was independently resolved by story **#3422** (closed 2026-08-20) via
**PR #3465**, which removed the `EnvironmentFile=/etc/cfgms/ha-secrets.env` line
from `scripts/ha-cluster-node-bootstrap.sh`. The gap is closed; there is no
open item to document here.

The ownership-boundary text that previously appeared in lab inventory prose is
now expressed as a product-level principle in
[ADR-030](../architecture/decisions/030-controller-secret-material-at-rest.md)
Decision 4, where it applies to every CFGMS deployment, not one specific
environment.
