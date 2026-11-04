# Contributing to CFGMS

Read the [Code of Conduct](CODE_OF_CONDUCT.md), then use
[DEVELOPMENT](DEVELOPMENT.md) for workstation/build setup. Current product goals
and release priorities are in the [vision](docs/product/vision.md) and
[roadmap](docs/product/roadmap.md).

## Report an issue or propose work

Use a public [community issue](https://github.com/cfg-is/cfgms/issues) for bugs,
questions or feature requests. Do not include credentials, client-identifying
information or undisclosed vulnerability detail. Use [SECURITY](SECURITY.md) for
security reports.

Locked `internal` issues are pipeline work items; they are not a request for
public comments. The private project body is the authoritative pipeline spec.
Open a community issue for discussion rather than trying to modify a locked
item. Story materialization follows ADR-015 at decomposition; sensitive bodies
can remain private until dispatch. [External contributor guidance](docs/development/external-contributors.md)
explains the separate PR/quarantine path.

## Prepare a contribution

- Branch from `develop`; submit PRs to `develop`, following the current
  [git workflow](docs/development/git-workflow.md).
- Check existing source/issues before adding another implementation or plan.
- Follow [coding/testing/documentation standards](docs/development/standards/README.md)
  and the relevant [architecture contract](ARCHITECTURE.md).
- Include meaningful error/tenant-boundary coverage and report actual validation,
  including skips and platform/live-service checks not run.
- Update current documentation and references when behavior changes. Consolidate
  superseded instructions rather than append a permanent progress report.
- Follow [commit/PR standards](docs/development/commit-and-pr-standards.md), describing
  the observable change and evidence without invented timings or readiness claims.

## Contributor agreement and licensing

Contributors must complete the [CLA](docs/legal/CLA.md) and contributor record in
[CONTRIBUTORS](CONTRIBUTORS.md) under the current legal process. The CLA owns its
terms; this page does not restate or change them. Maintainers use the
[enforcement procedure](docs/legal/CLA-ENFORCEMENT.md).

The repository is AGPL-3.0; [LICENSING](LICENSING.md) explains the commercial
embedding offer and actual [LICENSE](LICENSE) remains the legal text. Tenant or
cluster topology is not a different in-repository license tier.
