# CFGMS Documentation

Choose a reading path for the task. Each topic's owner describes its contract;
indexes route readers rather than repeat configuration, commands or policy.

| Task | Start here |
|---|---|
| Understand the product and release direction | [Vision](product/vision.md), [roadmap](product/roadmap.md) |
| Get a working environment | [Quick start](../QUICK_START.md), [deployment selector](deployment/README.md) |
| Operate or diagnose a deployment | [Operations](operations/README.md), [administration](administration/README.md), [troubleshooting](troubleshooting/README.md) |
| Configure a managed resource | [Module reference](modules/README.md), [config schema](reference/config-schema.md), [inheritance](guides/configuration-inheritance.md) |
| Integrate with an API or M365 | [REST guide](api/rest-api.md), [M365 setup](M365_INTEGRATION_GUIDE.md) |
| Develop CFGMS | [Workstation setup](../DEVELOPMENT.md), [architecture map](../ARCHITECTURE.md), [development workflow](development/README.md) |
| Plan or accept an epic | [Shared planning contract](development/product-planning.md) and the relevant role entry |
| Review web design direction | [Design system](design/web-ui-design-system.md), [reference mockups](design/mockups/README.md) |
| Select validation/evidence | [Testing](testing/README.md), [release checklist](testing/release-validation-checklist.md) |
| Review trust, access or reporting a vulnerability | [Security architecture](security/architecture.md), [reporting policy](../SECURITY.md) |
| Understand license/contributor requirements | [Licensing](../LICENSING.md), [legal documents](legal/README.md) |

[ADRs](architecture/decisions/README.md) preserve relevant decisions and lineage;
accepted decisions, current implementation and approved future direction are
different evidence. [Retained records](archive/README.md) need a current consumer;
“historical” alone does not justify keeping obsolete instructions.

Pipeline/security-review tooling has its own owner in the pinned `.claude/tooling`
repository. Product documentation and the remaining in-repo role/config entry
points must not become a duplicate tooling manual. See the
[documentation currency contract](development/product-planning.md#documentation-currency).
