# CFGMS Licensing

CFGMS is licensed under the **[GNU Affero General Public License v3.0](LICENSE)** (AGPL-3.0).

## Copyright

All CFGMS code is copyrighted by **Jordan Ritz** (as of January 2026). When cfg.is is formed as a legal entity, copyright will be assigned to that entity as documented in the CLA.

Every source file includes:

```go
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
```

## Plain-English FAQ

### Can I self-host CFGMS?

Yes. Running CFGMS on your own infrastructure — whether on-premises or in your private cloud — is fully permitted under AGPL-3.0. No commercial license is required.

### Can I use CFGMS to manage client endpoints as an MSP?

Yes. Managing your clients' endpoints is standard self-hosted use and requires no commercial license.

### Can I modify CFGMS for internal use?

Yes. You may modify CFGMS and run the modified version internally without releasing your changes, as long as you are not distributing or providing network access to the modified software to external parties.

### When do I need a commercial license?

**The key question: are you embedding CFGMS source code inside your own product?**

- **Code-level embedding** (you compile CFGMS source into your proprietary product) — AGPL-3.0 requires you to release your product's complete corresponding source under AGPL-3.0. A commercial license waives this obligation.
- **Arm's-length API integration** (your product calls a separately running CFGMS controller over its REST or gRPC API) — this does **not** trigger AGPL-3.0's source-sharing obligation. Your product's source stays yours.

**You do NOT need a commercial license for:**

- Self-hosting CFGMS for your own organization or to manage your clients
- Integrating with a running CFGMS controller over its network API
- Modifying CFGMS for internal use

**You DO need a commercial license for:**

- Shipping CFGMS source compiled into your own proprietary product without releasing that product's source under AGPL-3.0
- Distributing modified CFGMS to third parties under terms incompatible with AGPL-3.0

### Does arm's-length API integration trigger AGPL?

No. If your product communicates with a separately running CFGMS controller over the network (REST API, gRPC), AGPL-3.0's network-copyleft clause applies only to the CFGMS binary itself — not to software that talks to it across a network boundary. Your integration code is unaffected.

### Do I need to open source my own tools that call CFGMS?

Only if you compile CFGMS source directly into those tools. If your tools interact with CFGMS through its network API, AGPL-3.0 does not require you to release your tools' source.

### Can I fork CFGMS?

Yes. You may fork CFGMS under AGPL-3.0. Forks distributed to third parties must be released under AGPL-3.0 with full corresponding source.

### What is the tenant hierarchy model?

CFGMS supports a recursive parent-child tenant hierarchy with unlimited depth, using path-based identification (e.g., `acme-msp/client-a/production`). Each controller deployment has a single root tenant. This model supports MSPs managing many clients within one CFGMS deployment.

### How do I get a commercial license?

Contact [licensing@cfg.is](mailto:licensing@cfg.is).

## Contributor License Agreement (CLA)

**All contributors must sign the CLA before their code can be merged.**

The CLA (v2.0) establishes that:

- Contributors **assign copyright** in their contributions to Jordan Ritz
- The Copyright Holder retains discretion to license contributions under any license (including AGPL-3.0 or a commercial license)
- Rights will **transfer to cfg.is** entity when formed

**To contribute:**

1. Read the CLA: [docs/legal/CLA.md](docs/legal/CLA.md)
2. Add your name to [CONTRIBUTORS.md](CONTRIBUTORS.md)
3. Submit your pull request

See [CONTRIBUTING.md](CONTRIBUTING.md#contributor-license-agreement-cla) for complete details.

## Contact

- **General questions**: Open a [GitHub Discussion](https://github.com/cfg-is/cfgms/discussions)
- **Commercial licensing**: [licensing@cfg.is](mailto:licensing@cfg.is)
- **Security issues**: See [SECURITY.md](SECURITY.md)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

---

For the complete legal text, see [LICENSE](LICENSE).
