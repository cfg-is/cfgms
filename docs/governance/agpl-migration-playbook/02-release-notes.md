## Track 2 Artifact 2: v0.8.0-governance release notes

**For `gh release create v0.8.0-governance --notes-file <this file>`** (paste the body below; the `gh release create` invocation is shown at the bottom):

---

# v0.8.0-governance — License change to AGPL-3.0

This is a **governance release**, not a feature release. It tags the moment cfgms transitioned from the Apache-2.0 + Elastic License v2 dual-license model to a single **AGPL-3.0** license covering the entire repository.

## What changed

### Licensing

- `LICENSE` is now the GNU Affero General Public License v3.0 — full text in the repository root.
- `LICENSE-APACHE-2.0` and `LICENSE-ELASTIC-2.0` are removed.
- Every `.go` file in the source tree carries `SPDX-License-Identifier: AGPL-3.0-only`.
- A separate **commercial-embedding license** is available via cfg.is for third parties who need to embed CFGMS components in proprietary products without AGPL obligations. See [`LICENSE.CommercialLicenses.md`](LICENSE.CommercialLicenses.md) and email **licensing@cfg.is**. No code in the public repository is covered by the commercial license — every public-tree file is AGPL-3.0.

### Contributor License Agreement

- CLA upgraded to **v2.0** ([`docs/legal/CLA.md`](docs/legal/CLA.md)). The license-grant language was broadened from "Apache-2.0 + Elastic-2.0" to "any license selected by the Copyright Holder at its sole discretion", so future license changes do not require re-papering contributors. AI-assisted contribution disclosure was added to §5(f). The §1 copyright assignment is retained.

### HA clustering

- The `commercial/ha/` build-tag split is removed. HA (Raft consensus, failover, split-brain protection) now ships in every build from `pkg/ha`. No build tag needed; no separate edition.

### CI and tooling

- `.github/workflows/license-check.yml` no longer treats AGPL as a forbidden third-party dependency license — AGPL deps are now compatible with cfgms's own license.
- `docs/architecture/ha-commercial-split.md` and `docs/product/feature-boundaries.md` are removed (the OSS-vs-commercial feature table no longer exists).
- `LICENSING.md`, `README.md`, `CLAUDE.md`, and the architecture/guide docs have been swept to remove dual-license references.

## What this means for you

| You are… | What changes |
|---|---|
| **A self-hosting MSP or IT team** running cfgms on your own infra to manage your own (or your clients') endpoints | Nothing operationally. AGPL permits this fully. If you modify cfgms and expose the modifications via the network, AGPL §13 requires you to publish the corresponding source. |
| **A SaaS competitor** thinking about hosting a modified cfgms as a public service | AGPL §13 obligates you to publish your modifications under AGPL. |
| **An RMM or platform vendor** wanting to embed cfgms code in a proprietary product | The public AGPL terms make code-level embedding incompatible with a closed-source product. A separate commercial-embedding license is available — email **licensing@cfg.is**. |
| **An existing fork owner** as of 2026-05-24 | Your fork is grandfathered under its original Apache-2.0 license. Any merges from upstream after this date carry AGPL-3.0 terms. We've reached out individually. |
| **A new contributor** | The CLA v2.0 governs your contributions. CLA Assistant will surface the agreement on your first PR. |

## Strategic rationale

See Epic [#1716](https://github.com/cfg-is/cfgms/issues/1716) for the full reasoning. Short version: at cfgms's current adoption stage, AGPL-3.0's copyleft is the appropriate deterrent against RMM-incumbent embedding without acquiring or licensing. The dual-license model carried ongoing complexity without a corresponding defensive payoff today. AGPL→Apache is a unilateral move available later if and when permissiveness is worth more than single-license simplicity.

## Issues included

- #1716 — Epic
- #1744 — CLA v2.0 amendment (merged in PR #1753)
- #1745 — Remove commercial build-tag split, relocate HA to `pkg/ha`
- #1747 — LICENSE rewrite + SPDX migration + CI license-check update
- #1748 — Rewrite LICENSING.md for AGPL-3.0 single-license model
- #1749 — Update README.md license section and CLAUDE.md licensing guidance
- #1750 — Sweep architecture and guide docs to remove dual-license references
- #1751 — This governance tag (you're reading it)

---

### CLI

```bash
# Replace HEAD if you want to tag a specific commit
gh release create v0.8.0-governance \
  --target develop \
  --title "v0.8.0-governance — License change to AGPL-3.0" \
  --notes-file docs/governance/agpl-migration-playbook/02-release-notes.md
```

Use `--prerelease` if you want it surfaced as not-the-latest. For a governance milestone I'd leave it as a regular release so GitHub UI shows it as the headline event.
