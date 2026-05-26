## Track 2 Artifact 1: CHANGELOG.md entry

**Already added to [`/CHANGELOG.md`](../../../CHANGELOG.md) in this PR's first commit.** This file is a reference copy of what was added, for quick reference at execution time. The text below should match the current CHANGELOG.md `[0.9.6]` section — if they diverge, the live CHANGELOG.md is the source of truth.

```markdown
## [0.9.6] - 2026-05-24

Consolidation + AGPL governance release. Bundles the v0.9.0–v0.9.5 work that has shipped to `develop` since v0.8.1 (2026-01-25) but was never tagged, plus the AGPL-3.0 relicense (Epic #1716). See [`docs/product/roadmap.md`](docs/product/roadmap.md) for the full list of bundled v0.9.x epics.

### Changed

- **BREAKING (licensing)**: CFGMS is now licensed under **AGPL-3.0-only**. The previous Apache-2.0 + Elastic License v2 dual-license model has been retired (Epic #1716). Every file in the repository — controller, steward, protocol, integrations, CLI, workflow engine, and HA clustering — is now AGPL-3.0. A separate commercial-embedding license is available via cfg.is for third parties wishing to embed CFGMS in proprietary products without AGPL obligations; see [LICENSE.CommercialLicenses.md](LICENSE.CommercialLicenses.md).
- **CLA upgraded to v2.0** (Issue #1744, merged in PR #1753). §3 / §4 broadened to "any license selected by the Copyright Holder at its sole discretion" so future license changes do not require re-papering. §5(f) adds AI-assisted contribution disclosure. §1 copyright assignment retained.
- **High Availability (HA) is now in every build.** The `commercial/` build-tag split has been removed (Issue #1745). `pkg/ha` is the unified package — controllers built from the public source tree include Raft consensus, failover, and split-brain protection by default.

### Added

- `LICENSE` — full GNU AGPL-3.0 text (Issue #1747).
- `LICENSE.CommercialLicenses.md` — describes the outbound commercial-embedding license offering (Issue #1747).

### Removed

- `LICENSE-APACHE-2.0` and `LICENSE-ELASTIC-2.0` (Issue #1747).
- `commercial/` directory and the `commercial` build tag (Issue #1745).
- `docs/architecture/ha-commercial-split.md` and `docs/product/feature-boundaries.md` (Issue #1748, #1750).
- `"AGPL"` from `.github/workflows/license-check.yml` forbidden-dependency-licenses list (Issue #1747) — AGPL deps are now compatible with the project's own AGPL-3.0 license.

### Migration notes

- **Embedding CFGMS in a proprietary product**: contact licensing@cfg.is. The public repository remains AGPL-3.0 for all users.
- **Self-hosting CFGMS for your own organization (incl. as an MSP serving clients via the public network)**: AGPL-3.0 permits this. If you modify CFGMS and expose those modifications via the network, AGPL-3.0 §13 requires you to make corresponding source available to your users.
- **Existing forks** as of the migration date are grandfathered under their original Apache-2.0 license. Future merges from upstream after the relicense carry AGPL-3.0 terms.
```

### Notes

- I left the **existing** `## [0.7.0] - Unreleased` section alone — its "Dual Licensing" bullet describes the pre-migration state at the time that section was written. If 0.7.0 is never tagged, you may want to also revise that bullet during this commit. If 0.7.0 was already cut, leave it as historical record.
- The "Migration notes" section is the user-facing explainer that turns a one-line "we relicensed" into actionable guidance for the three audiences (proprietary embedders, self-hosters/MSPs, fork owners).
