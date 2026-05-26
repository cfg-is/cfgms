# v0.9.6 Consolidation + AGPL Governance Release Playbook (Story #1751)

This directory is the **execution playbook** for the founder-action items in [Issue #1751](https://github.com/cfg-is/cfgms/issues/1751) — the closeout story for the v0.9.6 release (Epic #1716 AGPL migration + the v0.9.0–v0.9.5 work consolidation, per [`docs/product/roadmap.md`](../../product/roadmap.md)).

## What's here

| File | Purpose | AC item |
|---|---|---|
| `01-changelog-entry.md` | Reference copy of the CHANGELOG entry that was added to `/CHANGELOG.md` in this same PR. | #1 (delivered in this PR) |
| `02-release-notes.md` | Drop-in body for the `v0.9.6` GitHub release, with the `gh release create` command. | #2 |
| `03-repo-metadata.md` | Description + topics diff and `gh repo edit` commands. | #3 |
| `05-followup-issues.md` | Two follow-up issue bodies (cfg.is website + commercial-license intake) with `gh issue create` commands. | #4 |

(File 04 for fork-owner notification was dropped on 2026-05-25 — investigation showed the only known fork (SAY-5/cfgms) has zero post-fork upstream engagement and the owner's single interaction was a one-time PR; no notification warranted. AC #4 was removed from #1751 on the same day.)

## How to use

1. **Now (PR review):** read each artifact. Edit wording in-place. Suggest changes via PR review comments if you want a different angle.
2. **At execution time (after all #1716 sub-stories merge):** run the `gh` commands from each artifact in order. Most are single-line commands; the release-notes flow uses `--notes-file` against the artifact directly.
3. **After execution:** decide whether to keep this directory as historical record OR delete it in a follow-up commit. See "Disposition" below.

## Disposition

This directory contains **execution artifacts**, not durable documentation. The CHANGELOG entry (the actual durable record) lives in `/CHANGELOG.md`.

Three options:

- **Keep** as historical record of how the migration was executed — useful if anyone audits the relicense path later or wants the rationale captured in-tree.
- **Move** to `docs/governance/history/` after execution if you want it preserved but out of the active playbook surface.
- **Delete** the entire directory in a follow-up commit once #1751 is closed. The CHANGELOG entry remains; the playbook itself has done its job.

Default recommendation: **Keep**. The release notes, repo metadata diff, and commercial-license intake-process outline are reference material that future-you (and any successor) will want to find without reconstructing.

## Origin

Drafted by Claude on 2026-05-24 from the issue body, Epic #1716 strategic rationale, the existing CHANGELOG.md style, and the actual state of the repo at the time of writing (one known fork, current repo description/topics, etc.). Founder review and edits expected before any `gh` command is executed.
