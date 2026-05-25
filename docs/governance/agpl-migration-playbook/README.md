# AGPL-3.0 Migration Playbook (Story #1751)

This directory is the **execution playbook** for the founder-action items in [Issue #1751](https://github.com/cfg-is/cfgms/issues/1751) — the closeout story for Epic #1716 (license migration to AGPL-3.0).

## What's here

| File | Purpose | AC item |
|---|---|---|
| `01-changelog-entry.md` | Reference copy of the CHANGELOG entry that was added to `/CHANGELOG.md` in this same PR. | #1 (delivered in this PR) |
| `02-release-notes.md` | Drop-in body for the `v0.8.0-governance` GitHub release, with the `gh release create` command. | #2 |
| `03-repo-metadata.md` | Description + topics diff and `gh repo edit` commands. | #3 |
| `05-followup-issues.md` | Two follow-up issue bodies (cfg.is website + commercial-license intake) with `gh issue create` commands. | #5 |

**AC item #4 (fork-owner notification) is intentionally omitted.** Investigation surfaced one known fork (SAY-5/cfgms) but it has zero commits since the fork point, no upstream merges, and the fork owner's single interaction with cfg-is/cfgms (PR #850 against issue #849 on 2026-04-24) was a one-time contribution attempt — not active fork maintenance. No notification is warranted; #1751's AC #4 should be amended to reflect "no active fork-maintainers, no notification required" at execution time. The Apache-2.0 grandfathering protection for that fork stands without any action on our part.

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
