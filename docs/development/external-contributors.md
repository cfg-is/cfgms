# External Contributors

This document describes how the CFGMS autonomous pipeline handles pull requests from contributors who are not trusted repository collaborators (`push`, `maintain`, or `admin` permission level).

## Quarantine model

The pipeline classifies every PR author by their GitHub collaborator permission level:

| Permission | Classification | Pipeline action |
|------------|---------------|-----------------|
| `admin`, `maintain`, `push` | Internal (trusted) | Normal review and merge flow |
| `triage`, `read`, `none` | External (untrusted) | Quarantined — pipeline skips |
| Unknown / API error | External (fail-closed) | Quarantined — pipeline skips |

Quarantine is enforced **before any `git fetch`, `git checkout`, container launch, or merge-queue enqueue** across all dispatch paths:

- `agent-dispatch.sh review-pr` — refused before cloning
- `agent-dispatch.sh create-clone-pr` — refused before cloning
- `agent-dispatch.sh check-pr-author` — explicit trust check (used by po-act.sh)
- `po-act.sh dispatch-fix` — refused before worktree creation
- `po-act.sh enqueue` — TOCTOU re-check before `gh pr merge --squash`

A quarantine comment is posted on the PR explaining the hold and linking to this document.

## Releasing a quarantined PR

A repository maintainer (push+) reviews the PR manually and, when satisfied:

1. Checks that the contributor has signed the CLA (see below).
2. Reviews the branch name — external authors cannot spoof an internal story link via a `feature/story-N-agent`-style branch name; the pipeline gates on author trust, not branch naming.
3. Applies the `human-reviewed:ok` label.

The label application event is recorded in the GitHub timeline. When the pipeline next processes the PR, it verifies that the actor who applied the label holds `push`, `maintain`, or `admin` permission. A label applied by another external actor is not accepted.

Once released, the PR flows through the normal autonomous review and merge path.

## Contributor License Agreement (CLA)

External contributors must sign the CLA before their work can be merged. To sign:

1. Read [docs/legal/CLA.md](../legal/CLA.md).
2. Add your name and GitHub username to `CONTRIBUTORS.md` in the same PR.
3. A maintainer can verify CLA status with:

   ```bash
   scripts/check-cla-signed.sh <github-login>
   ```

   Exit 0 = signed; exit 1 = not signed.

## Attribution

When an external-contributor PR is merged, the maintainer confirms attribution in the merge commit. The contributor's name and any co-author lines already in the PR are preserved by the squash merge.

## Branch-name impersonation

The pipeline does **not** use branch names as a trust signal. An external author naming their branch `feature/story-1234-agent` to impersonate a pipeline-dispatched story branch is detected and blocked: the branch-to-story link is suppressed for external PRs, and the author gate fires independently of the branch name.

## Cron dashboard output

The `po-cycle-preflight.py` preflight emits an `external_prs` list in its JSON output. The PO agent surfaces this in the dashboard under **EXTERNAL PR QUARANTINE**. Each entry shows the PR number, author login, head branch, title, and whether it has been released with `human-reviewed:ok`.
