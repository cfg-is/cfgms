# Regression corpus index

Defects this repository has had, each pinned to a commit where the defect is still present. A
sweep run against that commit either surfaces it or does not, which is a number.

The corpus answers two questions a sweep cannot answer about itself: does a given model find real
defects, and does a change to the harness make it find fewer.

## Entry rules

- `id` is permanent. Retire, never reuse.
- `commit` must be a commit where the defect is PRESENT, normally the parent of its fix.
- **An entry must be a defect, verified in the fix commit's own body.** A subject line is not
  evidence: a redesign, a refactor, or a salvage of files a previous commit missed all read like
  fixes and are not defects. An entry that was never a defect makes every score meaningless in
  the worst direction, marking a model down for not finding something that was never there.
- Seed an entry by hand only where a scenario has no historical instance, and mark it seeded so a
  score can be read with and without.

## Scoring rule

An entry is **found** when a sweep against its `commit` reports a finding whose `file` is one of
the entry's files and whose `vuln_class` matches. Line numbers are never compared -- they rot. A
finding on the right file with the wrong class is **near**, counted separately: the reviewer looked
in the right place and named the wrong thing.

A score is comparable only against another score over the same corpus revision. Record the
revision beside any number.

## The corpus is not the only signal

A model that finds every entry has found defects someone already fixed. That is a regression check,
not a measure of what a sweep is for.

Closure rate -- the share of hypotheses a lane resolves as `investigated` or `candidate_found`
rather than `inconclusive` -- pulls the other way: it rewards narrow, easily-closed hypotheses and
punishes the broad cross-boundary guess most likely to find something deep. Read the two together,
never either alone, and never tune a prompt against one of them.

## Entries

Detail lives outside this repository, under `$CFGMS_SECURITY_REVIEW_BASE/corpus/<id>.json`
(default `~/.cache/cfgms-security-review/corpus/`), because an entry describes a defect that is
still present at the commit it names. This index carries only what is safe to publish.

| id | commit | fixed by | scenario | class | defect |
|---|---|---|---|---|---|
| RC-01 | `2917eafe` | `3d03e725` | TS-12 | CWE-269 | operator payload dispatch had no server-side bound on how many targets one signed payload could reach |
| RC-02 | `70a1c805` | `46e8ee71` | TS-15 | CWE-345 | a composition path yielding a nil audit store passed storage validation, so a controller could run with no audit trail and fail only at first write |

Two entries is a small corpus. Small and verified beats large and wrong: a score over these two is
meaningful, and a score over five where three were never defects is not. Entries are added as real
sweeps confirm findings, and as fix commits are read rather than skimmed.

## Candidates rejected on inspection

Kept so they are not re-proposed. Each looked like a fix and was not:

- Registration moving the keypair generation to the steward. A deliberate redesign (ADR-032), not a
  defect in the flow it replaced.
- Cluster-visible revocation list. Architecture work, and the commit is partly a salvage of files an
  earlier commit left untracked.
