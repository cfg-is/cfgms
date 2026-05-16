# cfg-agent PAT Scope Audit

## Audit Date

2026-05-16

## Purpose

Documents the GitHub Personal Access Token (PAT) scopes held by `cfg-agent` (the
automation account used by Claude Code agents), and records the rationale for each
scope. Performed as the pre-requisite for Story #1476 (Projects V2 substrate
bootstrap) to ensure no silent scope expansion occurs.

## Audit Methodology

Scopes were read via `gh auth status` against the active token before any expansion
was attempted. The token identity was confirmed as the `jrdnr` account using the
`GH_TOKEN` environment variable, which is the cfg-agent operating credential in the
CI/agent container environment.

## Scopes at Audit Time

| Scope | Required? | Rationale |
|-------|-----------|-----------|
| `repo` | Yes | Full repository access — required for issue, PR, and branch operations in `cfg-is/cfgms` |
| `workflow` | Yes | GitHub Actions workflow file read/write — required for CI pipeline management |
| `read:org` | Yes | Read organization membership and teams — required for org-level project queries |
| `project` | Yes | GitHub Projects V2 read/write — required for queue operations on `cfgms-pipeline` board |
| `gist` | No | Not used by any current pipeline script; present from initial PAT generation |

## Expansion Decision

`project` scope was already present in the token at audit time. **No expansion was
required.** Story #1476 AC5 specifies that audit must precede expansion; since the
token already carried `project` scope, the expansion step is a no-op and the
idempotency requirement is satisfied.

## Gist Scope

The `gist` scope is not used by any current pipeline script and carries no known
risk (it grants write access only to the token owner's gists, not to org resources).
It may be removed on the next PAT rotation cycle if operational review confirms it
remains unused.

## Next PAT Rotation

PATs should be rotated on a 90-day cadence. The next rotation should audit whether
`gist` scope can be dropped and document any new scopes added for subsequent stories.
