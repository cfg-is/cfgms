# Pin Bump Decision Matrix

The full bump-or-hold rationale that backs the summary table in SKILL.md. Loaded by Claude in Phase 3.

## The matrix

| # | Has active CVE blocking required CI? | Cooldown elapsed? | Newer release exists? | Verdict | Notes |
|---|---|---|---|---|---|
| 1 | Yes | (any) | Yes | **BUMP NOW** | Cooldown overridden — vulnerability is its own justification. Write audit-log entry. |
| 2 | No  | Yes | Yes | **BUMP** | Routine refresh. No urgency. |
| 3 | No  | No  | Yes | **HOLD** | Within cooldown window. Report the unlock date in the founder summary. |
| 4 | No  | (n/a) | No  | **OK** | Up to date. |
| 5 | Yes | (n/a) | No  | **INVESTIGATE** | We're pinned at a vulnerable version with no fix available. Escalate. |

## What counts as "active CVE blocking required CI"

Concrete evidence — not just "this version has a CVE in some advisory database." All three of:

1. The CVE affects the `current` version (vulnerable version range includes it).
2. The CVE has severity `HIGH` or `CRITICAL` (medium/low don't override cooldown).
3. The CVE is detected by a required CI check — `security-deployment-gate`, `unit-tests`, `integration-tests`, or `Build Gate` — that is currently failing or has failed in the last 5 runs.

Evidence for criterion 3 is the Trivy SARIF artifact downloaded in Phase 2's CI-driven-signal step. If the SARIF lists `Installed Version: <current>` for a HIGH/CRITICAL CVE, criterion 3 is met.

If a CVE is in the advisory database but no CI check has surfaced it, this is **BUMP** (eligible normally) not **BUMP NOW** — wait for the cooldown.

## What counts as "cooldown elapsed"

`now - published_at >= cooldown_days` where `cooldown_days` is the per-pin cooldown threshold from `cooldown-policy.md`.

Default cooldown is **3 days**. Per-pin overrides allowed for higher-risk pins (the Go toolchain itself, anything in the security gate's hot path).

Cooldown is measured from the release's `published_at` timestamp returned by the upstream API, NOT from when we noticed.

## Worked examples

### Example 1 — the 2026-05-12 incident (Verdict: BUMP NOW)

- Pin: `go-toolchain`, current `1.25.9`
- Latest: `1.25.10`, published 2026-05-09 (3 days ago)
- CVEs in 1.25.9: CVE-2026-33811, 33814, 39820, 39836, 42499 — all HIGH severity, ecosystem GO, package stdlib
- CI signal: docker-security gate failing on PR #1426 since 2026-05-11; Trivy SARIF lists `Installed Version: v1.25.9` for all five CVEs
- Cooldown: 3 days elapsed; would have qualified for BUMP anyway, but **CI-driven override applies regardless**

Verdict: **BUMP NOW**. Audit log:

```
2026-05-12T15:30:00Z  go-toolchain  1.25.9→1.25.10  CVE-2026-33811 (+4) blocking security-deployment-gate  story:#NNNN
```

### Example 2 — newly-released minor bump, no urgency (Verdict: HOLD)

- Pin: `trivy`, current `v0.70.0`
- Latest: `v0.71.0`, published 2 days ago
- CVEs in v0.70.0: none in GHSA
- CI signal: none — docker-security gate is green on the latest develop runs
- Cooldown: NOT elapsed (2 < 3 days)

Verdict: **HOLD**. Founder summary line: `trivy v0.70.0→v0.71.0 — released 2 days ago; waiting until <date>`

### Example 3 — newer release, past cooldown, no CVE (Verdict: BUMP)

- Pin: `gosec`, current `v2.27.1`
- Latest: `v2.27.1`, published 4 days ago
- CVEs in v2.27.1: none
- CI signal: none
- Cooldown: elapsed (9 > 3 days)

Verdict: **BUMP**. Story body explains: routine refresh, past cooldown, no urgency. Cooldown block is `Cooldown elapsed (9 days since release; threshold 3 days)`.

### Example 4 — pinned-at-vulnerable, no fix available (Verdict: INVESTIGATE)

- Pin: `somepkg`, current `v1.2.3` (latest)
- CVEs in v1.2.3: CVE-2026-XXXXX, HIGH
- CI signal: yes (Trivy is flagging it)
- No newer release exists

Verdict: **INVESTIGATE**. Don't create a bump story (there's nowhere to bump to). Create a `high-priority` tracking issue describing the pin, the CVE, and the lack of upstream fix — assign to founder and set Blocked status via `po-act.sh block`. The skill should print this case explicitly in the report so the founder can escalate to the upstream or accept the risk.

## MCP server pins (kind `mcp`, e.g. serena)

MCP server pins run the **same** CVE/cooldown matrix above to decide *whether* to bump (cooldown is the default 3 days from the tag's `published_at`; an active HIGH/CRITICAL advisory affecting our pinned tag overrides it). What's different is a second, blast-radius classification that decides *what kind of story* the bump produces — because these are agent **tooling** dependencies: the planning and dev agents consume their tools by name (`mcp__<server>__<tool>` appears in `.claude/agents/*.md` `tools:` allowlists **and** instruction prose). A release that renames or removes a consumed tool silently breaks those agents — the `tools:` grant stops matching and the agent falls back to grep (or errors), which a one-line version bump would ship unnoticed.

### Step A — research the consumed-tool delta (Phase 2 add-on)

For an `mcp` pin with a newer release past cooldown:

1. **Our consumed surface:** `grep -rhoE 'mcp__<server>__[a-z_]+' .claude/agents/ .mcp.json | sort -u` — the exact tools we depend on by name (e.g. `mcp__serena__find_symbol`, `find_referencing_symbols`, …).
2. **Upstream tool-surface change between `current` and `latest`:** WebFetch the release notes / CHANGELOG for every tag in `(current, latest]` and look for renamed, removed, or signature-changed tools. (GHSA rarely resolves a git-installed server, so release notes are also the CVE source — `ecosystem`/`package` are null by design.)
3. **Intersect.** A change is **breaking for us** only if it touches a tool in our consumed surface (a renamed tool we don't use is irrelevant).

### Step B — classify the bump

| Consumed-tool delta | Story shape | Auto-mergeable? |
|---|---|---|
| None of our consumed tools renamed/removed/changed (patch/minor, additive only) | **Mechanical bump** — one-line `.mcp.json` tag change. Standard pin-bump story (`assets/story-template.md`); `locations[]` is just the `.mcp.json` line. | Yes, normal pipeline |
| Any consumed tool renamed / removed / signature-changed | **REWIRE story** — see below | **No** — needs deliberate review |

### The rewire story (breaking change)

Title it `deps: rewire <server> <from> → <to> (breaking: <tool> renamed/removed)` and expand the scope beyond `.mcp.json`:

- `.mcp.json` — bump the tag.
- **Every `.claude/agents/*.md`** returned by `grep -rl 'mcp__<server>__' .claude/agents/` — update the `tools:` frontmatter allowlist entries AND the instruction prose that names the old tool, in lockstep.
- Acceptance must include a **fresh-spawn smoke test** of an affected agent: spawn it and have it call a renamed/new tool directly, asserting it resolves. (Agent-definition edits hot-load on the next fresh subagent spawn — no restart — but an agent's self-report of its own toolset is unreliable, so force the actual tool call rather than asking it to introspect.)
- Note the lockstep hazard explicitly in the body: bumping `.mcp.json` without updating the allowlists ships agents whose serena grant silently no-ops.

This is the one pin class where the bump is **not** purely mechanical — treat a breaking `mcp` bump as a real rewire, not a version swap. When in doubt about whether a change is breaking, classify as REWIRE (false-positive costs one review; false-negative ships broken agents).

## Multiple CVEs in one pin

Aggregate by maximum severity. If a pin has both LOW and HIGH CVEs, treat it as HIGH.

In the audit log, list the highest-severity CVE ID followed by `(+N more)` rather than listing all of them.

## When to use the `--urgent` flag

`--urgent <pin-name>` forces BUMP NOW for that pin even when no CVE is in evidence. Use only when:

- Trivy / external scanner has flagged a CVE we know about but the GHSA query hasn't picked it up yet
- A supply-chain incident is reported on the pinned version
- The founder explicitly invokes it after their own threat-assessment

Every `--urgent` use generates an audit log line with reason field set to whatever the founder passed after the flag (or "founder-override" if no reason given).
