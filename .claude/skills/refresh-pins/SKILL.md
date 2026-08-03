---
name: refresh-pins
description: Research all pinned dependencies and the Go toolchain version against
  their upstream latest releases, apply a 3-day cooldown plus CVE-driven override
  policy, and create stories for pins that should be bumped. Use after the weekly
  `dependency-pins` GitHub issue lands, when Trivy or the docker-security gate
  flags a CVE in a currently-pinned version, when the weekly dependency-cve-scan
  reports a CVE against a `go.mod` module, or when the founder asks about pin
  freshness. Loads the full decision rationale and cooldown policy from
  references/ lazily — do not pre-load them. Outputs a single Markdown summary
  and one GitHub story per pin that should be bumped.
context: fork
agent: general-purpose
allowed-tools: Bash, Read, Write, WebFetch
---

# Refresh-Pins Skill

You research the state of every pinned dependency in the repo, apply the cooldown + CVE policy, and create dispatchable stories for the ones that need bumping. You produce one Markdown summary back to the founder, no chatter.

## Inputs

`$ARGUMENTS` is one of:

- empty — sweep every pin
- `<pin-name>` — focused single-pin run (e.g. `go-toolchain`, `trivy`, `gosec`)
- `--urgent <pin-name>` — CVE-driven; skip the cooldown gate, log the override
- `--urgent <go-module-path>` — a Go **module** dependency rather than a pinned
  tool (e.g. `go.opentelemetry.io/otel`). See "Dependency CVEs" below; these are
  not in the pin inventory and must not be treated as a missing pin.

## Phase 1: Discover

Run the discovery script to build the pin inventory:

```bash
./.claude/skills/refresh-pins/scripts/discover-pins.py
```

Output is JSON conforming to `references/inventory-schema.md` (load that file lazily if you need to interpret a field). Each pin entry has: `name`, `kind` (`lockstep` | `tool`), `current` version, `release_source` (URL or `gh:<org>/<repo>`), and `locations[]` of every file:line where the pin appears.

If `$ARGUMENTS` names a specific pin, filter the inventory to that pin only. Halt with a clear error if the named pin isn't in the inventory — **unless** it looks like a Go module path (contains `/` and a dot in its first segment, e.g. `go.opentelemetry.io/otel`), in which case follow "Dependency CVEs" below instead.

### Dependency CVEs (go.mod modules, not pinned tools)

The weekly `dependency-pins` issue carries two distinct kinds of finding. The
`Outdated Pinned Tool Versions` section is what `discover-pins.py` covers. A
`Dependency CVEs` section is **not** — it comes from the `dependency-cve-scan`
job running Nancy against the whole `go.mod` graph, and those modules are
deliberately absent from the pin inventory (the script reads go.mod only for the
`toolchain` directive).

These matter because they are the one class no PR or merge-queue scan can find:
the advisory is published against a dependency already merged, so nothing in the
diff moves and no code-triggered scan re-examines it.

For each affected module:

1. Find the first patched version — the Nancy output links the Sonatype Guide
   advisory, and `gh api graphql` GHSA (ecosystem `GO`, package = module path)
   gives `firstPatchedVersion.identifier`.
2. Check whether the module is a direct or indirect requirement
   (`go list -m -f '{{if .Indirect}}indirect{{else}}direct{{end}}' <module>`).
   An indirect dependency usually moves by bumping its parent instead.
3. **Skip the cooldown gate.** A CVE against a merged dependency is already
   shipping; the 3-day soak protects against regressions in fresh releases, not
   against a known-vulnerable status quo. Log the override in Phase 5 exactly as
   for a tool pin.
4. Create the story against `go.mod`/`go.sum` rather than the pin locations, and
   have it state the CVE ID, the current and target versions, and that
   `make security-deps` (with `GUIDE_TOKEN` exported) is the verification step.

## Phase 2: Research

For each pin (run in parallel where independent — separate Bash calls in one assistant turn):

1. **Latest stable version + published_at**
   - `gh:<owner>/<repo>` release source: `gh api repos/<owner>/<repo>/releases/latest --jq '{tag_name, published_at}'`
   - `https://go.dev/dl/?mode=json` source: `curl -fsSL 'https://go.dev/dl/?mode=json' | jq '[.[] | select(.stable)][0] | {version, files: [.files[] | select(.kind=="source")][0].sha256}'`
2. **CVEs against the current pinned version** — `gh api graphql` GHSA query:
   ```graphql
   query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
     securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 20) {
       nodes {
         severity
         advisory { ghsaId summary }
         vulnerableVersionRange
         firstPatchedVersion { identifier }
       }
     }
   }
   ```
   For Go stdlib use ecosystem `GO`, package `stdlib`. For tools that don't resolve cleanly through GHSA, fall back to a `WebFetch` of their release notes for the latest version and look for "CVE" mentions.
3. **CI-driven signal** — check whether the current pin is actively blocking CI:
   ```bash
   gh run list --repo cfg-is/cfgms --workflow docker-security.yml --status failure --limit 5 \
     --json databaseId,headSha --jq '.[].databaseId' | head -3 | while read run_id; do
       gh api "repos/cfg-is/cfgms/actions/runs/$run_id/artifacts" --jq '.artifacts[] | select(.name | contains("trivy")) | .archive_download_url'
   done
   ```
   Then for each artifact URL, download, unzip, and grep the SARIF for `"Installed Version": "<current_pin>"`. A match means the gate is currently failing on this exact pin → flag for cooldown override.
4. **MCP pins only (`kind: mcp`, e.g. serena)** — research the **consumed-tool delta**: the set of `mcp__<server>__<tool>` names we use (`grep -rhoE 'mcp__<server>__[a-z_]+' .claude/agents/ .mcp.json | sort -u`) versus any tool renamed/removed/signature-changed between `current` and `latest` (WebFetch the release notes for each intervening tag). This is what Phase 3 needs to classify the bump as mechanical vs. breaking. Release notes are also the CVE source for these pins (GHSA rarely resolves a git-installed server; `ecosystem`/`package` are null).

## Phase 3: Justify (apply the decision matrix)

Load `references/decision-matrix.md` and `references/cooldown-policy.md` only now (lazy).

Apply the matrix per pin. The summary table:

| Has active CVE blocking CI? | Cooldown elapsed? | Decision |
|---|---|---|
| Yes | (override) | **BUMP NOW** + audit log entry |
| Yes | Yes | **BUMP** |
| No | Yes | **BUMP** |
| No | No | **HOLD** until cooldown elapses |
| No newer release | — | **OK** |

For each pin, record a 1-paragraph justification block citing: current/latest versions, release date, days since release, the cooldown threshold applied, any CVE IDs found, and any CI-blocking signal observed.

If `$ARGUMENTS` started with `--urgent`, force BUMP NOW for the named pin regardless of cooldown — but still write the override line to the audit log.

## Phase 4: Create stories

For each pin with verdict BUMP or BUMP NOW:

> **`kind: mcp` pins** carry an extra blast-radius classification (decision-matrix.md "MCP server pins"). If the consumed-tool delta (Phase 2 step 4) shows a tool we use was renamed/removed/changed, this is a **REWIRE story** — expand the scope to every `.claude/agents/*.md` that names the tool (allowlist + prose) plus `.mcp.json`, title it `deps: rewire <server> ... (breaking: ...)`, require a fresh-spawn smoke test in the ACs, and mark it **not auto-mergeable** (human-reviewed). A non-breaking `mcp` bump uses the standard one-line template below.

1. Read `assets/story-template.md` (lazy load)
2. Substitute placeholders:
   - `{{NAME}}` — pin name (e.g. `go-toolchain`)
   - `{{FROM}}` — current version
   - `{{TO}}` — latest version
   - `{{JUSTIFICATION}}` — paragraph from Phase 3
   - `{{LOCATION_COUNT}}` — number of file:line entries
   - `{{LOCATION_LIST}}` — bullet list of every `file:line` to touch
   - `{{FROM_PATTERN}}` / `{{TO_PATTERN}}` — regex-escaped version strings for grep verification
   - `{{SCOPE_PATHS}}` — comma-separated paths to grep within (derived from `locations`)
   - `{{COOLDOWN_BLOCK}}` — "Cooldown elapsed (N days since release)" OR "Cooldown OVERRIDE: CVE-X blocking <gate>"
3. Write the instantiated body to `/tmp/refresh-pins-<slug>.md`
4. Create the story as a PRIVATE project draft (never a public issue). Pass the
   dependency-pins tracking epic as the parent, or `0` if there is none:
   ```bash
   bash ./scripts/pipeline-helper.sh create-story <epic_num_or_0> \
     "deps: bump <name> <from> → <to> (<short-reason>)" \
     /tmp/refresh-pins-<slug>.md
   # Returns CREATED_DRAFT:<item_id>, status Draft by default.
   ```
5. Capture the returned `item_id` for the report.

**Before creating a story, check for an existing open one for the same pin.**
Title text is not a reliable match key — story titles have drifted across
sweeps (`deps: bump X ... (Issue #2675)` vs `ci: bump X ...`), so two stories
for the identical pin+SHA bump can have completely different titles. Instead:

1. List every open issue for the repo (`gh issue list --state open --json
   number,title,body --limit 200`) plus `project-queue.sh list-by-status
   Draft` and `list-by-status Ready` for undispatched drafts.
2. Match on the pin's **canonical identifier** appearing in the body/scope —
   e.g. the `uses:` action path (`actions/checkout`, `github/codeql-action`),
   the binary/package name (`trufflehog`), or the pin's current SHA/version
   string — not the free-text title.
3. If a match is found: diff the two stories' "Files In Scope" lists against
   the live discovery-script inventory. Keep whichever is a superset /
   more accurate (a later sweep may have found locations, including
   commented-out lines, that an earlier one missed); update that story's body
   in place via `project-queue.sh` / `pipeline-helper.sh` rather than creating
   a new one, and close the other as superseded if it's already a public
   issue, or delete the draft if it never materialized.
4. Only create a new story once you've confirmed no open issue already
   targets this pin.

Do not create a public issue for a pin that already has one open — this
produces duplicate stories racing two dev agents onto the same workflow
lines (observed 2026-07-29: 4 of 6 stories in a sweep duplicated already-open
`Ready` stories from a prior sweep, undetected by title matching).

## Phase 5: Cooldown override audit (if any BUMP NOW)

For each BUMP NOW verdict, append one line to `.claude/scratch/pin-overrides.log`:

```
<ISO-8601 UTC>  <pin-name>  <from>→<to>  <CVE-or-reason>  story:#<NNNN>
```

Create the file if it doesn't exist. Append only — never rewrite.

## Phase 6: Report to the founder

Single Markdown summary, sections in this order (omit empty sections):

```markdown
## Pin Refresh — <local time, e.g. 11:51 EDT>

### Bumping immediately (CVE-driven, cooldown override)
- <name> <from>→<to> — <CVE-ID> blocking <gate>; story #NNNN

### Bumping (cooldown elapsed)
- <name> <from>→<to> — released <N> days ago; story #NNNN

### Holding (within cooldown window)
- <name> <from>→<to> — released <N> days ago; waiting until <YYYY-MM-DD>

### Up to date
- <count> pins up to date (collapsed; expand on request)

### Stories created
- #NNNN — deps: bump <name>
- ...
```

## Rules

- **Lazy-load references**: do not read `references/decision-matrix.md`, `references/cooldown-policy.md`, or `references/inventory-schema.md` until Phase 2/3 needs them. They are not in your context until you Read them.
- **One story per logical pin**, not per file. `go-toolchain` is one story that touches all 13 file:line locations in lockstep.
- **No code edits**: this skill creates stories, it does not edit go.mod / workflows / Dockerfiles directly. Dispatched dev agents apply the bumps under the regular pipeline.
- **CI-blocking pins skip cooldown**: a vulnerability that's actively failing required CI is its own justification — don't wait the 3 days.
- **Dependency CVEs skip cooldown too**: a `Dependency CVEs` finding is published against code already merged, so the vulnerable version is the status quo, not the risk being soaked against. Bump to the first patched version and log the override.
- **Never report a scan that could not run as clean**: if `make security-deps` reports a missing `GUIDE_TOKEN`, or the weekly `dependency-cve-scan` job failed before scanning, say so explicitly. Nancy returns 401 without a Sonatype Guide token, and an unauthenticated run produces no evidence rather than a clean result.
- **Audit every override**: every BUMP NOW that overrides cooldown gets a line in the audit log. No exceptions.
- **Idempotent**: re-running the skill produces the same stories (or comments on existing ones if they already exist). No duplicates.
