---
name: refresh-pins
description: Research all pinned dependencies and the Go toolchain version against
  their upstream latest releases, apply a 3-day cooldown plus CVE-driven override
  policy, and create stories for pins that should be bumped. Use after the weekly
  `dependency-pins` GitHub issue lands, when Trivy or the docker-security gate
  flags a CVE in a currently-pinned version, or when the founder asks about pin
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

## Phase 1: Discover

Run the discovery script to build the pin inventory:

```bash
./.claude/skills/refresh-pins/scripts/discover-pins.py
```

Output is JSON conforming to `references/inventory-schema.md` (load that file lazily if you need to interpret a field). Each pin entry has: `name`, `kind` (`lockstep` | `tool`), `current` version, `release_source` (URL or `gh:<org>/<repo>`), and `locations[]` of every file:line where the pin appears.

If `$ARGUMENTS` names a specific pin, filter the inventory to that pin only. Halt with a clear error if the named pin isn't in the inventory.

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
4. Create the story:
   ```bash
   gh issue create --repo cfg-is/cfgms \
     --title "deps: bump <name> <from> → <to> (<short-reason>)" \
     --label "story,dependencies" \
     --body-file /tmp/refresh-pins-<slug>.md
   ```
5. Add the new story to the project queue at Draft status:
   ```bash
   item_id=$(bash ./scripts/project-queue.sh add-issue <STORY_NUM> | python3 -c "import json,sys; print(json.load(sys.stdin)['item_id'])")
   bash ./scripts/project-queue.sh update-field "$item_id" status "Draft"
   ```
6. Capture the returned URL/number for the report

If a story for the same pin+version already exists (search by title with `gh issue list --search "deps: bump <name> <from> → <to>"`), update it in place via `gh issue comment` rather than duplicating.

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
- **Audit every override**: every BUMP NOW that overrides cooldown gets a line in the audit log. No exceptions.
- **Idempotent**: re-running the skill produces the same stories (or comments on existing ones if they already exist). No duplicates.
