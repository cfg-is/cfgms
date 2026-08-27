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

The inventory covers ~100 pins across six kinds. Do **not** issue one upstream
query per pin — `gomod`, `npm` and `docker` are researched in bulk, and only
`lockstep`, `tool` and `mcp` get per-pin treatment.

### 2a. Bulk staleness (kinds `gomod`, `npm`)

One command per ecosystem, not one per package:

```bash
# Go: current + available update for every module, direct and indirect
go list -m -u -f '{{.Path}} {{.Version}}{{if .Update}} -> {{.Update.Version}}{{end}}' all 2>/dev/null | grep ' -> '

# npm: ALWAYS `npm ci` first. `npm outdated` reports against the INSTALLED
# tree, so a stale or partial node_modules produces confident-looking nonsense.
# Measured on the 2026-08-14 sweep, both from an unclean tree:
#   react-router  reported "8.3.0 -> 7.18.2" — a downgrade across a major
#   @xterm/xterm  reported with no `current`, reading as "declared but never
#                 installed", while being imported by ShellTab.tsx and present
#                 in the lockfile
# Neither was real. Re-baseline, then measure.
cd web && npm ci && npm outdated --json
```

**`latest` is a dist-tag, not "the highest version".** Maintainers point it
wherever they like, and it can sit *below* what is installed:

| Package | Installed | `latest` | Reality |
|---|---|---|---|
| `react-router` | 8.3.0 | 7.18.2 | 8.3.0 *is* current; `version-7` is a maintenance tag |
| `claude-code-cli` | 2.1.226 | 2.1.232 | but `stable` is 2.1.223, below the pin |

Compare `current` against `wanted`, and read the full `dist-tags` map before
concluding anything. **Never propose a bump whose target is lower than the
current version** — resolve the discrepancy instead.

Match results back to inventory entries by `package`. A module that appears in
the `go list` output but not in the inventory is **indirect** — do not create a
staleness story for it (MVS owns its version); it is covered by 2b.

### 2b. Bulk vulnerability (the whole transitive graph)

This is what actually reaches the 334 indirect Go modules and every transitive
npm package. Run all three — they have different databases and genuinely
disagree:

```bash
# Go: authoritative for stdlib + module advisories, reachability-aware
govulncheck ./... 2>&1 | grep -E '^Vulnerability|Found in|Fixed in'

# Everything in the tree, excluding local-only artifacts. .cache/go-mod is an
# in-tree module cache that CI does not have; scanning it floods the result
# with findings from vendored copies rather than what we ship.
trivy fs . --scanners vuln --severity UNKNOWN,CRITICAL,HIGH,MEDIUM \
  --skip-dirs .cache --skip-dirs web/node_modules --quiet

# Shipped artifacts — the only check that sees the OS packages and the stdlib
# compiled into the binary. Base-image and toolchain CVEs appear ONLY here.
docker build -f cmd/controller/Dockerfile -t cfgms-pin-scan:controller .
trivy image cfgms-pin-scan:controller --scanners vuln --severity CRITICAL,HIGH,MEDIUM --quiet
```

Nancy (`make security-deps`) needs `GUIDE_TOKEN`; if it is absent, say the
dependency scan was **skipped**, never that it was clean — an unauthenticated
Nancy run returns 401, which is an absence of evidence, not evidence of absence.

Map each finding to the inventory entry whose `package` matches. A finding with
no matching entry is an indirect dependency: the story targets `go.mod`/`go.sum`
(or `web/package-lock.json`) and states which direct parent to raise.

### 2c. Base images (kind `docker`)

Staleness for a digest-pinned image is not a version comparison — a tag like
`alpine:3.23` is repointed at new digests without the tag changing. Resolve the
tag's current digest and compare:

```bash
docker buildx imagetools inspect alpine:3.23 --format '{{.Manifest.Digest}}'
```

Vulnerability comes from the image scan in 2b, not from GHSA.

### 2d. Per-pin research (kinds `lockstep`, `tool`, `mcp`)

For each of these pins (run in parallel where independent — separate Bash calls in one assistant turn):

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

### Group before you create

A sweep over ~100 pins must not emit ~100 stories. Each story costs a dispatch,
a review cycle and a merge-queue passage, and a one-line version bump does not
justify that on its own. **Group pins into the fewest stories that keep each
story independently reviewable and revertible.**

Group pins together when **all** of these hold:

- same verdict (all BUMP, or all BUMP NOW — never mix urgency)
- no file overlap between them, or they are already lockstep with each other
- no interaction: a failure in one does not implicate the others
- cooldown unlock dates within ~2 days (the latest one governs the group)

Keep a pin in its **own** story when any of these hold:

- it carries a CVE justification the others do not — the urgency and the audit
  trail belong to that pin alone
- it is a `mcp` rewire (breaking tool delta), which is human-reviewed
- it touches more than ~5 files, or its blast radius differs in kind from the
  rest (e.g. `go-toolchain` rebuilds everything)
- it is a `gomod`/`npm` bump whose transitive fan-out changes other modules —
  minimum version selection can raise siblings, so the diff is not what the
  title says

Natural groupings that usually hold:

| Group | Rationale |
|---|---|
| GitHub Action SHA pins | all `.github/workflows/`, mechanical, verified by `zizmor` |
| Security CLI tools (gosec, trivy, …) | independent binaries, one workflow each |
| `docker` base images | few files, verified by one image scan |
| Direct `gomod` bumps with no CVE | one `go mod tidy`, one `go.sum` diff |

Title a grouped story for the group, not the first member — e.g.
`deps: refresh 6 GitHub Action pins (routine, cooldown elapsed)` — and give it a
table of every pin with from/to/released/unlock so the dev agent has the full
list without re-running discovery.

Split a group the moment one member needs real work: a grouped story that turns
into a debugging session for one pin blocks the other five.

**Say in the story which members are load-bearing.** A grouped bump reads as
uniformly mechanical and is reviewed that way. On the 2026-08-14 sweep, one
member of a 21-module group (`go.etcd.io/raft/v3` v3.6→v3.7) turned out to be a
breaking API change — `raftpb` moved between value and pointer types — and had
to be split out mid-implementation. Three others (`modernc.org/sqlite` under the
DNA store, `go.etcd.io/bbolt` under the Raft WAL, `quic-go` under all internal
mTLS traffic) were mechanical but needed suite-specific verification rather than
the aggregate run. Name those up front so the implementer verifies deliberately
instead of discovering it at compile time.

**A `gomod` bump can quietly change the `go` directive.** `go get` may raise the
language version in `go.mod` as a side effect, independently of any module's own
requirement. It is easy to describe such a PR as "go.mod and go.sum only" and be
wrong about which *lines* changed. Diff `go.mod` explicitly and disclose it.

### Per-story mechanics

For each story (one pin, or one group):

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

   **Executing vs. prose (for AC2's grep verification):** a version string
   surviving in the tree after the bump is not automatically a failure — only
   an *executing* reference (a live pin, an install command, a dependency
   declaration) fails the check. A version string inside a `//`/`#` comment,
   inside a quoted string passed to `echo`/`printf`/`Sprintf`/`console.log`,
   or anywhere in a `.md` file, is prose and must not block the story.
   `scripts/verify_pin_clean.py` implements this classification (see the
   script's own docstring for the full rule order); the story template's AC2
   already invokes it. Two real cases this exists to prevent: a `.pre-commit-
   config.yaml`-style echoed `"... run: go install
   honnef.co/go/tools/cmd/staticcheck@2026.1"` help string (story #3627/PR
   #3642), and a `// Issue #3628 bumped pinnedVersion 5.13.1 -> 5.23.1`
   file-header comment (story #3628/PR #3646). Both are prose; neither should
   ever fail AC2 again.
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
- **This applies to every bulk command in Phase 2, not just Nancy.** All of them
  fail the same way: quietly, with empty output that is indistinguishable from
  "nothing to report". Check each one actually ran before reporting on it:
  - `go list -m -u all` needs the module proxy. On a network failure or a proxy
    error it exits non-zero and prints nothing to stdout — which greps to zero
    updates and reads as "all modules current". Capture the exit code.
  - `npm outdated` exits **1 when it finds outdated packages** and 0 when it
    finds none. Do not treat non-zero as failure; distinguish "exit 1 with JSON
    on stdout" (findings) from "exit 1 with an error" (did not run).
  - `govulncheck` and `trivy` exit non-zero on findings *and* on database
    download failure. `trivy` in particular reports a DB-download error that
    looks nothing like a vulnerability list — see `scripts/security-trivy.sh`,
    which exists precisely to keep those two apart.
  - `docker build` for the image scan can fail before any scanning happens.
  If a command did not run, the affected pins are **UNKNOWN**, not **OK**. Say
  which ones and why. An inventory of 100 pins reported as "3 outdated, 97 up to
  date" is a much stronger claim than "3 outdated, 97 not researched", and only
  one of them may be true.
- **Audit every override**: every BUMP NOW that overrides cooldown gets a line in the audit log. No exceptions.
- **Idempotent**: re-running the skill produces the same stories (or comments on existing ones if they already exist). No duplicates.
