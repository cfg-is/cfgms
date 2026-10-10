# Pin Inventory JSON Schema

`scripts/discover-pins.py` emits a JSON array to stdout. Each element is a pin object.

## Pin object

```jsonc
{
  "name": "go-toolchain",       // string — stable identifier for this pin (used in story titles, override audit log)
  "kind": "lockstep",           // "lockstep" | "tool" | "mcp" | "npm" | "docker" | "gomod"
  "current": "1.25.10",         // string — version string as it appears in the source (no leading "v" for Go)
  "release_source": "https://go.dev/dl/?mode=json",  // URL or "gh:<owner>/<repo>"
  "ecosystem": "GO",            // GHSA SecurityAdvisoryEcosystem enum, or null if not GHSA-queryable
  "package": "stdlib",          // package name for GHSA query, or null
  "locations": [                // every file:line where this version string appears
    {"file": "go.mod", "line": 5, "match": "toolchain go1.25.10"},
    {"file": ".github/workflows/cross-platform-build.yml", "line": 19, "match": "GO_VERSION: '1.25.10'"}
  ]
}
```

## `kind` values

- **`lockstep`** — the pin appears in multiple files that must all move together. The dev agent's story must update every entry in `locations[]` in a single PR. The acceptance verification AC must grep for the old version (expect 0) and new version (expect `len(locations)`). For `go-toolchain`, `locations[]` also includes any workflow `docker pull` / `pull_with_retry` pre-pull step that warms the same `golang:` image a Dockerfile `FROM` line references, and any literal occurrence of the version in a repo `*.ps1` script (e.g. a winget package pin) — both move in lockstep with the Dockerfile and workflow entries.
- **`tool`** — covers two distinct sub-cases that share the same downstream Phase 2/3 handling:
  - **Tool-pin declarations** in `dependency-pin-check.yml` (gosec, staticcheck, trivy, …). `locations[]` starts with the `check_version` declaration, then every install/usage site found by grepping `.github/workflows/` (excluding `dependency-pin-check.yml` itself), `.devcontainer/Dockerfile`, `Makefile`, `cmd/*/Dockerfile`, `scripts/*.sh`, and every `*.ps1` script in the repo for the literal version string. A PowerShell `Url = '...'` match also pulls in its paired `Sha256 = '...'` line, which carries no version string of its own to grep for. All entries must move together in a single bump PR.
  - **GitHub Action SHA pins** (`uses: <owner>/<name>@<sha>` lines in workflows). The name embeds the short SHA (`gha:actions/checkout@34e11487`) so each unique (action, sha) pair is its own inventory entry. `locations[]` lists every workflow file:line that uses that exact SHA. Multiple entries for the same action with different SHAs is the natural representation of SHA drift across workflows — a drift-finder consumer can group by stripping `@<sha>` from `name`.
- **`mcp`** — a git-pinned MCP server in `.mcp.json` (`git+https://github.com/<owner>/<repo>@<tag>`, e.g. `serena`). `current` is the git tag (with leading `v`), `release_source` is `gh:<owner>/<repo>`, `locations[]` is the `.mcp.json` line. **Distinct downstream handling:** these are agent *tooling* dependencies — their tool names are consumed by name in `.claude/agents/*.md` (`tools:` allowlists + prose). Phase 3 applies the **blast-radius classification** (see `decision-matrix.md` "MCP server pins"): a non-breaking bump is a one-line `.mcp.json` story; a release that renames/removes/changes a consumed tool is a **rewire story** that also touches every agent file using the affected tool.

- **`npm`** — a version pinned as an npm package version string in a file the repo builds from, rather than declared in `dependency-pin-check.yml`. Currently covers every direct dependency and devDependency in `web/package.json`; those entries carry a `dev` boolean. devDependencies are included because the build toolchain runs in CI against repository contents, so a compromised build-time package is a supply-chain exposure whether or not it ships. **Measure against a clean tree** — `npm outdated` reports on the installed `node_modules`, and a stale one yields phantom results including apparent downgrades. Note also that `dist-tags.latest` can point *below* the installed version (`react-router` 8.3.0 installed, `latest` 7.18.2), so `latest` alone never justifies a bump.

  **Claude Code CLI is deliberately NOT in this inventory**, despite being an npm global install in `.devcontainer/Dockerfile` and `windows-setup.ps1`. It is exempt from pin tracking entirely (founder decision 2026-10-01, Issue #4473) — see `cooldown-policy.md` "Claude Code CLI exemption". Both install sites resolve npm's `stable` dist-tag at build/setup time instead of naming a version, so there is no version string for a discoverer to find or a story to bump.

- **`docker`** — a container image pinned by a `FROM` line in any Dockerfile in the repo, or listed in `.github/ci-images.yml` (the third-party images CI pulls from Docker Hub, including compose test services no Dockerfile names), excluding `golang:` images (those belong to the `go-toolchain` lockstep pin and would otherwise produce a second, competing entry). Carries two extra fields: `tag` (e.g. `3.23`) and `digest` (e.g. `sha256:fd79…`). `current` is the **digest** when one is pinned, because that is what Docker resolves — a tag such as `alpine:3.23` is silently repointed at new digests without the tag changing, so comparing tags would report a stale image as current. Freshness is therefore `docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'`, not a release feed. A pin that comes from the image list also carries `upstream_ref` (`<image>:<tag>@sha256:<digest>`), `mirror_name` (the entry's `mirror:` value) and `mirror` (`ghcr.io/cfg-is/ci-mirror/<mirror_name>:<tag>`), and its `locations[]` includes the `.github/ci-images.yml` line; a bump must edit that line, every compose/Dockerfile/workflow occurrence, and be followed by a mirror refresh (the weekly pin check already mirrors a newly found digest). `golang:` list entries are not `docker` pins: their lines are added to the `go-toolchain` lockstep `locations[]`. Vulnerabilities come from the **image scan** (`trivy image`), never from GHSA: OS packages and the Go stdlib compiled into the binary are visible only there.
- **`gomod`** — a **direct** module requirement in `go.mod`. Indirect requirements are deliberately not enumerated: there are an order of magnitude more of them, their versions are chosen by minimum version selection rather than by us, and bumping one usually means raising its direct parent instead. They are not uncovered — Phase 2's bulk vulnerability scan reaches the entire transitive graph. The split is: **staleness per direct pin, vulnerability in bulk.** `ecosystem`/`package` are populated so the standard GHSA query works unchanged. Note that a `gomod` bump's real diff can be wider than its title: MVS may raise sibling modules, so the story must be checked against the actual `go.mod`/`go.sum` diff rather than assumed to be one line.

## `release_source` values

- `https://go.dev/dl/?mode=json` — Go release index. Returns array of versions; `[.[] | select(.stable)][0]` is the latest stable.
- `gh:<owner>/<repo>` — fetch via `gh api repos/<owner>/<repo>/releases/latest` for `tag_name` and `published_at`.
- `https://registry.npmjs.org/<package>` — npm registry document. `.["dist-tags"].latest` is the version an unpinned install resolves to; `.time["<version>"]` gives each version's publish timestamp, which is what the 3-day cooldown is measured against.

## `ecosystem` and `package`

Used for GHSA vulnerability queries against the `current` pinned version. Set to `null` when the tool doesn't have a clean GHSA mapping — fall back to release-notes WebFetch.

Common mappings (extend as needed):

| Tool | ecosystem | package |
|---|---|---|
| Go stdlib | `GO` | `stdlib` |
| gosec | `GO` | `github.com/securego/gosec` |
| staticcheck | `GO` | `honnef.co/go/tools` |
| trivy | (none in GHSA) | (use release notes) |
| nancy | (none in GHSA) | (use release notes) |

## Notes on the discover script's output

- The script does NOT verify lockstep consistency — if `go.mod` is at 1.25.10 but one workflow is still on 1.25.9, both versions appear in the same `go-toolchain` pin's `locations[]`. The CONSUMER (Claude in Phase 3) is expected to detect this and surface it as a lockstep-drift finding. This is the bug class that bit us on 2026-05-12 with PR #1433.
- For GitHub Action SHA pins, the equivalent drift signal is **multiple inventory entries with the same prefix before the `@`** — e.g., both `gha:actions/checkout@34e11487` and `gha:actions/checkout@93cb6efe` in the same inventory means two workflows pin different SHAs of the same action. Phase 3 should consolidate the bump story for the older entry(s).
- For `kind: tool` pins, `locations[]` includes the `check_version` declaration in `dependency-pin-check.yml` plus every additional install/usage site found by grepping for the literal version string across `.github/workflows/` (excluding `dependency-pin-check.yml`), `.devcontainer/Dockerfile`, `Makefile`, `cmd/*/Dockerfile`, `scripts/*.sh`, and every `*.ps1` script in the repo. A dispatched dev agent must update all listed locations to avoid lockstep drift.
- The order of `locations[]` is deterministic (alphabetical by file path), which makes diffs of the inventory readable.
- The script is read-only; no side effects.
