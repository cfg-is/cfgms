# Pin Inventory JSON Schema

`scripts/discover-pins.py` emits a JSON array to stdout. Each element is a pin object.

## Pin object

```jsonc
{
  "name": "go-toolchain",       // string — stable identifier for this pin (used in story titles, override audit log)
  "kind": "lockstep",           // "lockstep" | "tool"
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

- **`lockstep`** — the pin appears in multiple files that must all move together. The dev agent's story must update every entry in `locations[]` in a single PR. The acceptance verification AC must grep for the old version (expect 0) and new version (expect `len(locations)`).
- **`tool`** — pin is enumerated in `dependency-pin-check.yml` and may appear in additional usage locations (Dockerfile installs, Makefile targets). The single `locations[]` entry points at the check_version declaration; the bump story discovers the actual usage locations by grepping for the version string.

## `release_source` values

- `https://go.dev/dl/?mode=json` — Go release index. Returns array of versions; `[.[] | select(.stable)][0]` is the latest stable.
- `gh:<owner>/<repo>` — fetch via `gh api repos/<owner>/<repo>/releases/latest` for `tag_name` and `published_at`.

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
- The order of `locations[]` is deterministic (alphabetical by file path), which makes diffs of the inventory readable.
- The script is read-only; no side effects.
