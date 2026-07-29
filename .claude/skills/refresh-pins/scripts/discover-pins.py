#!/usr/bin/env python3
"""Discover all pinned dependencies across the CFGMS repo.

Emits a JSON inventory to stdout following the schema documented in
references/inventory-schema.md. Each pin entry includes every file:line
location where the version string appears, so consumers can verify
lockstep bumps.

Discovery sources:
- go.mod              — Go toolchain directive
- .github/workflows/  — GO_VERSION env vars, go-version: in setup-go uses
- cmd/*/Dockerfile    — FROM golang:X-alpine tags
- .devcontainer/Dockerfile — same
- .github/workflows/dependency-pin-check.yml — the existing tool pin list
  (check_version <name> <repo> <version> calls)
- .github/workflows/*.yml — GitHub Action SHA pins (uses: <owner>/<name>@<sha>)
  — one inventory entry per unique (action, sha) tuple so SHA drift across
  workflows is naturally visible (multiple entries with the same action name
  but different SHAs).
- .mcp.json — git-pinned MCP servers (git+https://github.com/<owner>/<repo>@<tag>,
  e.g. serena). kind="mcp"; these are agent *tooling* dependencies whose tool
  names are consumed by name in .claude/agents/*.md, so a tool-renaming release
  is a breaking change (see references/decision-matrix.md "MCP server pins").

Run from repo root or any subdir — uses `git rev-parse --show-toplevel`
to anchor.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def grep_files(pattern: re.Pattern, files: list[Path], root: Path) -> list[dict]:
    """Return location dicts for every matching line."""
    locations = []
    for f in files:
        if not f.exists() or not f.is_file():
            continue
        try:
            for i, line in enumerate(f.read_text().splitlines(), 1):
                if pattern.search(line):
                    locations.append({
                        "file": str(f.relative_to(root)),
                        "line": i,
                        "match": line.strip(),
                    })
        except UnicodeDecodeError:
            continue
    return locations


def discover_go_toolchain(root: Path) -> dict:
    """Go toolchain pin — lockstep across go.mod, workflows, Dockerfiles."""
    locations = []

    # go.mod toolchain directive
    go_mod = root / "go.mod"
    current = None
    for i, line in enumerate(go_mod.read_text().splitlines(), 1):
        m = re.match(r"^toolchain go(\S+)", line)
        if m:
            current = m.group(1)
            locations.append({
                "file": "go.mod",
                "line": i,
                "match": line.strip(),
            })
            break
    if current is None:
        # Fall back to the `go X.Y.Z` directive if no explicit toolchain
        for i, line in enumerate(go_mod.read_text().splitlines(), 1):
            m = re.match(r"^go (\S+)", line)
            if m:
                current = m.group(1)
                locations.append({
                    "file": "go.mod",
                    "line": i,
                    "match": line.strip(),
                })
                break

    # Workflow GO_VERSION and go-version: pins
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    locations.extend(grep_files(
        re.compile(r"(GO_VERSION|go-version):\s*['\"]?\d+\.\d+(\.\d+)?['\"]?"),
        workflows, root,
    ))

    # Dockerfile FROM golang: pins (active uncommented lines only)
    dockerfiles = list((root / "cmd").glob("*/Dockerfile")) + \
                  list((root / "cmd").glob("*/Dockerfile.*"))
    devcontainer_df = root / ".devcontainer" / "Dockerfile"
    if devcontainer_df.exists():
        dockerfiles.append(devcontainer_df)
    locations.extend(grep_files(
        re.compile(r"^\s*FROM\s+golang:\d+\.\d+(\.\d+)?"),
        dockerfiles, root,
    ))

    return {
        "name": "go-toolchain",
        "kind": "lockstep",
        "current": current or "unknown",
        "release_source": "https://go.dev/dl/?mode=json",
        "ecosystem": "GO",
        "package": "stdlib",
        "locations": locations,
    }


def discover_tool_usage_locations(version: str, root: Path) -> list[dict]:
    """Grep in-scope paths for additional usage locations of a tool version string.

    Searches for the literal version string across workflow files (excluding the
    dependency-pin-check.yml declaration file itself), devcontainer Dockerfile,
    Makefile, cmd Dockerfiles, and shell scripts. Returns location dicts for
    every match — these are the install/usage pins that must move lockstep with
    the check_version declaration.
    """
    search_files: list[Path] = []

    for f in sorted((root / ".github/workflows").glob("*.yml")):
        if f.name != "dependency-pin-check.yml":
            search_files.append(f)

    devcontainer_df = root / ".devcontainer" / "Dockerfile"
    if devcontainer_df.exists():
        search_files.append(devcontainer_df)

    makefile = root / "Makefile"
    if makefile.exists():
        search_files.append(makefile)

    for f in sorted((root / "cmd").glob("*/Dockerfile")):
        search_files.append(f)

    for f in sorted((root / "scripts").glob("*.sh")):
        search_files.append(f)

    return grep_files(re.compile(re.escape(version)), search_files, root)


def discover_tool_pins(root: Path) -> list[dict]:
    """Tool pins listed in .github/workflows/dependency-pin-check.yml.

    Parses lines of the form:
      check_version "<name>" "<repo>" "<version>"

    For each pin the locations[] array contains the check_version declaration
    plus every additional install/usage site discovered by grepping the in-scope
    paths for the literal version string.
    """
    pins = []
    pin_file = root / ".github/workflows/dependency-pin-check.yml"
    if not pin_file.exists():
        return pins

    pattern = re.compile(
        r'^\s*check_version\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"'
    )

    for i, line in enumerate(pin_file.read_text().splitlines(), 1):
        m = pattern.match(line)
        if not m:
            continue
        name, repo, version = m.group(1), m.group(2), m.group(3)
        locations = [{
            "file": ".github/workflows/dependency-pin-check.yml",
            "line": i,
            "match": line.strip(),
        }]
        locations.extend(discover_tool_usage_locations(version, root))
        pins.append({
            "name": name,
            "kind": "tool",
            "current": version,
            "release_source": f"gh:{repo}",
            "ecosystem": None,  # GHSA query needs case-by-case mapping for tools
            "package": None,
            "locations": locations,
        })
    return pins


_GITHUB_ACTION_USES_RE = re.compile(
    # Match:  uses: <owner>/<name>[/<subpath>]@<40-hex-sha>  [# v<tag-hint>]
    # Owner and name use the GitHub allowed-character set; subpath is optional
    # (some actions live in subdirs of a monorepo, e.g. actions/cache/save).
    r"""
    ^\s*-?\s*uses:\s*
    (?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)
    @
    (?P<sha>[a-fA-F0-9]{40})
    (?:\s*\#\s*(?P<hint>\S+))?
    """,
    re.VERBOSE,
)


def discover_github_actions(root: Path) -> list[dict]:
    """Discover GitHub Action SHA pins across every workflow file.

    One inventory entry per unique (action, sha) tuple — so when the same
    action appears at different SHAs across workflows (drift, or intentional
    pin-back), each version becomes its own entry. The optional `# vN` hint
    after the SHA is captured into the match string for human readability;
    it is not parsed as the canonical version (the SHA is the source of
    truth, since release notes and tags can be retconned).

    The `name` slug embeds the short SHA so multiple entries for the same
    action remain unique inventory keys (a downstream consumer can group
    by stripping `@<sha>`).
    """
    workflows = sorted((root / ".github/workflows").glob("*.yml"))

    # (action, sha) → {"hint": "v4" or None, "locations": [...]}
    by_pin: dict[tuple[str, str], dict] = {}

    for wf in workflows:
        if not wf.is_file():
            continue
        try:
            lines = wf.read_text().splitlines()
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(lines, 1):
            m = _GITHUB_ACTION_USES_RE.match(line)
            if not m:
                continue
            action = m.group("action")
            sha = m.group("sha")
            hint = m.group("hint")
            key = (action, sha)
            entry = by_pin.setdefault(key, {"hint": hint, "locations": []})
            # Keep the first non-None hint we see (they should all agree).
            if entry["hint"] is None and hint is not None:
                entry["hint"] = hint
            entry["locations"].append({
                "file": str(wf.relative_to(root)),
                "line": i,
                "match": line.strip(),
            })

    pins = []
    for (action, sha), entry in sorted(by_pin.items()):
        # `current` is the full SHA — the canonical identity of the pinned
        # version. Tag hints (e.g. `# v4`) are advisory only.
        pins.append({
            "name": f"gha:{action}@{sha[:8]}",
            "kind": "tool",
            "current": sha,
            "release_source": f"gh:{action.split('/', 1)[0]}/{action.split('/', 1)[1].split('/', 1)[0]}",
            "ecosystem": None,
            "package": None,
            "locations": entry["locations"],
        })
    return pins


def discover_mcp_pins(root: Path) -> list[dict]:
    """MCP server pins in .mcp.json — git+https://github.com/<owner>/<repo>@<tag>.

    Each git-pinned MCP server (e.g. serena) becomes one pin entry. Generic:
    any current/future .mcp.json server pinned to a GitHub git tag is covered.

    These are agent *tooling* dependencies — the planning/dev agents consume
    their tools by name (e.g. `mcp__serena__find_symbol` appears in
    .claude/agents/*.md `tools:` allowlists and prose), so a release that
    renames/removes a tool is a BREAKING change that needs a rewire story, not a
    one-line pin bump. The blast-radius classification lives in Phase 3 (see
    references/decision-matrix.md "MCP server pins"); this discovery only emits
    the pin + its .mcp.json location.
    """
    pins: list[dict] = []
    mcp_file = root / ".mcp.json"
    if not mcp_file.exists():
        return pins
    try:
        text = mcp_file.read_text()
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return pins
    git_ref = re.compile(
        r"git\+https://github\.com/([^/]+)/([^/@]+?)(?:\.git)?@(v?[0-9][^\s\"']*)"
    )
    raw_lines = text.splitlines()
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return pins
    for name in sorted(servers):
        cfg = servers[name]
        args = cfg.get("args", []) if isinstance(cfg, dict) else []
        match = None
        for arg in args:
            if isinstance(arg, str):
                match = git_ref.search(arg)
                if match:
                    break
        if not match:
            continue  # non-git-pinned server (uvx latest, npx, local path) — not a versioned pin
        owner, repo, tag = match.group(1), match.group(2), match.group(3)
        locations = [
            {"file": ".mcp.json", "line": i, "match": line.strip()}
            for i, line in enumerate(raw_lines, 1)
            if git_ref.search(line)
        ]
        # An MCP server's git ref can be pinned a second time, independently, in
        # a Dockerfile that bakes it into the agent image (e.g. `uv tool install
        # --from git+https://github.com/<owner>/<repo>@<tag> <name>`). setup-env.sh
        # repoints .mcp.json at that baked binary at container startup, so a bump
        # that only touches .mcp.json is a no-op — both locations must move
        # together. Missing this cost story #3074 a manual scope correction.
        drift_tag = None
        for dockerfile in sorted(root.glob("**/Dockerfile*")):
            if ".git" in dockerfile.parts:
                continue
            try:
                docker_lines = dockerfile.read_text().splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            rel = str(dockerfile.relative_to(root))
            for i, line in enumerate(docker_lines, 1):
                dmatch = git_ref.search(line)
                if dmatch and dmatch.group(1) == owner and dmatch.group(2) == repo:
                    locations.append({"file": rel, "line": i, "match": line.strip()})
                    if dmatch.group(3) != tag:
                        drift_tag = dmatch.group(3)
        pin = {
            "name": name,
            "kind": "mcp",
            "current": tag,
            "release_source": f"gh:{owner}/{repo}",
            "ecosystem": None,  # git-installed; GHSA rarely resolves — Phase 2 falls back to release notes
            "package": None,
            "locations": locations,
        }
        if drift_tag:
            # Two divergent pins of the same server — surface it like the
            # actions/checkout "mixed pins" case so Phase 3's justification
            # calls out unifying them, not just bumping .mcp.json's tag.
            pin["drift_current"] = drift_tag
        pins.append(pin)
    return pins


def main() -> int:
    root = repo_root()
    inventory = [discover_go_toolchain(root)]
    inventory.extend(discover_tool_pins(root))
    inventory.extend(discover_github_actions(root))
    inventory.extend(discover_mcp_pins(root))
    json.dump(inventory, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
