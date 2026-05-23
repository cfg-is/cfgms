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


def main() -> int:
    root = repo_root()
    inventory = [discover_go_toolchain(root)]
    inventory.extend(discover_tool_pins(root))
    inventory.extend(discover_github_actions(root))
    json.dump(inventory, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
