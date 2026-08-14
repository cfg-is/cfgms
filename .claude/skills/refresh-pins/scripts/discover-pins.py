#!/usr/bin/env python3
"""Discover all pinned dependencies across the CFGMS repo.

Emits a JSON inventory to stdout following the schema documented in
references/inventory-schema.md. Each pin entry includes every file:line
location where the version string appears, so consumers can verify
lockstep bumps.

Discovery sources:
- go.mod              — Go toolchain directive
- .github/workflows/  — GO_VERSION env vars, go-version: in setup-go uses
- **/Dockerfile*      — FROM golang:X tags (toolchain, lockstep) and every other
  base image (alpine, debian, ...) as its own `kind: "docker"` pin. Globbed from
  the repo root, not from cmd/ and .devcontainer/ only: Dockerfile.test-runner
  sits at the root and was invisible to the earlier globs, so a toolchain bump
  left the image that runs the integration suites on the old Go version.
- go.mod require blocks — every DIRECT module requirement, `kind: "gomod"`.
  Indirect requirements are deliberately not enumerated (334 of them here);
  their versions are chosen by MVS rather than by us, so the actionable signal
  is a CVE, not staleness. SKILL.md Phase 2 covers the full transitive graph
  with a single vulnerability scan instead.
- web/package.json — direct dependencies and devDependencies, `kind: "npm"`.
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


#: Directories that contain dependency *copies* rather than our own sources.
#: Anything discovered inside them is not a pin we control.
_VENDOR_DIRS = {".git", "node_modules", ".cache", "vendor", "worktrees"}


def all_dockerfiles(root: Path) -> list[Path]:
    """Every Dockerfile in the repo, wherever it lives.

    Earlier globs looked only under cmd/*/ and .devcontainer/, which missed
    Dockerfile.test-runner at the repo root — the image that runs the
    integration suites. A toolchain bump driven by this inventory would have
    left it on the old Go version, so base-image discovery globs from the root
    and filters vendored trees instead of enumerating known locations.
    """
    out: list[Path] = []
    for f in sorted(root.glob("**/Dockerfile*")):
        if _VENDOR_DIRS & set(f.parts):
            continue
        if f.is_file():
            out.append(f)
    return out


#: FROM [--flag=value ...] <ref> [AS <stage>]
#:
#: Only the reference is captured here; it is split in parse_image_ref rather
#: than by regex. A single pattern cannot separate the tag from a registry port
#: — in `registry.example.com:5000/foo/bar:latest` both are a colon followed by
#: characters, and a naive alternation binds `:5000` as the tag, yielding
#: image=registry.example.com tag=5000. That is worse than missing the line:
#: it emits a confidently wrong pin.
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--[A-Za-z0-9-]+=\S+\s+)*(?P<ref>\S+)",
)


def parse_image_ref(ref: str) -> tuple[str, str, str] | None:
    """Split a Docker image reference into (image, tag, digest).

    Returns None for a reference that carries no version information — a
    multi-stage stage name (`FROM builder`) or a bare image with neither tag nor
    digest. Those are not pins.

    The tag is the part after the LAST colon, and only when that colon comes
    after the last slash. Anything earlier is a registry port, which belongs to
    the image. Splitting from the right is what makes a registry host with a
    port parse correctly.
    """
    digest = ""
    if "@" in ref:
        ref, _, digest = ref.partition("@")
        if not digest.startswith("sha256:"):
            digest = ""

    tag = ""
    colon = ref.rfind(":")
    if colon != -1 and colon > ref.rfind("/"):
        tag = ref[colon + 1:]
        ref = ref[:colon]

    if not tag and not digest:
        return None
    return ref, tag, digest


def discover_base_images(root: Path) -> list[dict]:
    """Container base images pinned by FROM lines, excluding golang:.

    golang: images are the Go toolchain's concern — they must move in lockstep
    with go.mod and every workflow GO_VERSION, so discover_go_toolchain() owns
    them and emitting them here too would produce a second, competing pin.

    Everything else — alpine, debian, and any future base — is its own pin. The
    shipped controller and steward images are built FROM alpine, so an Alpine
    advisory lands directly in a released artifact; before this discoverer
    existed nothing in the sweep looked at it.

    One entry per unique (image, tag, digest). A digest-pinned image keeps the
    digest as `current` because that is what Docker actually resolves; the tag
    is carried alongside for readability, since `alpine:3.23` can be repointed
    at a new digest without the tag changing.
    """
    by_pin: dict[tuple[str, str, str], list[dict]] = {}

    for df in all_dockerfiles(root):
        try:
            lines = df.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = str(df.relative_to(root))
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            m = _FROM_RE.match(line)
            if not m:
                continue
            ref = m.group("ref")

            # A build-arg-substituted reference (FROM ${BASE}, FROM node:${VER})
            # cannot be resolved without evaluating the build. Warn on stderr
            # rather than skipping quietly: a silently dropped FROM line is
            # exactly the failure this discoverer exists to remove, and stderr
            # keeps the JSON on stdout parseable.
            if "$" in ref:
                print(
                    f"discover-pins: WARNING {rel}:{i} build-arg FROM not "
                    f"resolvable, image left untracked: {line.strip()}",
                    file=sys.stderr,
                )
                continue

            parsed = parse_image_ref(ref)
            if parsed is None:
                # Multi-stage stage reference, or an image with neither tag nor
                # digest — no version to track.
                continue
            image, tag, digest = parsed
            if image == "golang" or image.endswith("/golang"):
                continue
            by_pin.setdefault((image, tag, digest), []).append(
                {"file": rel, "line": i, "match": line.strip()}
            )

    pins: list[dict] = []
    for (image, tag, digest), locations in sorted(by_pin.items()):
        pins.append({
            "name": f"docker:{image}:{tag}" if tag else f"docker:{image}",
            "kind": "docker",
            "current": digest or tag,
            "tag": tag or None,
            "digest": digest or None,
            "release_source": f"https://hub.docker.com/_/{image}",
            "ecosystem": None,  # OS-package CVEs come from the image scan, not GHSA
            "package": image,
            "locations": locations,
        })
    return pins


def discover_go_modules(root: Path) -> list[dict]:
    """Direct module requirements from go.mod.

    Only direct requirements are emitted. The indirect set is an order of
    magnitude larger (334 vs 47 here) and its versions are selected by minimum
    version selection rather than chosen by us — bumping one directly usually
    means raising the parent that requires it. Enumerating them as pins would
    also make Phase 2's per-pin research infeasible.

    That is not a coverage hole: SKILL.md Phase 2 runs one vulnerability scan
    across the whole transitive graph, which reaches every indirect module.
    Staleness is tracked per direct pin; vulnerability is tracked in bulk.

    `ecosystem`/`package` are populated so the existing GHSA query in Phase 2
    works unchanged against these entries.
    """
    go_mod = root / "go.mod"
    if not go_mod.exists():
        return []

    pins: list[dict] = []
    in_require = False
    # `module/path v1.2.3` optionally followed by `// indirect`
    req_re = re.compile(
        r"^\s*(?P<path>[A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+"
        r"(?P<version>v\S+)(?P<rest>.*)$"
    )

    for i, line in enumerate(go_mod.read_text().splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("//"):
            continue

        target = stripped
        if not in_require:
            if not stripped.startswith("require "):
                continue
            target = stripped[len("require "):]

        m = req_re.match(target)
        if not m:
            continue
        if "indirect" in m.group("rest"):
            continue

        path = m.group("path")
        pins.append({
            "name": f"gomod:{path}",
            "kind": "gomod",
            "current": m.group("version"),
            "release_source": f"https://proxy.golang.org/{path}/@latest",
            "ecosystem": "GO",
            "package": path,
            "locations": [{"file": "go.mod", "line": i, "match": stripped}],
        })
    return pins


def discover_npm_packages(root: Path) -> list[dict]:
    """Direct dependencies and devDependencies from web/package.json.

    The frontend has its own dependency tree that no other discoverer touches.
    devDependencies are included because the build toolchain runs in CI against
    repository contents — a compromised build-time package is a supply-chain
    exposure regardless of whether it ships.

    Transitive npm packages are handled the same way as indirect Go modules: by
    the bulk vulnerability scan in Phase 2, not by enumeration.
    """
    pkg_json = root / "web" / "package.json"
    if not pkg_json.exists():
        return []
    try:
        data = json.loads(pkg_json.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    raw_lines = pkg_json.read_text().splitlines()
    pins: list[dict] = []

    for section in ("dependencies", "devDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name in sorted(block):
            spec = block[name]
            if not isinstance(spec, str):
                continue
            locations = [
                {"file": "web/package.json", "line": i, "match": line.strip()}
                for i, line in enumerate(raw_lines, 1)
                if f'"{name}"' in line
            ]
            pins.append({
                "name": f"npm:{name}",
                "kind": "npm",
                "current": spec,
                "dev": section == "devDependencies",
                "release_source": f"https://registry.npmjs.org/{name}",
                "ecosystem": "NPM",
                "package": name,
                "locations": locations,
            })
    return pins


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

    # Dockerfile FROM golang: pins (active uncommented lines only).
    # Globbed repo-wide — see all_dockerfiles() for why the previous
    # cmd/*+devcontainer globs were not enough.
    locations.extend(grep_files(
        re.compile(r"^\s*FROM\s+golang:\d+\.\d+(\.\d+)?"),
        all_dockerfiles(root), root,
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


def discover_claude_code_cli(root: Path) -> list[dict]:
    """Claude Code CLI pin — `ARG CLAUDE_CODE_VERSION` in .devcontainer/Dockerfile.

    dependency-pin-check.yml does check this pin's freshness, but through a bespoke
    npm dist-tags block rather than a `check_version` declaration, so
    discover_tool_pins() — which parses only `check_version` lines — never saw it.
    The sweep was therefore blind to a pin CI actively tracks. Same root shape as
    the Go toolchain, which needed its own discoverer for the same reason.

    The version is read from the Dockerfile, matching where
    dependency-pin-check.yml reads it from, so the two can never disagree about
    what the image installs. Nothing here hardcodes a version.

    Returns a list so a missing or renamed ARG yields [] rather than a bogus entry
    with current="unknown" — the workflow already warns loudly in that case, and a
    silent placeholder in the inventory would invite a story to "bump" a pin that
    no longer exists.
    """
    dockerfile = root / ".devcontainer" / "Dockerfile"
    if not dockerfile.exists():
        return []

    arg_re = re.compile(r"^ARG\s+CLAUDE_CODE_VERSION=(\S+)")
    for i, line in enumerate(dockerfile.read_text().splitlines(), 1):
        m = arg_re.match(line)
        if not m:
            continue
        return [{
            "name": "claude-code-cli",
            "kind": "npm",
            "current": m.group(1),
            "release_source": "https://registry.npmjs.org/@anthropic-ai/claude-code",
            "ecosystem": "NPM",
            "package": "@anthropic-ai/claude-code",
            "locations": [{
                "file": ".devcontainer/Dockerfile",
                "line": i,
                "match": line.strip(),
            }],
        }]
    return []


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
    inventory.extend(discover_claude_code_cli(root))
    inventory.extend(discover_github_actions(root))
    inventory.extend(discover_mcp_pins(root))
    inventory.extend(discover_base_images(root))
    inventory.extend(discover_go_modules(root))
    inventory.extend(discover_npm_packages(root))
    json.dump(inventory, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
