#!/usr/bin/env python3
"""Coverage tests for discover-pins.py.

The discovery script had no tests, and every gap in it has cost real work:
a repo-root Dockerfile invisible to the toolchain pin (which would have left
the integration-test runner image on an old Go version), and container base
images absent from the inventory entirely while the shipped controller and
steward images are built FROM them.

These tests assert the *shape* of coverage against a synthetic repo, so a
future refactor cannot silently narrow discovery again.

Run: python3 .claude/skills/refresh-pins/scripts/discover_pins_test.py
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("discover_pins", _HERE / "discover-pins.py")
dp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dp)

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def make_repo(tmp: Path) -> Path:
    """A synthetic repo carrying one of every pin shape we claim to discover."""
    root = tmp / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / "cmd/controller").mkdir(parents=True)
    (root / "web").mkdir(parents=True)

    (root / "go.mod").write_text(
        "module example.com/x\n"
        "\n"
        "go 1.26\n"
        "\n"
        "toolchain go1.26.5\n"
        "\n"
        "require (\n"
        "\tgithub.com/spf13/cobra v1.10.2\n"
        "\tgolang.org/x/crypto v0.53.0\n"
        "\tgolang.org/x/mod v0.37.0 // indirect\n"
        ")\n"
    )

    # A repo-root Dockerfile: the shape that was previously invisible.
    (root / "Dockerfile.test-runner").write_text(
        "FROM golang:1.26.5@sha256:" + "a" * 64 + "\n"
    )
    # Multi-stage: golang builder + non-golang runtime, plus a stage reference
    # that must NOT be mistaken for an external image.
    (root / "cmd/controller/Dockerfile").write_text(
        "FROM golang:1.26.5-alpine3.23@sha256:" + "b" * 64 + " AS builder\n"
        "RUN echo build\n"
        "FROM alpine:3.23@sha256:" + "c" * 64 + "\n"
        "COPY --from=builder /x /x\n"
    )
    (root / ".github/workflows/ci.yml").write_text(
        "env:\n"
        "  GO_VERSION: '1.26.5'\n"
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "    - uses: actions/checkout@" + "d" * 40 + " # v7.0.1\n"
    )
    (root / "web/package.json").write_text(json.dumps({
        "dependencies": {"react": "^19.0.0"},
        "devDependencies": {"vitest": "^3.0.0"},
    }, indent=2))

    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = make_repo(Path(td))

        toolchain = dp.discover_go_toolchain(root)
        images = dp.discover_base_images(root)
        modules = dp.discover_go_modules(root)
        npm = dp.discover_npm_packages(root)

        print("go-toolchain")
        files = {loc["file"] for loc in toolchain["locations"]}
        check(toolchain["current"] == "1.26.5", "reads the toolchain directive")
        check("Dockerfile.test-runner" in files,
              "covers a repo-root Dockerfile",
              f"saw {sorted(files)}")
        check("cmd/controller/Dockerfile" in files, "covers cmd/*/Dockerfile")
        check(".github/workflows/ci.yml" in files, "covers workflow GO_VERSION")

        print("base images")
        names = {p["name"] for p in images}
        check("docker:alpine:3.23" in names, "discovers a non-golang base image",
              f"saw {sorted(names)}")
        check(not any("golang" in n for n in names),
              "excludes golang images (owned by go-toolchain)",
              f"saw {sorted(names)}")
        check(not any(p.get("tag") == "builder" for p in images),
              "does not treat a multi-stage stage name as an image")
        alpine = next((p for p in images if p["name"] == "docker:alpine:3.23"), None)
        check(alpine is not None and alpine["current"].startswith("sha256:"),
              "pins the digest, not the tag, when a digest is present")

        print("go modules")
        mods = {p["package"] for p in modules}
        check("github.com/spf13/cobra" in mods, "discovers a direct requirement",
              f"saw {sorted(mods)}")
        check("golang.org/x/mod" not in mods,
              "excludes indirect requirements",
              f"saw {sorted(mods)}")
        check(all(p["ecosystem"] == "GO" for p in modules),
              "sets ecosystem so the GHSA query works unchanged")

        print("npm")
        pkgs = {p["package"] for p in npm}
        check("react" in pkgs, "discovers a dependency", f"saw {sorted(pkgs)}")
        check("vitest" in pkgs, "discovers a devDependency", f"saw {sorted(pkgs)}")
        check(any(p["package"] == "vitest" and p["dev"] for p in npm),
              "flags devDependencies with dev=true")

        print("no-crash on a repo missing every optional source")
        bare = Path(td) / "bare"
        (bare).mkdir()
        (bare / "go.mod").write_text("module e\n\ngo 1.26\n")
        subprocess.run(["git", "init", "-q"], cwd=bare, check=True)
        check(dp.discover_base_images(bare) == [], "no Dockerfiles -> no docker pins")
        check(dp.discover_npm_packages(bare) == [], "no package.json -> no npm pins")
        check(dp.discover_go_modules(bare) == [], "no requires -> no gomod pins")

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)}")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("All discover-pins coverage tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
