#!/usr/bin/env python3
"""Tests for the sweep's harness pin (Issue #4136).

Run: python3 .claude/scripts/security-review/harness_snapshot_test.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness_snapshot as hs  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def make_fake_repo(root: str) -> None:
    """A repo-shaped tree holding one of each kind of file the pin covers."""
    layout = {
        ".devcontainer/scripts/investigator-entrypoint.sh": "#!/bin/sh\necho entry\n",
        ".claude/agents/investigator.md": "# investigator\n",
        "docs/security-review/methodology.md": "# methodology\n",
        ".claude/scripts/security-review/schema.py": "SCHEMA = 1\n",
        ".claude/scripts/security-review/lanes/ollama_lane.py": "LANE = 1\n",
        # Excluded on purpose -- see the tests below.
        ".claude/scripts/security-review/schema_test.py": "TEST = 1\n",
        ".claude/scripts/security-review/__pycache__/schema.cpython-311.pyc": "junk",
        ".claude/scripts/security-review/notes.md": "not code\n",
    }
    for rel, content in layout.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)


def test_pin_covers_running_code_only() -> None:
    with tempfile.TemporaryDirectory() as repo:
        make_fake_repo(repo)
        files = hs.harness_files(repo)
        check(
            ".claude/scripts/security-review/schema.py" in files,
            "pin: a harness module is covered",
            str(files),
        )
        check(
            ".claude/scripts/security-review/lanes/ollama_lane.py" in files,
            "pin: a nested lane module is covered",
            str(files),
        )
        check(
            all(".devcontainer" in f or ".claude" in f or "docs" in f for f in files),
            "pin: every covered path is one of the three roots",
            str(files),
        )
        # A test edit is not a harness change: test files never run in a
        # container, so covering them would make an unrelated edit read as a
        # different harness and quarantine completed steps for nothing.
        check(
            not any(f.endswith("_test.py") for f in files),
            "pin: test files are excluded -- they never run in a container",
            str(files),
        )
        check(
            not any("__pycache__" in f for f in files),
            "pin: __pycache__ is excluded -- a compiled artifact is not the harness",
            str(files),
        )
        check(
            not any(f.endswith("notes.md") for f in files),
            "pin: a non-.py file in the harness dir is not code and is excluded",
            str(files),
        )


def test_pin_is_deterministic_and_order_stable() -> None:
    with tempfile.TemporaryDirectory() as repo:
        make_fake_repo(repo)
        first = hs.harness_files(repo)
        second = hs.harness_files(repo)
        check(first == second, "pin: the file list is stable across calls", f"{first}\n{second}")
        check(
            hs.compute_identity(repo, first) == hs.compute_identity(repo, second),
            "pin: the identity is stable across calls",
        )


def test_identity_changes_on_content_and_on_rename() -> None:
    with tempfile.TemporaryDirectory() as repo:
        make_fake_repo(repo)
        files = hs.harness_files(repo)
        base = hs.compute_identity(repo, files)

        target = os.path.join(repo, ".claude/scripts/security-review/schema.py")
        with open(target, "w") as f:
            f.write("SCHEMA = 2\n")
        check(
            hs.compute_identity(repo, hs.harness_files(repo)) != base,
            "pin: changed content changes the identity",
        )

        with open(target, "w") as f:
            f.write("SCHEMA = 1\n")
        check(
            hs.compute_identity(repo, hs.harness_files(repo)) == base,
            "pin: restoring the content restores the identity",
        )

        # The path is hashed alongside the bytes, so moving a file with
        # identical content is still a different harness -- where a module is
        # mounted is part of what ran.
        os.rename(target, os.path.join(repo, ".claude/scripts/security-review/schema2.py"))
        check(
            hs.compute_identity(repo, hs.harness_files(repo)) != base,
            "pin: a rename with unchanged bytes still changes the identity",
        )


def test_create_is_idempotent_and_never_repins() -> None:
    """[REQUIRED TEST] A resume must not silently re-pin against a newer tree.

    That is the original defect wearing a different hat: the sweep would still
    end up having run two harness versions, just with the second one recorded
    as if it had been there all along.
    """
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        make_fake_repo(repo)
        first = hs.create_harness_pin(repo, sweep)

        # The working tree moves on, exactly as it does when someone edits the
        # harness while a sweep is running.
        with open(os.path.join(repo, ".claude/scripts/security-review/schema.py"), "w") as f:
            f.write("SCHEMA = 999\n")

        second = hs.create_harness_pin(repo, sweep)
        check(second["hash"] == first["hash"], "pin: a second call keeps the original hash")
        check(second["pinned_at"] == first["pinned_at"], "pin: a second call does not re-stamp the time")
        pinned = os.path.join(hs.pin_path(sweep), ".claude/scripts/security-review/schema.py")
        with open(pinned) as f:
            body = f.read()
        check(body == "SCHEMA = 1\n", "pin: the pinned bytes are the ORIGINAL, not the edited tree", body)


def test_pin_is_read_only_and_tampering_is_detected() -> None:
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        make_fake_repo(repo)
        pin = hs.create_harness_pin(repo, sweep)
        check(hs.verify_pin(sweep) == [], "pin: a fresh pin verifies intact", str(hs.verify_pin(sweep)))

        target = os.path.join(hs.pin_path(sweep), pin["files"][0])
        wrote = True
        try:
            with open(target, "a") as f:
                f.write("x")
        except PermissionError:
            wrote = False
        check(not wrote, "pin: the pinned copy is not writable")

        os.chmod(target, 0o644)
        with open(target, "a") as f:
            f.write("\n# tampered\n")
        problems = hs.verify_pin(sweep)
        check(bool(problems), "pin: tampering with the pinned copy is detected", str(problems))
        check(
            any("changed since it was pinned" in p for p in problems),
            "pin: the report says what is wrong, not merely that something is",
            str(problems),
        )


def test_missing_pin_is_a_supported_answer() -> None:
    """A sweep created before pinning existed has none and must stay
    resumable -- `read_pin` answers None rather than raising, and the dispatch
    side falls back to the live tree."""
    with tempfile.TemporaryDirectory() as sweep:
        check(hs.is_pinned(sweep) is False, "pin: an unpinned sweep reports unpinned")
        check(hs.read_pin(sweep) is None, "pin: reading an absent pin returns None, never raises")
        check(
            hs.verify_pin(sweep) == ["no harness pin recorded for this sweep"],
            "pin: verifying an absent pin says so plainly",
            str(hs.verify_pin(sweep)),
        )


def test_half_written_pin_reads_as_absent() -> None:
    """The manifest is written last, so its presence is the signal. A pin
    interrupted mid-copy must read as absent and be redone, never used."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        make_fake_repo(repo)
        partial = os.path.join(hs.pin_path(sweep), ".claude/scripts/security-review")
        os.makedirs(partial, exist_ok=True)
        with open(os.path.join(partial, "schema.py"), "w") as f:
            f.write("SCHEMA = 1\n")
        check(hs.is_pinned(sweep) is False, "pin: a pin directory without a manifest is not a pin")
        pin = hs.create_harness_pin(repo, sweep)
        check(hs.is_pinned(sweep) is True, "pin: it is completed rather than refused")
        check(hs.verify_pin(sweep) == [], "pin: the completed pin verifies intact", str(hs.verify_pin(sweep)))
        check(bool(pin["hash"]), "pin: the completed pin has a hash")


def test_empty_harness_refuses_rather_than_pinning_nothing() -> None:
    """An empty pin would verify intact forever and record that a sweep ran a
    harness of no files. Refuse instead."""
    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as sweep:
        raised = False
        try:
            hs.create_harness_pin(repo, sweep)
        except hs.HarnessPinError:
            raised = True
        check(raised, "pin: an empty harness tree is refused, not pinned as nothing")


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All harness_snapshot.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
