#!/usr/bin/env python3
"""Pin the HARNESS to a sweep, the way `snapshot.py` already pins the target
(Issue #4136).

A sweep had no single harness version. `snapshot.py` freezes the code under
review and `verify_snapshot()` re-checks it against the pinned commit before
anything is dispatched -- but the harness that does the reviewing was mounted
from the live working tree, verified on a running container:

    .../.claude/scripts/security-review -> /opt/cfgms-harness/security-review
    .../lanes/ollama_lane.py            -> /usr/local/bin/investigator-lane-entrypoint.py
    .../investigator-entrypoint.sh      -> /usr/local/bin/investigator-entrypoint.sh

So editing the working tree mid-sweep changed what the NEXT container ran,
against the same pinned commit. Nothing detected it at dispatch time:
`harness_identity.json` is recomputed on every call and overwritten, so it
recorded the last dispatch rather than the sweep.

That matters twice over. A sweep is evidence, and evidence whose production
conditions changed midway -- with no record that they did -- is not evidence.
And it made iterating on the harness needlessly destructive: `resume` compares
each step's recorded `harness_identity` against the current one and quarantines
a mismatch, so landing any harness change re-ran every completed step of every
open sweep.

WHAT IS PINNED. Exactly the files the recorded identity already hashes, which
is exactly what a container actually runs:

  - every non-test `.py` under `.claude/scripts/security-review`
  - `.devcontainer/scripts/investigator-entrypoint.sh`
  - `.claude/agents/investigator.md`
  - `docs/security-review/methodology.md`

Test files are excluded for the same reason the identity excludes them: they
never run in a container, so pinning them would make an unrelated test edit
look like a harness change.

WHAT IS NOT PINNED, deliberately. `schema.py`, `resume.py` and the rest are
pinned as files, but the modules the lane IMPORTS at runtime still resolve
through the container's own mount layout -- this module copies bytes, it does
not change Python's import resolution. And the target snapshot is untouched:
these are two independent pins, one on the code under review and one on the
code doing the reviewing, and conflating them would make either impossible to
reason about alone.

IDEMPOTENT, like `create_snapshot()`. A second `launch` against a sweep id that
already exists (same ref, same UTC minute) must not fail, and a `resume` must
never silently re-pin against a newer tree -- that would be the original defect
wearing a different hat. An existing, non-empty pin is left exactly as it is.

READ-ONLY once written, for the same reason the target snapshot is: a lane
container mounts it, and the pin is only worth having if nothing can edit it
afterwards.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone

_WRITE_BITS = 0o222

# Kept in the order the dispatch-side digest feeds them, so a hash computed
# here and one computed there agree. Relative to the repo root.
_SINGLE_FILES = (
    ".devcontainer/scripts/investigator-entrypoint.sh",
    ".claude/agents/investigator.md",
    "docs/security-review/methodology.md",
)
_HARNESS_DIR = ".claude/scripts/security-review"

PIN_DIR_NAME = "harness"
PIN_MANIFEST_NAME = "harness_pin.json"


class HarnessPinError(Exception):
    """A real operational failure -- a source file missing, or a destination
    that cannot be created or written. Never raised for "already pinned",
    which is the normal idempotent path and returns quietly."""


def _is_pinned_py(name: str) -> bool:
    return name.endswith(".py") and not name.endswith("_test.py")


def harness_files(repo_root: str) -> list[str]:
    """Repo-relative paths of every file that belongs in the pin, in a stable
    order. Deterministic across machines: directory walks are sorted, and
    `__pycache__` is skipped because a compiled artifact is not the harness.
    """
    found = [p for p in _SINGLE_FILES if os.path.isfile(os.path.join(repo_root, p))]
    harness_dir = os.path.join(repo_root, _HARNESS_DIR)
    for dirpath, dirnames, filenames in os.walk(harness_dir):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for name in sorted(filenames):
            if _is_pinned_py(name):
                found.append(os.path.relpath(os.path.join(dirpath, name), repo_root))
    return found


def compute_identity(root: str, relative_paths: list[str]) -> str:
    """sha256 over each file's repo-relative path and then its bytes, in the
    given order.

    The path is hashed alongside the content so a rename with unchanged bytes
    still changes the identity -- where a file is mounted is part of what ran.

    NOT the same number as `agent-dispatch.sh`'s `harness_identity`, and not
    meant to be. That digest is PER MODE: lane mode hashes the lane entrypoint
    (once by itself and again in the directory walk) and no agent profile,
    plan mode hashes the agent profile and neither the lane entrypoint nor the
    walk. Measured on this tree the three values are all different -- pin
    d9ed2644, lane mode 1cb95418, plan mode 0cc95238.

    They answer different questions and both are wanted. This one is "which
    harness version is this sweep running", a single value for the whole
    sweep. That one is "which files did THIS container mount", which is what
    `resume` compares per step. What matters is that each is STABLE, and since
    #4136 both are computed from the pin, so both are.
    """
    digest = hashlib.sha256()
    for rel in relative_paths:
        with open(os.path.join(root, rel), "rb") as f:
            content = f.read()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _strip_write_bits(path: str) -> None:
    mode = os.stat(path, follow_symlinks=False).st_mode
    os.chmod(path, mode & ~_WRITE_BITS)


def _make_read_only(root: str) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                _strip_write_bits(p)
        for name in dirnames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                _strip_write_bits(p)
    _strip_write_bits(root)


def pin_path(sweep_dir: str) -> str:
    return os.path.join(sweep_dir, PIN_DIR_NAME)


def is_pinned(sweep_dir: str) -> bool:
    """True when this sweep already carries a pin worth trusting.

    Requires the manifest, not just a non-empty directory: a half-written pin
    from an interrupted launch must be recognised as absent rather than used,
    since the manifest is written last.
    """
    return os.path.isfile(os.path.join(pin_path(sweep_dir), PIN_MANIFEST_NAME))


def create_harness_pin(repo_root: str, sweep_dir: str) -> dict:
    """Copy the harness into `<sweep_dir>/harness/` and record its identity.

    Returns the pin manifest, whether it was written now or already existed --
    callers want the identity either way, and making the return value depend on
    which path ran would push that branch into every caller.
    """
    dest = pin_path(sweep_dir)
    manifest_path = os.path.join(dest, PIN_MANIFEST_NAME)

    if is_pinned(sweep_dir):
        with open(manifest_path) as f:
            return json.load(f)

    relative_paths = harness_files(repo_root)
    if not relative_paths:
        raise HarnessPinError(
            f"no harness files found under {repo_root} -- refusing to pin an empty harness"
        )

    try:
        for rel in relative_paths:
            src = os.path.join(repo_root, rel)
            dst = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    except OSError as exc:
        raise HarnessPinError(f"could not write harness pin to {dest}: {exc}") from exc

    # Identity is computed from the SOURCE tree, then verified against the
    # copy. Computing it from the copy alone would make a truncated or partial
    # copy self-consistent -- it would hash whatever landed and call it
    # correct, which is precisely the failure a pin exists to rule out.
    identity = compute_identity(repo_root, relative_paths)
    copied_identity = compute_identity(dest, relative_paths)
    if identity != copied_identity:
        raise HarnessPinError(
            "harness pin does not match its source after copying "
            f"(source {identity[:12]}, copy {copied_identity[:12]})"
        )

    manifest = {
        "algorithm": "sha256",
        "hash": identity,
        "files": relative_paths,
        "pinned_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
    except OSError as exc:
        raise HarnessPinError(f"could not write {manifest_path}: {exc}") from exc

    _make_read_only(dest)
    return manifest


def read_pin(sweep_dir: str) -> dict | None:
    """The pin manifest, or `None` for a sweep created before this existed.

    `None` is a supported answer, not an error: an in-flight sweep from before
    this change has no pin and must still be resumable -- callers fall back to
    the live tree exactly as they did before.
    """
    if not is_pinned(sweep_dir):
        return None
    with open(os.path.join(pin_path(sweep_dir), PIN_MANIFEST_NAME)) as f:
        return json.load(f)


def verify_pin(sweep_dir: str) -> list[str]:
    """Re-hash the pinned copy and report how it differs from its manifest.

    Returns a list of human-readable differences -- empty means intact.
    Reports rather than raises, matching `snapshot.verify_snapshot()`: the
    caller decides whether a drifted pin is fatal, and a verifier that raises
    cannot report more than its first finding.
    """
    manifest = read_pin(sweep_dir)
    if manifest is None:
        return ["no harness pin recorded for this sweep"]

    dest = pin_path(sweep_dir)
    problems = []
    for rel in manifest.get("files", []):
        if not os.path.isfile(os.path.join(dest, rel)):
            problems.append(f"missing from the pin: {rel}")
    if problems:
        return problems

    actual = compute_identity(dest, manifest.get("files", []))
    if actual != manifest.get("hash"):
        problems.append(
            f"pinned harness content changed since it was pinned "
            f"(recorded {str(manifest.get('hash'))[:12]}, found {actual[:12]})"
        )
    return problems
