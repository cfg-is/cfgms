#!/usr/bin/env python3
"""Generate docs/design/mockups/README.md table from per-mockup *.yaml sidecar files.

Usage:
    scripts/generate-mockups-index.py           -- print updated README to stdout
    scripts/generate-mockups-index.py --write   -- update README.md in place
    scripts/generate-mockups-index.py --check   -- exit non-zero if README.md is stale

Adding a new mockup: create docs/design/mockups/<name>.yaml with:

    file:   <filename>.html
    order:  <integer>   (controls table position; ties broken by filename)
    status: <status text, e.g. **Reference** or Superseded>
    what:   <single-line description for the table cell>

Then run `scripts/generate-mockups-index.py --write` and commit the result together
with the new html and yaml files.  The generator reads the *.yaml sidecars so two
concurrent mockup PRs only touch their own new files — no conflict on README.md.
"""

import os
import sys
import difflib

MOCKUPS_DIR = os.path.join("docs", "design", "mockups")
README_PATH = os.path.join(MOCKUPS_DIR, "README.md")
BEGIN_MARKER = "<!-- BEGIN GENERATED TABLE -->"
END_MARKER = "<!-- END GENERATED TABLE -->"


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _parse_meta(path):
    """Parse a simple key: value file; first colon splits each line."""
    meta = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n").strip()
            if line and not line.startswith("#"):
                key, _, val = line.partition(":")
                meta[key.strip()] = val.strip()
    return meta


def _load_entries(mockups_dir):
    entries = []
    for fname in sorted(os.listdir(mockups_dir)):
        if not fname.endswith(".yaml"):
            continue
        meta = _parse_meta(os.path.join(mockups_dir, fname))
        if "file" not in meta:
            print(f"warning: {fname} missing 'file' field, skipping", file=sys.stderr)
            continue
        entries.append(meta)
    entries.sort(key=lambda e: (int(e.get("order", 999)), e.get("file", "")))
    return entries


def _build_section(entries):
    lines = [
        BEGIN_MARKER,
        "| File | What it is | Status |",
        "|------|------------|--------|",
    ]
    for e in entries:
        fname = e["file"]
        what = e.get("what", "")
        status = e.get("status", "")
        lines.append(f"| [`{fname}`]({fname}) | {what} | {status} |")
    lines.append(END_MARKER)
    return "\n".join(lines)


def _apply(readme_text, new_section):
    bi = readme_text.find(BEGIN_MARKER)
    ei = readme_text.find(END_MARKER)
    if bi == -1 or ei == -1:
        raise SystemExit(
            f"error: markers not found in {README_PATH}\n"
            f"  Add {BEGIN_MARKER!r} and {END_MARKER!r} to the file."
        )
    return readme_text[:bi] + new_section + readme_text[ei + len(END_MARKER):]


def main():
    args = set(sys.argv[1:])
    if "--help" in args or "-h" in args:
        print(__doc__)
        return

    root = _repo_root()
    entries = _load_entries(os.path.join(root, MOCKUPS_DIR))
    new_section = _build_section(entries)

    readme_path = os.path.join(root, README_PATH)
    with open(readme_path, encoding="utf-8") as f:
        current = f.read()

    updated = _apply(current, new_section)

    if "--check" in args:
        if current == updated:
            print(f"✅ {README_PATH} matches generator output ({len(entries)} entries)")
        else:
            print(f"❌ {README_PATH} is out of date — run: scripts/generate-mockups-index.py --write", file=sys.stderr)
            diff = difflib.unified_diff(
                current.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile="committed",
                tofile="generated",
                n=2,
            )
            for line in list(diff)[:40]:
                sys.stderr.write(line)
            sys.exit(1)
    elif "--write" in args:
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(updated)
        print(f"✅ {README_PATH} updated ({len(entries)} entries)")
    else:
        sys.stdout.write(updated)


if __name__ == "__main__":
    main()
