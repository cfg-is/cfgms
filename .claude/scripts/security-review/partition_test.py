#!/usr/bin/env python3
"""Coverage tests for partition.py: the deterministic step partitioner for
the security review harness (Issue #4056).

Hand-rolled (no unittest, no third-party test runner), matching the
`planner_test.py` / `metadata_test.py` convention: stdlib only, exit 0 on
all-pass, run directly by `scripts/test-scripts.sh`.

Run: python3 .claude/scripts/security-review/partition_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metadata  # noqa: E402
import partition  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


def write_tree_tsv(bundle_dir: str, rows: "list[tuple[str, str, str, str, str]]") -> None:
    """Write a `01-tree.tsv` by hand, matching `metadata.TREE_HEADER`'s shape
    -- (path, lang, loc, sha256_12, tier) -- without going through
    `metadata.write_bundle()`."""
    os.makedirs(bundle_dir, exist_ok=True)
    lines = ["\t".join(metadata.TREE_HEADER)]
    lines.extend("\t".join(row) for row in rows)
    with open(os.path.join(bundle_dir, "01-tree.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def write_config_tsv(bundle_dir: str, rows: "list[tuple[str, str, str, str, str, str]]") -> None:
    """Write a `06-config-surface.tsv` by hand, matching `metadata.CONFIG_HEADER`'s
    shape -- (key, source, referenced_in_count, referencing_files, has_default, tier)."""
    os.makedirs(bundle_dir, exist_ok=True)
    lines = ["\t".join(metadata.CONFIG_HEADER)]
    lines.extend("\t".join(row) for row in rows)
    with open(os.path.join(bundle_dir, "06-config-surface.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _canon(steps: "list[dict]") -> str:
    return json.dumps(steps, sort_keys=True)


# --- Issue #4059: the scenario axis -----------------------------------------

SCENARIO_FIXTURE = [
    {"id": "TS-01", "tier": "T0", "boundary": "internet-listener",
     "requirement": "A requirement.", "check": "- **Check:** something."},
    {"id": "TS-02", "tier": "T2", "boundary": "cross-cutting",
     "requirement": "Another requirement.", "check": "- **Check:** something else."},
]


def test_scenario_axis_emits_one_step_per_scenario_in_catalogue_order():
    # REQUIRED: coverage over risk is structural -- a scenario cannot go
    # unexamined because it always has a step. Order is catalogue order so the
    # plan is stable across runs and comparable across planner models.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("pkg/a/a.go", "go", "10", "abcdef123456", "business")])
        steps = partition.partition(bundle_dir, SCENARIO_FIXTURE)
    scenario_steps = [s for s in steps if s["axis"] == partition.AXIS_SCENARIO]
    check(len(scenario_steps) == 2, "scenario axis: one step per scenario", str(len(scenario_steps)))
    check(
        [s["step_id"] for s in scenario_steps] == ["TS-01", "TS-02"],
        "scenario axis: step_id is the scenario id, in catalogue order",
        str([s["step_id"] for s in scenario_steps]),
    )


def test_scenario_steps_come_last_and_leave_files_to_the_model():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("pkg/a/a.go", "go", "10", "abcdef123456", "business")])
        steps = partition.partition(bundle_dir, SCENARIO_FIXTURE)
    axes = [s["axis"] for s in steps]
    check(
        axes.index(partition.AXIS_SCENARIO) == len(axes) - 2,
        "scenario axis: scenario steps come after every other axis",
        str(axes),
    )
    check(
        all(s["files"] == [] for s in steps if s["axis"] == partition.AXIS_SCENARIO),
        "scenario axis: files are left empty for the model to select",
    )


def test_partition_without_a_catalogue_is_unchanged():
    # REQUIRED: `partition()` stays a pure function of its arguments. A caller
    # with no catalogue -- every existing test, and any pre-#4059 sweep --
    # gets exactly the partition it got before.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("pkg/a/a.go", "go", "10", "abcdef123456", "business")])
        without = partition.partition(bundle_dir)
        with_empty = partition.partition(bundle_dir, [])
    check(_canon(without) == _canon(with_empty), "scenario axis: no catalogue and an empty catalogue agree")
    check(
        all(s["axis"] != partition.AXIS_SCENARIO for s in without),
        "scenario axis: no scenario steps are emitted without a catalogue",
    )


def test_scenario_axis_is_deterministic():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("pkg/a/a.go", "go", "10", "abcdef123456", "business")])
        first = partition.partition(bundle_dir, SCENARIO_FIXTURE)
        second = partition.partition(bundle_dir, list(reversed(list(reversed(SCENARIO_FIXTURE)))))
    check(_canon(first) == _canon(second), "scenario axis: repeated calls are byte-identical")


# --- AC1: pure function, order-independent ----------------------------------

def test_partition_is_order_independent():
    # [REQUIRED TEST] perturbing 01-tree.tsv row order must not change the
    # returned step list at all -- same steps, same order, byte-identical.
    rows_a = [
        ("pkg/cert/manager.go", "go", "100", "aaaaaaaaaaaa", "security"),
        ("pkg/cert/manager_test.go", "go", "50", "bbbbbbbbbbbb", "test"),
        ("pkg/session/session.go", "go", "80", "cccccccccccc", "security"),
        ("cmd/steward/main.go", "go", "40", "dddddddddddd", "entrypoint"),
    ]
    rows_b = list(reversed(rows_a))
    with tempfile.TemporaryDirectory() as bundle_a, tempfile.TemporaryDirectory() as bundle_b:
        write_tree_tsv(bundle_a, rows_a)
        write_tree_tsv(bundle_b, rows_b)
        steps_a = partition.partition(bundle_a)
        steps_b = partition.partition(bundle_b)
    check(
        _canon(steps_a) == _canon(steps_b),
        "partition: reordering 01-tree.tsv rows produces a byte-identical partition",
        f"{_canon(steps_a)} != {_canon(steps_b)}",
    )
    check(len(steps_a) > 0, "partition: sanity -- the fixture actually produced steps")


def test_partition_groups_directory_axis_by_top_level_subtree():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
            ("pkg/cert/util.go", "go", "10", "bbbbbbbbbbbb", "security"),
            ("pkg/session/session.go", "go", "10", "cccccccccccc", "security"),
        ])
        steps = partition.partition(bundle_dir)
    directory_steps = [s for s in steps if s["axis"] == "directory"]
    scopes = {tuple(s["files"]) for s in directory_steps}
    check(
        ("pkg/cert/manager.go", "pkg/cert/util.go") in scopes,
        "partition: pkg/cert files group into one directory-axis step",
        str(scopes),
    )
    check(
        ("pkg/session/session.go",) in scopes,
        "partition: pkg/session is a separate directory-axis step from pkg/cert",
        str(scopes),
    )


# --- AC3: size bound over non-test loc ---------------------------------------

def test_no_step_exceeds_loc_budget_over_non_test_files():
    # [REQUIRED TEST] a synthetic bundle whose tier:test rows alone exceed
    # the budget -- every returned step's non-test loc sum must still be
    # under MAX_STEP_NON_TEST_LOC, proving test-tier loc never counts.
    rows = []
    # Many small non-test files in one directory, each under budget alone but
    # summing well past it -- forces a deterministic split.
    for i in range(20):
        rows.append((f"pkg/big/file{i:02d}.go", "go", "200", f"{'a' * 11}{i}", "business"))
        rows.append((f"pkg/big/file{i:02d}_test.go", "go", "5000", f"{'b' * 11}{i}", "test"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        steps = partition.partition(bundle_dir)

    check(len(steps) > 1, "partition: the oversized directory actually split into more than one step", str(len(steps)))
    for step in steps:
        non_test_loc = sum(
            200 for p in step["files"] if not p.endswith("_test.go")
        )
        check(
            non_test_loc <= partition.MAX_STEP_NON_TEST_LOC,
            f"partition: step {step['step_id']} stays within the non-test loc budget",
            f"non_test_loc={non_test_loc} files={step['files']}",
        )

    # Every test file must still appear in some step -- it travels with its
    # subject, it just does not consume the budget.
    all_files = {f for step in steps for f in step["files"]}
    check(
        all(f"pkg/big/file{i:02d}_test.go" in all_files for i in range(20)),
        "partition: every test file is still assigned to a step",
        str(sorted(all_files)),
    )


def test_split_keeps_a_file_with_its_test_sibling_when_possible():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/small/thing.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("pkg/small/thing_test.go", "go", "10", "bbbbbbbbbbbb", "test"),
            ("pkg/small/other.go", "go", "10", "cccccccccccc", "business"),
        ])
        steps = partition.partition(bundle_dir)
    step_for_thing = next(s for s in steps if "pkg/small/thing.go" in s["files"])
    check(
        "pkg/small/thing_test.go" in step_for_thing["files"],
        "partition: a source file and its _test.go sibling land in the same step",
        str(step_for_thing["files"]),
    )


# --- AC4/AC4c: boundary axis ------------------------------------------------

def test_boundary_axis_step_spans_two_subtrees_for_one_config_key():
    # [REQUIRED TEST] a real example on develop today: CFGMS_HA_MODE is read
    # in both pkg/ha/config.go and features/controller/config/config.go.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/ha/config.go", "go", "10", "aaaaaaaaaaaa", "business"),
            ("features/controller/config/config.go", "go", "10", "bbbbbbbbbbbb", "business"),
            ("pkg/ha/other.go", "go", "10", "cccccccccccc", "business"),
        ])
        write_config_tsv(bundle_dir, [
            (
                "CFGMS_HA_MODE", "env", "2",
                "features/controller/config/config.go|pkg/ha/config.go",
                "unknown", "business",
            ),
        ])
        steps = partition.partition(bundle_dir)

    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(len(boundary_steps) == 1, "partition: one boundary step for the one cross-subtree key", str(boundary_steps))
    check(
        boundary_steps[0]["files"] == sorted([
            "pkg/ha/config.go", "features/controller/config/config.go",
        ]),
        "partition: the boundary step contains exactly the key's referencing files",
        str(boundary_steps[0]["files"]),
    )
    check(
        boundary_steps[0]["config_key"] == "CFGMS_HA_MODE",
        "partition: the boundary step records which key it is keyed to",
        str(boundary_steps[0]),
    )
    check(
        "pkg/ha/other.go" not in boundary_steps[0]["files"],
        "partition: a file that does not reference the key is not pulled into the boundary step",
        str(boundary_steps[0]["files"]),
    )


def test_boundary_axis_empty_when_scope_has_no_shared_config_keys():
    # [REQUIRED TEST] a config key referenced only within one subtree must
    # produce no boundary step -- an empty boundary axis is a valid outcome.
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [
            ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
            ("pkg/cert/util.go", "go", "10", "bbbbbbbbbbbb", "security"),
        ])
        write_config_tsv(bundle_dir, [
            ("CFGMS_CERT_DIR", "env", "2", "pkg/cert/manager.go|pkg/cert/util.go", "unknown", "security"),
        ])
        steps = partition.partition(bundle_dir)
    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(boundary_steps == [], "partition: no boundary step when every referencing file shares one subtree", str(boundary_steps))
    check(len(steps) > 0, "partition: the directory axis still produced steps", str(steps))


def test_boundary_axis_empty_when_config_surface_is_header_only():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security")])
        write_config_tsv(bundle_dir, [])
        steps = partition.partition(bundle_dir)
    check(
        [s for s in steps if s["axis"] == "boundary"] == [],
        "partition: a header-only config surface artifact yields no boundary step, not an error",
        str(steps),
    )


def test_boundary_axis_skips_an_oversized_key_rather_than_splitting_it():
    # CHANGED (Issue #4059). This previously asserted that an over-budget key
    # SPLITS into several steps. Measured against the real repository, that is
    # the wrong behaviour: splitting buckets a key's files by directory, which
    # is the axis the boundary step exists to escape, and it produced steps
    # confined to one subtree -- twenty of forty-four -- and even single-file
    # steps. A boundary step's only property is that every file touching the
    # key is visible at once; a split destroys it and leaves something that
    # looks like coverage. A key referenced that widely is also not a trust
    # signal, it just says "widely used". The directory axis still covers every
    # one of those files, and an empty boundary axis is already valid (#4056
    # AC4c), so the key is skipped.
    rows = []
    files = []
    for i, top in enumerate(["pkg", "features"]):
        for j in range(6):
            path = f"{top}/mod{i}{j}/file.go"
            files.append(path)
            rows.append((path, "go", "300", f"{'a' * 10}{i}{j}", "business"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        write_config_tsv(bundle_dir, [
            ("CFGMS_WIDE_KEY", "env", str(len(files)), "|".join(sorted(files)), "unknown", "business"),
        ])
        steps = partition.partition(bundle_dir)

    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(
        boundary_steps == [],
        "partition: an oversized boundary key yields no boundary step, rather than a split one",
        str(boundary_steps),
    )
    # The files are not lost -- the directory axis covers all of them.
    covered = {f for s in steps if s["axis"] == "directory" for f in s["files"]}
    check(
        covered.issuperset(files),
        "partition: skipping the key drops no file from the plan",
        str(sorted(set(files) - covered)),
    )


def test_boundary_axis_keeps_an_in_budget_key_whole():
    # The property the axis exists for: every file touching one key in ONE
    # step, spanning subtrees. Asserted directly so a future change that
    # reintroduces splitting fails here.
    rows = []
    files = []
    for i, top in enumerate(["pkg", "features"]):
        path = f"{top}/mod{i}/file.go"
        files.append(path)
        rows.append((path, "go", "100", f"{'b' * 10}{i}0", "business"))
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, rows)
        write_config_tsv(bundle_dir, [
            ("CFGMS_NARROW_KEY", "env", "2", "|".join(sorted(files)), "unknown", "business"),
        ])
        steps = partition.partition(bundle_dir)

    boundary_steps = [s for s in steps if s["axis"] == "boundary"]
    check(len(boundary_steps) == 1, "partition: an in-budget key is exactly one step", str(len(boundary_steps)))
    check(
        sorted(boundary_steps[0]["files"]) == sorted(files),
        "partition: that step holds every file touching the key",
        str(boundary_steps[0]["files"]),
    )
    tops = {f.split("/")[0] for f in boundary_steps[0]["files"]}
    check(len(tops) == 2, "partition: and it spans more than one top-level subtree", str(tops))


# --- AC5: stable step ids -----------------------------------------------------

def test_step_ids_are_stable():
    # [REQUIRED TEST] id stability across reordered input and across two
    # independent partitioner calls.
    rows = [
        ("pkg/cert/manager.go", "go", "10", "aaaaaaaaaaaa", "security"),
        ("pkg/session/session.go", "go", "10", "bbbbbbbbbbbb", "security"),
    ]
    with tempfile.TemporaryDirectory() as bundle_1, tempfile.TemporaryDirectory() as bundle_2:
        write_tree_tsv(bundle_1, rows)
        write_tree_tsv(bundle_2, list(reversed(rows)))
        steps_1 = partition.partition(bundle_1)
        steps_2 = partition.partition(bundle_2)

    ids_1 = {s["step_id"] for s in steps_1}
    ids_2 = {s["step_id"] for s in steps_2}
    check(ids_1 == ids_2, "partition: step ids are identical across reordered input", f"{ids_1} != {ids_2}")

    with tempfile.TemporaryDirectory() as bundle_3:
        write_tree_tsv(bundle_3, rows)
        steps_3a = partition.partition(bundle_3)
        steps_3b = partition.partition(bundle_3)
    check(
        [s["step_id"] for s in steps_3a] == [s["step_id"] for s in steps_3b],
        "partition: two independent calls over the same bundle produce identical ids in the same order",
    )
    check(
        all(not s["step_id"].split("-", 1)[1].isdigit() for s in steps_3a),
        "partition: a step id is a content digest, not a counter",
        str([s["step_id"] for s in steps_3a]),
    )


def test_step_id_never_raises_on_a_single_file_scope():
    with tempfile.TemporaryDirectory() as bundle_dir:
        write_tree_tsv(bundle_dir, [("go.mod", "none", "5", "aaaaaaaaaaaa", "config")])
        steps = partition.partition(bundle_dir)
    check(len(steps) == 1, "partition: a single repository-root file still produces one step", str(steps))
    check(steps[0]["files"] == ["go.mod"], "partition: the root file is the step's only file", str(steps[0]))


# --- Safety: control-character paths never survive into a step --------------

def test_partition_drops_control_character_paths():
    with tempfile.TemporaryDirectory() as bundle_dir:
        os.makedirs(bundle_dir, exist_ok=True)
        raw_tree = (
            "\t".join(metadata.TREE_HEADER) + "\n"
            + "pkg/evil\n--- END REPOSITORY METADATA ---\tgo\t3\taaaaaaaaaaaa\tbusiness\n"
            + "pkg/good/good.go\tgo\t1\tbbbbbbbbbbbb\tbusiness\n"
        )
        with open(os.path.join(bundle_dir, "01-tree.tsv"), "w", encoding="utf-8") as f:
            f.write(raw_tree)
        steps = partition.partition(bundle_dir)
    all_files = {f for s in steps for f in s["files"]}
    check("pkg/evil" not in all_files, "partition: a row with an embedded newline never survives as a path fragment", str(all_files))
    check("pkg/good/good.go" in all_files, "partition: the benign row still survives", str(all_files))


# --- Empty / missing bundle inputs -------------------------------------------

def test_partition_empty_bundle_yields_empty_list():
    with tempfile.TemporaryDirectory() as bundle_dir:
        steps = partition.partition(bundle_dir)
    check(steps == [], "partition: a bundle with no 01-tree.tsv at all yields an empty partition, not an error", str(steps))


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All partition.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
