#!/usr/bin/env python3
"""Coverage tests for source_leak.py (Issue #4071).

Hand-rolled (no unittest, no third-party runner, no mocks), matching the
`schema_test.py` / `scenarios_test.py` convention: stdlib only, exit 0 on
all-pass, non-zero otherwise, auto-discovered by `scripts/test-scripts.sh`.

The cases below are built from real source out of this repository rather than
invented strings, because the property under test is "does a real copied line
get caught, and does a real legitimate citation get through" -- and a synthetic
string proves neither.

Run: python3 .claude/scripts/security-review/source_leak_test.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_leak  # noqa: E402

FAILURES: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    if cond:
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(name)
        print(f"  [FAIL] {name}" + (f"\n         {detail}" if detail else ""))


# A real excerpt from pkg/audit/manager.go, the file the measured false positive
# and several confirmed findings concern.
REAL_SOURCE = '''
func (m *Manager) enqueue(ctx context.Context, entry *business.AuditEntry) error {
	select {
	case <-m.stop:
		return fmt.Errorf("audit manager is stopped")
	default:
	}

	select {
	case m.queue <- entry:
		return nil
	case <-m.stop:
		return fmt.Errorf("audit manager is stopped")
	case <-ctx.Done():
		return fmt.Errorf("audit enqueue cancelled while waiting for capacity: %w", ctx.Err())
	}
}
'''


def test_a_copied_line_of_source_is_caught():
    verdict = (
        "The call is reachable. Relevant code: "
        'return fmt.Errorf("audit enqueue cancelled while waiting for capacity: %w", ctx.Err())'
    )
    span = source_leak.find_leak(verdict, {"pkg/audit/manager.go": REAL_SOURCE})
    check(span is not None, "a pasted line of source is caught", repr(verdict[:70]))
    check(
        span is not None and len(span) >= source_leak.DEFAULT_MIN_LEAK_CHARS,
        "the offending span is returned so the caller can name what leaked",
        repr(span),
    )


def test_a_coordinate_and_identifier_citation_passes():
    # The shape the verifier is supposed to emit: coordinates, symbols, a call
    # path, a vocabulary verdict. No source text.
    verdict = (
        "reachable_from_untrusted. Entry point handleListAuditEntries at "
        "features/controller/api/handlers_audit.go:79 reaches Manager.enqueue at "
        "pkg/audit/manager.go:336 via store.Query. No guard found."
    )
    check(
        source_leak.find_leak(verdict, {"pkg/audit/manager.go": REAL_SOURCE}) is None,
        "a coordinate-and-identifier citation is not a leak",
        repr(source_leak.find_leak(verdict, {"pkg/audit/manager.go": REAL_SOURCE})),
    )


def test_a_bare_symbol_name_is_never_a_leak():
    # Every finding already carries `file` and `symbol`; naming them back cannot
    # be the thing that trips the guard.
    for symbol in ("enqueue", "Manager.enqueue", "makeHeartbeatStatusChangeCallback",
                   "resolveMaxTargetsForTenant", "errorMessageRedactPattern"):
        check(
            source_leak.find_leak(symbol, {"f.go": REAL_SOURCE}) is None,
            f"the symbol {symbol!r} alone is not a leak",
        )


def test_reindented_source_is_still_caught():
    # A model re-indenting or re-joining a copied line is still shipping it.
    # Comparison is whitespace-insensitive on both sides for exactly this.
    verdict = (
        "case <-ctx.Done(): return fmt.Errorf("
        '"audit enqueue cancelled while waiting for capacity: %w", ctx.Err())'
    )
    check(
        source_leak.find_leak(verdict, REAL_SOURCE) is not None,
        "reformatted source is still caught",
        repr(source_leak.find_leak(verdict, REAL_SOURCE)),
    )


def test_text_shorter_than_the_threshold_cannot_leak():
    check(
        source_leak.find_leak("case <-m.stop:", REAL_SOURCE) is None,
        "text shorter than the threshold is not a leak",
    )


def test_empty_inputs_are_not_leaks():
    check(source_leak.find_leak("", REAL_SOURCE) is None, "empty text is not a leak")
    check(source_leak.find_leak("anything at all", "") is None, "empty source is not a leak")
    check(source_leak.find_leak("anything at all", {}) is None, "empty mapping is not a leak")
    check(source_leak.find_leak("anything at all", []) is None, "empty list is not a leak")
    check(source_leak.find_leak(None, REAL_SOURCE) is None, "None text is not a leak")


def test_sources_accept_mapping_list_or_string():
    leak = (
        'return fmt.Errorf("audit enqueue cancelled while waiting for capacity: %w", ctx.Err())'
    )
    check(source_leak.find_leak(leak, REAL_SOURCE) is not None, "sources as a bare string")
    check(source_leak.find_leak(leak, [REAL_SOURCE]) is not None, "sources as a list")
    check(source_leak.find_leak(leak, {"a.go": REAL_SOURCE}) is not None, "sources as a mapping")


def test_only_content_is_compared_never_paths():
    # A path is metadata the harness already ships; matching against it would
    # reject the coordinate citations the verifier is required to produce.
    check(
        source_leak.find_leak(
            "pkg/audit/manager.go:336 reaches pkg/storage/interfaces/business/audit_store.go:41",
            {"pkg/audit/manager.go": "package audit"},
        )
        is None,
        "file paths in the verdict are not compared against source paths",
    )


def test_the_threshold_is_configurable_and_lowering_it_catches_more():
    short = "case <-m.stop:"
    check(source_leak.find_leak(short, REAL_SOURCE, min_chars=10) is not None,
          "a lower threshold catches a shorter span")
    check(source_leak.find_leak(short, REAL_SOURCE, min_chars=200) is None,
          "a higher threshold lets it through")
    check(source_leak.find_leak(short, REAL_SOURCE, min_chars=0) is None,
          "a non-positive threshold disables the check rather than matching everything")


def test_assert_form_raises_and_names_the_span():
    leak = (
        'return fmt.Errorf("audit enqueue cancelled while waiting for capacity: %w", ctx.Err())'
    )
    try:
        source_leak.assert_no_leak(leak, REAL_SOURCE)
    except source_leak.SourceLeakError as exc:
        check("verbatim span" in str(exc), "assert_no_leak: raises SourceLeakError", str(exc)[:90])
        check("audit enqueue cancelled" in str(exc),
              "assert_no_leak: the message names the offending span", str(exc)[:120])
    else:
        check(False, "assert_no_leak: raises SourceLeakError", "no error raised")


def test_assert_form_is_silent_on_a_clean_verdict():
    try:
        source_leak.assert_no_leak(
            "reachable_from_untrusted via handleListAuditEntries at handlers_audit.go:79",
            REAL_SOURCE,
        )
        check(True, "assert_no_leak: a clean verdict passes silently")
    except source_leak.SourceLeakError as exc:
        check(False, "assert_no_leak: a clean verdict passes silently", str(exc))


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("All source_leak.py checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
