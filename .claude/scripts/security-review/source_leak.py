#!/usr/bin/env python3
"""Source-leak guard for the verification stage (Issue #4071).

The verification stage is the one place in this harness that reads source AND
produces text that travels onward. Its verdicts are handed to the adjudicator,
which runs a hosted frontier model and must never see source -- that separation
is the reason the two are distinct stages rather than one.

A verifier can prove reachability without quoting code: it cites `file:line`
coordinates, symbol and function names, and a call path made of identifiers.
All three are already metadata this harness ships -- every finding carries
`file` and `symbol`, and the planner bundle ships `01-tree.tsv` and
`03-routes.tsv`. What it must never do is paste the lines it read.

This module makes that a checked property rather than an instruction in a
prompt. A prompt asks; a check enforces. Measured repeatedly across Issue
#4069: a model told not to do something does it anyway at a rate that
run-to-run variance makes hard to even measure, so the only controls that hold
are the ones that do not depend on the model choosing to comply.

Pure functions, no I/O: fully covered by `source_leak_test.py` without a
container, a model, or a repository checkout.
"""
from __future__ import annotations

import re

# A verbatim run this long, lifted from a file the verifier read, is a code
# excerpt rather than a reference to one.
#
# Why 60. Identifiers are short: the longest symbol in the measured sweep
# (`makeHeartbeatStatusChangeCallback`, `resolveMaxTargetsForTenant`) is under
# 40 characters, and a call path built from them -- "handleListAuditEntries ->
# store.Query -> fmt.Errorf" -- does not appear verbatim in any source file
# because the arrows are not in the source. A copied line of Go, by contrast,
# runs well past 60 with its receiver, arguments and error wrapping intact.
#
# The threshold is deliberately a floor rather than a guess to be tuned: raising
# it lets longer excerpts through, and the cost of lowering it is a rejected
# verdict the verifier can restate, which is cheap and visible.
DEFAULT_MIN_LEAK_CHARS = 60

# Comparison is whitespace-insensitive. A model re-indenting a copied line, or
# joining it onto one line, is still shipping the line; matching raw text would
# miss exactly the case worth catching.
_WS_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Collapse whitespace runs to a single space and strip the ends.

    The one normalisation applied to both sides of the comparison, so a leak
    cannot be disguised by reformatting."""
    return _WS_RE.sub(" ", text or "").strip()


def find_leak(
    text: str, sources: "dict | list | str", min_chars: int = DEFAULT_MIN_LEAK_CHARS
) -> "str | None":
    """Return the first verbatim span of at least `min_chars` that `text` shares
    with any of `sources`, or `None` when there is none.

    `sources` is the content of the files the verifier read -- a mapping of path
    to content, a list of contents, or a single string; only the content is
    used, never the paths.

    Returns the offending span itself rather than a boolean so the caller can
    name what leaked when it rejects the verdict. An empty `text`, empty
    `sources`, or a non-positive `min_chars` returns `None`: there is nothing to
    leak, or nothing to leak into.
    """
    if not text or min_chars <= 0:
        return None

    if isinstance(sources, str):
        contents = [sources]
    elif isinstance(sources, dict):
        contents = list(sources.values())
    else:
        contents = list(sources or [])

    haystacks = [normalize(c) for c in contents if c]
    if not haystacks:
        return None

    needle = normalize(text)
    if len(needle) < min_chars:
        return None

    # Slide a window of exactly `min_chars` over the verdict text. A longer
    # shared run necessarily contains a window of this length, so checking every
    # window of the minimum size finds every leak; the span returned is the
    # first one, which is enough to name the problem.
    for start in range(len(needle) - min_chars + 1):
        span = needle[start : start + min_chars]
        for hay in haystacks:
            if span in hay:
                return span
    return None


def assert_no_leak(
    text: str, sources: "dict | list | str", min_chars: int = DEFAULT_MIN_LEAK_CHARS
) -> None:
    """Raise `SourceLeakError` when `text` shares a verbatim span with `sources`.

    The raising form, for the path where a leak must stop the verdict rather
    than be recorded and carried onward."""
    span = find_leak(text, sources, min_chars)
    if span is not None:
        raise SourceLeakError(
            f"verdict contains a {len(span)}-character verbatim span from a file "
            f"the verifier read; cite coordinates and identifiers, never source "
            f"text. Offending span: {span!r}"
        )


class SourceLeakError(ValueError):
    """Raised when text bound for a stage that must not see source contains a
    verbatim excerpt of it."""
