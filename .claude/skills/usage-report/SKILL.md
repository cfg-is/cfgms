---
name: usage-report
description: Analyze Claude Code pipeline token and dollar usage from the token_report.py harness -- by time window, segment, model, role, agent layer, or story/PR. Use whenever the founder asks about token usage, spend, cost, "where's the money going", a usage/cost breakdown, or a report scoped to a time window (e.g. "since Wed 5:00", "last 3 days", "this week").
context: fork
agent: general-purpose
allowed-tools: Bash
---

# Usage Report Skill

You answer questions about pipeline token/dollar spend using
`.claude/metrics/token_report.py`, which reads Claude Code's own transcripts
-- no new instrumentation, no guessing. Produce one concise narrative
summary back to the caller: total spend, the breakdown that actually answers
their question, and any caveat that changes how the numbers should be read.
Do not dump the raw table unless asked for detail.

This skill is about **usage telemetry** (where did tokens/dollars actually
go). It is unrelated to `.claude/bench/` (quality-per-dollar benchmarking) --
don't conflate the two even though both live under epic #3026.

## Inputs

`$ARGUMENTS` is the caller's request in their own words, e.g. empty, "since
Wed 5:00", "last 3 days by model", "cost per story this week", "which review
lens costs the most", "where's the money going".

## Step 1: Resolve the time window to a precise `--since <DAYS>`

`--since` takes a **plain float number of days**, applied internally as
`now - timedelta(days=N)`. There is no separate flag for an absolute
timestamp -- but because the subtraction is linear, any absolute cutoff can
be expressed exactly as a fractional day count. Do not reach for
`--format jsonl` + manual timestamp filtering; it is unnecessary and this
already handles arbitrary precision.

1. Get the current instant: `date -u +%s`.
2. Resolve the request to a target UTC instant:
   - "last N days" / "this week" (~7) / no window mentioned → use N directly,
     or default to 7 if nothing was said.
   - A named day/time ("since Wed 5:00", "since 3pm yesterday") → resolve to
     the most recent **past** occurrence of that day/time relative to now
     (if today itself is that weekday, treat "since <weekday>" as meaning
     earlier today unless the phrasing implies a week prior). Convert to a
     UTC epoch with `date -u -d '<description>' +%s` where the shell
     supports GNU date; otherwise compute the date by hand from the current
     date and day-of-week.
3. Compute `since_days = (now_epoch - target_epoch) / 86400.0` and pass
   `--since <since_days>` verbatim (a plain decimal is fine, e.g. `1.7083`).

## Step 2: Pick the report shape from the request

| the caller is asking about | command |
|---|---|
| general "usage/cost since X", no further detail | `--composition` **and** `--group-by segment --top 20` |
| a specific model / "are we routing to the cheap model" | `--group-by model` |
| a trend / "this week" broken down by day | `--group-by day` |
| "which role / review lens / tech-lead / fix round costs what" | `--group-by role` |
| "main loop vs subagents vs workflow agents" | `--group-by agent` |
| "where does the money actually go" (cache vs generation) | `--composition` |
| a specific story/PR number, or "cost per story/PR" | `--story-report` (see caveat below) |
| ambiguous / caller just says "usage" or "spend" | run composition + `--group-by segment` together and present both |

All non-story-report commands take the same `--since` from Step 1. Add
`--project <slug>` only if the caller names a specific repo/project.

## Step 3: Run it

```bash
.claude/metrics/token_report.py --since <N> --composition
.claude/metrics/token_report.py --since <N> --group-by <key> --top 20
```

For a story/PR question:

```bash
.claude/metrics/token_report.py --story-report --since <N>
```

## Step 4: Report back -- narrative, not a data dump

State the total spend for the window up front, then the one or two numbers
that actually answer what was asked (top segment/model/role and its share,
or the specific story's dev/fix/review split). Mention the window you
resolved in plain terms ("since 2026-07-22 17:00 UTC, ~6 days") so the
caller can sanity-check your date math.

Always surface these when they apply -- they change how the numbers should
be read, not just decorate them:

- **A model row marked `UNPRICED`** (`*`) in the output means it has no entry
  in `pricing.json`; its tokens are real but its dollar figure is not
  guessed. Say so rather than silently omitting or estimating it.
- **`--story-report` rows can be `partial`** -- transcript missing, story
  number unresolved, or (the common case for anything dispatched before dev-agent
  session persistence landed, or before the `cfg-agent` image was rebuilt
  after it) no dev-mode launch was found, so the largest cost component is
  silently absent, not genuinely zero. Never report a partial row's total as
  complete.
- **Dispatched dev/fix-agent containers only produce telemetry if the
  `cfg-agent:latest` image was rebuilt after dev-agent session persistence
  (story #3051) landed.** If a window's dispatched-agent numbers look
  suspiciously low or absent, check `docker images cfg-agent --format
  '{{.CreatedAt}}'` against when #3051 merged and flag the gap rather than
  reporting silence as "no cost."
- Cost composition, if you ran it: call out the cache-read/cache-write share
  vs. output share -- historically ~90%+ of spend is context re-reading, not
  generation, which matters for where the caller should focus optimization.

If `token_report.py` reports "No transcript directory found" or similar, say
so plainly rather than presenting an empty report as zero usage.
