# Security Review Harness

A periodic, advisory, multi-lab LLM review harness that reads the codebase and produces
structured findings for human triage. It never blocks a PR and never files issues directly —
report-first, always. See epic #3900 for the full design rationale and locked intent decisions.

This document is the canonical reference for the artifact layout, the four-terminal-state
resume rule, and the de-duplication key rule. Every harness story (schema validation, the
lane adapters, the consolidator, the orchestrator) points here instead of re-deriving these
rules independently.

## Implementation

Python 3 standard library plus bash, matching the existing `.claude/scripts/` convention —
no third-party pip dependencies (no `jsonschema`, nothing). The shared, dependency-free
primitives live in `.claude/scripts/security-review/`:

| Module | Responsibility |
|---|---|
| `schema.py` | `validate_finding`, `validate_step_envelope`, and the injection-safe `safe_log_event`/`log_event` log formatter |
| `atomic_write.py` | `write_json_atomic` — temp file + `os.replace`, never a partial file visible at the final path |
| `resume.py` | `missing_steps` — resolves outstanding steps under the four-terminal-state rule below |
| `basedir.py` | `resolve_base_dir` — fail-closed resolution of the sweep base directory |
| `consolidate.py` | `consolidate` — reads every lane's step files, de-dupes findings, and renders `report/consolidated.json` / `report/consolidated.md` |

This directory's name contains a hyphen, so it is never imported with a plain
`import security-review` statement. A module that needs a sibling imports it the way
`.claude/metrics/usage_db.py` imports `token_report.py`:
`sys.path.insert(0, str(Path(__file__).resolve().parent))` followed by a plain `import <module>`.

## Artifact layout

All sweep state lives outside the repository, under a base directory resolved by
`basedir.py::resolve_base_dir()` (default `${HOME}/.cache/cfgms-security-review`, matching the
`CFGMS_AGENT_SESSIONS_BASE` / `CFGMS_AGENT_LEDGER_DIR` precedent in
`.claude/scripts/agent-dispatch.sh`). Nothing under this tree is ever committed.

```
~/.cache/cfgms-security-review/
  <sweep-id>/
    manifest.json                      sweep config: lanes, target ref, step list, status
    plan/
      step-001.json                    step prompt + scope (generated from metadata only)
      step-002.json
      ...
    lanes/
      anthropic-opus5/
        step-001.findings.json         terminal: step complete and validated
        step-002.status.json           non-terminal: parked | refused | failed
        ...
      openai-gpt56-sol/
        step-001.findings.json
        ...
      ollama-qwen/
        step-001.findings.json
        ...
    report/
      consolidated.json                machine-readable, de-duplicated
      consolidated.md                  what the PO reads
```

**Sweep id** is `<UTC timestamp>-<short sha>`, e.g. `2026-09-05T0214Z-0541b9c8`, binding the
sweep to the exact commit it reviewed — findings are only meaningful against the tree they
were produced from, and `develop` moves several times an hour.

**Naming is deterministic and self-describing.** From any path you can read the sweep, the
lane (lab + model), and the step — `lanes/openai-gpt56-sol/step-007.findings.json` needs no
index to interpret.

This story (#3901) defines the schema, the atomic writer, the resume scanner, and the
fail-closed base-dir resolver only. It does not create the sweep tree above — that is
story S2 (#3902).

## The four terminal states

A step is the unit of restartability. Resume is stateless: rescan the lane directory, run
whatever `resume.py::missing_steps()` reports as outstanding. There is no separate progress
database to corrupt.

| State | Meaning | On resume |
|---|---|---|
| `complete` | findings written and schema-valid | skip |
| `parked` | rate limited or quota exhausted (HTTP 429, plan cap) | retry |
| `refused` | model declined the request on policy grounds | retry once on fallback, then surface |
| `failed` | auth error, schema violation, malformed response | surface to human, do not retry |

A step is `complete` if and only if its `<step_id>.findings.json` exists **and** validates
against the step-envelope schema with `state == "complete"`. A `.findings.json` that fails
schema validation is treated as **not complete** — it is returned by `missing_steps()` for
reattempt or human inspection, never silently dropped (this is what "a lane emitting a
schema-invalid finding marks that step `failed`, and does not silently drop it" means in
practice: the resume scanner is the mechanism that keeps it visible).

`<step_id>.status.json` carries the envelope for the three non-terminal outcomes. A `refused`
step is returned as missing on every scan; distinguishing a first-refusal-retry from a
second-refusal-surface is a lane-side concern (only the lane knows its own fallback-model
policy) — `resume.py` only reports "still needs work". A `failed` step is deliberately never
returned as missing: it is surfaced to a human, never auto-retried, per the table above.

## Writes are atomic

Every artifact under the sweep tree is written via `atomic_write.py::write_json_atomic()`:
serialize to `<path>.tmp` in the same directory, `fsync` the file descriptor, then
`os.replace(tmp, path)`. `os.replace` is atomic on both POSIX and Windows — unlike
`os.rename` on Windows, which fails outright if the destination already exists. A process
killed mid-write can never leave a truncated file that looks complete: the final path is
either the previous complete version or does not exist yet, never a partial write.

## Schemas

### Finding

Every lane emits the same shape (`schema.py::validate_finding`):

```json
{
  "sweep_id":      "2026-09-05T0214Z-0541b9c8",
  "commit_sha":    "0541b9c8",
  "lane":          "anthropic-opus5",
  "step_id":       "step-007",
  "file":          "pkg/example/thing.go",
  "symbol":        "Thing.DoSomething",
  "vuln_class":    "<taxonomy value>",
  "severity":      "<low|medium|high|critical>",
  "confidence":    "<low|medium|high>",
  "title":         "...",
  "evidence":      "...",
  "suggested_fix": "..."
}
```

All twelve fields are required. `severity` and `confidence` are validated against their enum;
every other field must be a non-empty string.

**The de-duplication key is `file` + `symbol` + `vuln_class` — never a line number.** Line
ranges rot as `develop` advances; symbol names survive. `schema.py` does not define or read a
line-number field of any kind. A caller-supplied line-shaped field (`line`, `line_number`,
`line_range`, ...) is silently ignored, not rejected and not validated, so nothing downstream
can key on it by accident.

`confidence` is recorded per finding but is not used to filter at the finder stage — filtering
during discovery measurably depresses recall. Coverage is the finder's job; ranking is the
consolidator's.

### Step envelope

The record a lane writes per step, regardless of outcome (`schema.py::validate_step_envelope`):

```json
{
  "sweep_id":        "2026-09-05T0214Z-0541b9c8",
  "commit_sha":      "0541b9c8",
  "lane":            "anthropic-opus5",
  "step_id":         "step-007",
  "state":           "<complete|parked|refused|failed>",
  "model_id":        "claude-opus-5",
  "stop_reason_raw": "<provider's raw, unmodified terminating reason>",
  "findings":        []
}
```

`sweep_id`, `commit_sha`, `lane`, `step_id`, `state`, and `model_id` are always required.

- When `state == "complete"`: `findings` is required as a list (`[]` is valid and distinct from
  `refused`/`failed` — a genuinely clean step is still `complete`). `stop_reason_raw` is not
  required.
- For every other state: `stop_reason_raw` is required and must be non-empty. `findings` is
  not read.

`stop_reason_raw` is recorded **verbatim** — whatever the provider actually returned, unmodified
— so a new refusal encoding after a provider update is diagnosable from the recorded envelope
rather than lost to a normalized enum. This module defines the envelope shape only; each lane
decides how it populates `stop_reason_raw` from its own provider's response shape (Anthropic
`stop_reason`, OpenAI `finish_reason`, or another provider's equivalent field) — that mapping,
and refusal detection itself, are lane stories (#3906–#3908), not this one.

## Fail-closed base directory

`basedir.py::resolve_base_dir()` reads `CFGMS_SECURITY_REVIEW_BASE`, defaulting to
`${HOME}/.cache/cfgms-security-review` only when the env var is genuinely unset. It raises
(the CLI form exits non-zero and prints nothing to stdout) instead of ever returning a path
that is:

- empty, or `.`,
- inside the repository root or any subpath of it (repo root detected via
  `git rev-parse --show-toplevel`, or passed explicitly by the caller), or
- not creatable/writable.

Failure to determine the repo root is itself a fail-closed condition, not a reason to skip the
guard: if no `repo_root` is passed and `git rev-parse --show-toplevel` cannot answer — git absent
from `PATH`, the 10s timeout, a cwd that is not a work tree, or empty output — `resolve_base_dir()`
raises before creating anything. Otherwise a run in any of those states would resolve to an in-repo
path and create the sweep tree there, which is precisely what this control exists to stop. Callers
that legitimately run outside a checkout pass the root explicitly (`--repo-root`).

There is no working-directory fallback and no `./` default. This is the actual control — a
`.gitignore` entry is belt-and-braces only, since a root-anchored entry would not catch a
sweep tree written to an unexpected in-repo path.

## Log injection

Findings and step envelopes carry model-generated text (`title`, `evidence`, `stop_reason_raw`)
into diagnostic logs. `make lint-log-injection` does not apply to this code — that target is a
Go linter over `features/**/api/` and cannot see this Python. Every place this package logs
tainted content routes through `schema.py::safe_log_event`/`log_event`, which renders a single
JSON line via `json.dumps` — embedded newlines and control characters inside string values are
escaped, so a payload crafted to look like a second log line stays inside its field instead of
becoming one. `resume.py` uses this when it logs a schema-invalid `.findings.json` for human
diagnosis.

## Consolidation and the coverage table

`consolidate.py::consolidate(sweep_dir, repo_root)` (#3904) is the last step of a sweep: a pure
read-existing-files-and-render pass over whatever `lanes/<lane>/step-*.findings.json` and
`step-*.status.json` files currently exist, in any state of completeness. It never calls a
provider API and never dispatches a container, so it is safe to run — and to test — against
fixture data before any lane (S6/S7/S8) exists. It produces two files under
`<sweep_dir>/report/`:

- `consolidated.json` — machine-readable, de-duplicated findings.
- `consolidated.md` — the coverage table followed by the findings, what the PO reads.

**De-duplication key is `file` + `symbol` + `vuln_class`**, exactly as the Finding schema above —
never a line number. Every occurrence across every lane's `step-*.findings.json` sharing this key
collapses into one consolidated entry; the entry's `lanes` field lists exactly the lanes that
independently reported it, and `occurrences` keeps each lane's own `severity`/`confidence`/
`title`/`evidence`/`suggested_fix` rather than discarding the disagreement.

**Agreement is measured against completed steps, not configured lanes.** A consolidated
finding's `agreement` field is `{"reported": N, "eligible": M}`, where `M` is the number of
lanes that actually completed the step(s) the finding came from — not the number of lanes in
the sweep. A lane that never ran that step (parked, failed, or not yet dispatched) contributes
neither a "reported" nor a "did not find it" signal, so it must not inflate the denominator:
counting it as silent agreement is exactly the false-confidence failure mode SEC3900's
refusal-handling section exists to prevent, just relocated to the consolidator.

**The coverage table** in `consolidated.md` has one row per lane discovered under `lanes/`, with
`complete`/`parked`/`refused`/`failed` counts (rendered as `N/M` against the total steps
discovered across the whole sweep) derived from every lane's status/findings files. A sweep with
zero lane output (no lane directories, or lane directories with no step files yet) renders as
`0/0` for every state, not an error — an incomplete sweep is visibly incomplete on the first
screen of the report rather than only inferable by counting files. This module trusts the
`state` field in each envelope as already correctly classified by the lane that wrote it; it
does not re-derive refusal/parked/failed from raw provider fields itself.

**Schema-invalid files are excluded, not crashed on.** Every file is validated through
`schema.py`'s actual `validate_finding`/`validate_step_envelope` — never a hand-typed
"does this look valid" check that could drift from the real schema. A file that fails
validation contributes no findings and is counted as `failed` in the coverage table for that
lane/step, exactly as visible as a normal `failed` step.

**Path-traversal validation (SEC3900 A1).** A finding's `file` field is model-generated text.
Before it is used for anything, it is checked for membership in the real repository tree at the
finding's own `commit_sha` (`git ls-tree -r --name-only <commit_sha>`, resolved once per
distinct `commit_sha` and cached). A `file` value that is absolute, `../`-shaped, or simply
absent from that tree is excluded from both output files and logged via `schema.py::log_event`
for human follow-up. `file` is never joined onto a filesystem path or opened — the only
operation performed against it is a set-membership check — so a malicious value cannot cause a
path operation outside the sweep tree.

**Markdown rendering never trusts model text as structure.** `title`/`evidence` render as
literal content: embedded newlines are escaped to `\n` and `|` is escaped to `\|` before
insertion, so a forged Markdown heading or table-row sequence embedded in a finding cannot
become a real heading or an extra table row — it stays inline text inside the cell/line it was
written into.
