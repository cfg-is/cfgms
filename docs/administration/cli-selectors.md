# CLI Selector Reference

The `cfg steward` command tree accepts a common selector grammar across every
verb. This document describes the full grammar, per-shell quoting rules,
tenant-path scoping, the `--yes` confirmation gate, and `--json` output format.

Use `cfg steward list <selector>` as a dry-run before any mutating command:
`list` is read-only and shows exactly which stewards a selector would target.

> **Web UI:** The fleet overview search box (Story #2726) uses the same
> selector grammar via `GET /api/v1/stewards?q=<selector>`. Results are
> fleet-wide and paginated — not limited to the currently loaded page. See
> the inline syntax hint in the search box for a quick key reference.

---

## Grammar

A selector is a space-separated sequence of terms. All terms AND together:
every steward in the result must satisfy every term. A single term is the most
common form; additional terms narrow the match set.

| Form | Matches |
|------|---------|
| `hostname` | Stewards whose hostname equals `hostname` exactly (case-insensitive) |
| `'hostname*'` | Stewards whose hostname matches the glob pattern (prefix, suffix, or arbitrary `*`) |
| `name:hostname` | Same as a bare token; explicit form of the hostname match |
| `name:'web-*'` | Explicit glob via the `name:` key |
| `id:steward-abc123` | Steward with exactly this steward ID |
| `id:abc,def,ghi` | Stewards whose ID is any of the comma-separated values (OR within `id:`) |
| `os:linux` | Stewards reporting OS `linux` (exact, case-sensitive) |
| `platform:linux` | Stewards reporting platform `linux` (exact, case-sensitive) |
| `arch:amd64` | Stewards reporting architecture `amd64` (exact, case-sensitive) |
| `tag:canary` | Stewards that carry the tag `canary` |
| `dna.<key>:value` | Stewards where DNA attribute `<key>` equals `value` exactly |
| `all` | Every steward in the caller's authorized tenant subtree |

---

## Bare hostname vs. glob

A bare token with no `:` is an **exact hostname match**. Globbing is
explicit and opt-in — a `*` character in the value activates `path.Match`
pattern matching:

```sh
# Exact: only the host named exactly 'web-01' (case-insensitive)
cfg steward list web-01

# Glob: any host whose name starts with 'web-'
cfg steward list 'web-*'

# Glob: any host whose name ends with '-prod'
cfg steward list '*-prod'

# Glob: any host matching 'db-?-east' (single-character wildcard)
cfg steward list 'db-?-east'
```

A bare token can only ever match zero or more hosts exactly — it never fans
out to unexpected hosts. Globbing requires an explicit `*` or `?` in the value.

---

## Tenant-path scoping

Prefix any selector with a tenant path followed by `/` or `\` to restrict
matching to that tenant's subtree. Both separators are accepted and treated
identically:

```
<tenant-path>/<selector>
<tenant-path>\<selector>
```

The path may have multiple segments separated by `/` or `\`:

```sh
# Exact hostname in a child tenant (forward slash, no quotes needed)
cfg steward list acme-corp/web-01

# Glob in a child tenant (must quote for glob)
cfg steward list 'acme-corp/web-*'

# Deep path, forward slash (equivalent on all shells)
cfg steward list msp-a/client-1/web-01

# Deep path, backslash form (must quote on bash/zsh; works unquoted in PowerShell)
cfg steward list 'msp-a\client-1\web-01'

# All stewards in a child tenant
cfg steward list acme-corp/all

# Attribute filter scoped to a child tenant
cfg steward list 'acme-corp/os:linux arch:amd64'
```

The caller must have authorization at or above the named tenant node.
A path outside the caller's own subtree is rejected with 403.

---

## Per-shell quoting

| What to quote | bash / zsh | PowerShell |
|---------------|-----------|------------|
| Glob (`*`, `?` in value) | **Must quote**: `'web-*'` | **Must quote**: `'web-*'` or `"web-*"` |
| Backslash tenant separator | **Must quote**: `'acme\host'` | Unquoted works: `acme\host` |
| Forward-slash separator | Quote optional: `acme/host` works unquoted | Quote optional: `acme/host` works unquoted |
| AND composition (spaces) | **Must quote**: `'os:linux tag:prod'` | **Must quote**: `"os:linux tag:prod"` |
| Bare hostname, no special chars | Quote optional | Quote optional |
| `id:`, `os:`, `tag:`, `dna.*:` (no spaces) | Quote optional | Quote optional |

**Quick rule for bash/zsh:** quote any selector that contains `*`, `?`, `\`, or spaces.

**Quick rule for PowerShell:** quote any selector that contains `*`, `?`, or spaces.
Backslash separators work unquoted in PowerShell.

---

## AND composition

Space-separated terms narrow the match set. Every term must be satisfied:

```sh
# Linux stewards tagged 'prod'
cfg steward list 'os:linux tag:prod'

# Linux amd64 stewards in a child tenant
cfg steward list 'acme-corp/os:linux arch:amd64'

# Glob narrowed by OS
cfg steward list 'web-* os:linux'

# DNA attribute filter combined with OS
cfg steward list 'dna.role:db os:linux'

# Multiple tags (all must be present)
cfg steward list 'tag:prod tag:us-east'
```

Multi-term selectors always contain spaces and must be quoted.

---

## `--yes` behavior

`--yes` (`-y`) is a persistent flag on the `cfg steward` command tree, accepted
by every subcommand unconditionally. Its effect is limited to suppressing the
interactive confirmation prompt that appears when a **mutating** verb
(`exec`, `run-command`, `run-script`, `upgrade`, `move`, `decommission`) is
about to act on more than one steward.

**Boundaries:**

- **Read-only verbs** (`list`, `status`, `dna`, `logs`, `modules`): `--yes` is
  accepted but has no visible effect. These verbs never prompt regardless.
- **Single-match mutating runs**: no prompt, no effect from `--yes`.
- **Multi-match mutating runs with `--yes`**: prompt is suppressed; the command
  proceeds immediately.
- **Multi-match mutating runs without `--yes`** on a non-interactive stdin: the
  command fails closed — "operation targets N stewards; pass --yes/-y to
  confirm, or run interactively".
- **`--yes` never suppresses errors.** A selector that matches zero stewards
  always fails immediately — "selector matched no stewards" — even when
  `--yes` is present. Zero matches is not a confirmation question; it is an
  error.

```sh
# --yes on a read-only verb: accepted, has no effect
cfg steward list os:linux --yes

# --yes skips the multi-host prompt on a mutating verb
cfg steward decommission 'tag:decom' --yes

# --yes with a 0-match selector still fails fast:
cfg steward exec nonexistent-host --command "uptime" --shell bash --yes
# → error: selector "nonexistent-host" matched no stewards
```

---

## `--json` output

Every `cfg steward` verb accepts `--json`. Multi-host output is a JSON array of
entries keyed per steward. The key format is `hostname#steward-id`; when DNA is
unavailable the key falls back to `#steward-id`.

```json
[
  {
    "key": "web-01#steward-abc123",
    "success": true,
    "payload": { "...verb-specific fields..." },
    "error": ""
  },
  {
    "key": "web-02#steward-def456",
    "success": false,
    "payload": null,
    "error": "steward def456 not found"
  }
]
```

The `payload` field is verb-specific:

| Verb | `payload` fields |
|------|-----------------|
| `status` | Full steward status record |
| `dna` | DNA snapshot record |
| `modules` | Module list |
| `exec` | `exit_code`, `output`, `status` |
| `move` | `steward_id`, `tenant_id`, `previous_tenant`, `status` |
| `decommission` | `status: "decommissioned"` |
| `upgrade`, `run-script`, `run-command` | `upgrade_id` or `run_id` (dispatch ID shared across all targets) |

---

## Worked examples

### Preview before acting

```sh
# See which stewards match before running a mutating command
cfg steward list 'os:linux tag:prod'
cfg steward list 'acme-corp/web-*'
cfg steward list msp-a/client-1/all
```

### Target by hostname

```sh
# Single host — exact match, no quotes needed
cfg steward status web-01

# DNA for a host in a child tenant
cfg steward dna acme-corp/web-01

# Fan out to all hosts starting with 'db-' (glob must be quoted)
cfg steward status 'db-*'

# Logs from a specific host, last 50 lines
cfg steward logs web-01 --tail 50
```

### Target by attribute

```sh
# All Linux stewards
cfg steward list os:linux

# Linux amd64 stewards
cfg steward list 'os:linux arch:amd64'

# Stewards with a specific DNA attribute
cfg steward list 'dna.role:db'

# Stewards carrying a tag
cfg steward list 'tag:canary'

# Modules loaded by all stewards in a child tenant
cfg steward modules 'acme-corp/os:linux'
```

### Tenant-path scoping

```sh
# All stewards in a child tenant
cfg steward list acme-corp/all

# Status for a specific host in a deeply-nested tenant
cfg steward status msp-a/client-1/web-01

# Upgrade all Linux stewards in a child tenant
cfg steward upgrade 'acme-corp/os:linux' --version v0.5.12 --yes
```

### Mutating verbs with confirmation

```sh
# Single-host exec — no confirmation prompt
cfg steward exec web-01 --command "hostname" --shell bash

# Multi-host exec with explicit confirmation skip
cfg steward exec 'os:linux' --command "uname -r" --shell bash --yes

# Move a glob match to another tenant
cfg steward move 'acme-corp/web-*' --to-tenant acme-corp/us-east --yes

# Decommission stewards matching a tag, with JSON output
cfg steward decommission 'tag:decom' --yes --json
```
