# Pin Cooldown Policy

Why we wait, how long, and when we override.

## The 3-day default

Default cooldown: **3 days** from upstream release `published_at` before bumping a pin.

### Why we wait at all

Three classes of incident the cooldown defends against:

1. **Supply-chain compromise** — malicious or compromised release that the upstream maintainer or registry yanks within hours-to-days. CVE-2026-33634 (compromised Trivy v0.69.4-6, ref `docs/runbooks/trivy-rollback.md`) is the canonical example. The maintainer yanked the bad versions within 48 hours. A 3-day window catches the obvious cases without making us laggards.
2. **Regression in the release** — the release builds and ships but introduces a behavior regression that surfaces over 24-72 hours of community use. Bumping immediately means we run into the regression too.
3. **Build/install issues** — the release artifact has a missing file, wrong checksum, or broken installer. Caught quickly by the broader community.

### Why 3 days specifically

| Threshold | Pro | Con |
|---|---|---|
| 0 days (immediate) | Always on the latest | Full exposure to supply-chain attacks |
| 3 days (default) | Catches supply-chain yanks (48-72h typical) | Brief lag on patches |
| 7 days | More conservative | Real lag during active CVE waves |
| 14 days | Maximum caution | Months behind on routine updates |

The CFGMS posture is **3 days routine, override on CI-blocking CVE**. Aligned with the founder's stated policy ("3-5 days from release unless upgrade faster is warranted to fix a current vulnerability").

## Per-pin overrides

The default is 3 days for every pin discovered. Per-pin overrides live in a small JSON file alongside this doc:

`.claude/skills/refresh-pins/references/cooldown-overrides.json` (optional — absent file means "all pins use the default")

Example:

```json
{
  "go-toolchain": {"cooldown_days": 5, "reason": "stdlib bumps touch the entire build; extra caution"},
  "gosec":        {"cooldown_days": 2, "reason": "low blast radius; faster refresh OK"}
}
```

Claude reads this in Phase 3 and applies the per-pin value when present.

## Override conditions (skip the cooldown)

The cooldown is overridden when ANY of these are true:

1. **Active CVE blocking required CI** — see `decision-matrix.md` for the precise definition. This is the common case.
2. **`--urgent` flag** at invocation time — founder asserts urgency from external knowledge (Trivy DB lag, supply-chain announcement, etc.).
3. **Cooldown override file exists with `force: true`** — emergency mode, set by the founder for a specific pin. Documented in the audit log immediately. Removed after the bump lands.

When the cooldown is overridden, **the audit log entry is mandatory**.

## The audit log

Location: `.claude/scratch/pin-overrides.log`

Format (one line per override, append-only):

```
<ISO-8601 UTC>  <pin-name>  <from>→<to>  <reason>  story:#<NNNN>
```

Examples:

```
2026-05-12T15:30:14Z  go-toolchain  1.25.9→1.25.10  CVE-2026-33811 (+4 more) blocking security-deployment-gate  story:#1444
2026-05-15T08:12:00Z  trivy         v0.70.0→v0.71.0  --urgent (founder: yanked-version-announcement)            story:#1450
```

Rationale (why an append-only log):

- **Auditability**: every bump-without-cooldown leaves a record of why
- **Pattern detection**: if the same pin gets overridden repeatedly, the cooldown for that pin may need tuning
- **Forensics**: when a future incident traces back to a too-fast bump, the log shows the decision and its rationale
- **Append-only**: rewriting history defeats the audit purpose. Use a new line to correct a prior entry.

Claude appends via `printf '...' >> .claude/scratch/pin-overrides.log` — never rewrites.

## When NOT to override

Even with these signals, do NOT skip cooldown when:

- The CVE severity is `MEDIUM` or `LOW` (only HIGH/CRITICAL justifies the override)
- The CVE is in a code path the project doesn't exercise (mark as `accept-risk` in a tracking issue rather than racing to bump)
- The release was published less than 6 hours ago — `published_at < 6 hours` is too fresh even with a CVE; wait the minimum 6h for any obvious supply-chain yank to surface

The 6-hour minimum is hard-coded; it's not configurable per pin. A release that's been out less than 6 hours is too fresh to trust, full stop.
