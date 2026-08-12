# Web UI — Reference Mockups

Self-contained HTML mockups for the CFGMS web UI design direction (Epic #2344).
Open any file directly in a browser — no build step, no external assets. Each
file wraps its mockup in a small preview harness:

- **Desktop / Tablet / Mobile** viewport toggle (renders the mockup in an
  iframe so its responsive breakpoints fire off the framed width, letting you
  review the desktop layout from a phone).
- The cockpit, login, and fleet-overview add an **Auto / Light / Dark** theme
  toggle. The fleet-overview also carries a small **preview state** strip
  (Ready / Loading / Error / Empty) so its data-state screens can be reviewed
  from one file; that strip is a harness affordance, not product UI.

See [`../web-ui-design-system.md`](../web-ui-design-system.md) for the identity,
principles, and token rationale these mockups express.

<!-- BEGIN GENERATED TABLE -->
| File | What it is | Status |
|------|------------|--------|
| [`troubleshooting-cockpit.html`](troubleshooting-cockpit.html) | The chosen direction — agentic troubleshooting cockpit: case bar, dense ticket quick-reference, tabbed Investigation/Chat rail, and an evidence→cause→action canvas (drift-diff, blast-radius graph, change timeline, remediation). Brand-aligned, both themes. | **Reference** |
| [`login.html`](login.html) | The authentication screen — **passkey-only** (ADR-021 Amendment 1): usernameless-first "Sign in with a passkey", optional username to scope to a specific account, "Remember Username" prefill, no password. `signin` / `waiting` / `invalid` (no passkey) / `expired` states, both themes. | **Reference** |
| [`passkeys.html`](passkeys.html) | Self-service **My passkeys** (Epic #2931 / #2992) — list / add / remove your own passkeys: editable label, device-type sub-line, "This device" chip, Added / Last-used. Add & remove step up to `AssuranceStrong`. `list` (several keys) and `one` (backup nudge + last key's Remove **locked** — the anti-lockout guard) states, both themes. | **Reference** |
| [`fleet-overview.html`](fleet-overview.html) | The read-only fleet overview inside the app shell — tenant-scope switcher, live-filter search, sort, saved views, selectable **device-DNA columns**, scale-aware pagination, and a row drill-in **asset-DNA drawer**. Both themes; Ready / Loading / Error / Empty states. | **Reference** |
| [`registration-console.html`](registration-console.html) | The **Registration** console (Epic #2931 · #2934/#2935/#2936) — one page, three tabs: **Pending** (enrollment queue, Deny live), **Tokens** (prefix-only, status badges), **IP-Trust** (CIDRs, pre-seeded vs manual). Write controls (Approve/Approve-all/Approve-by-CIDR · Mint/Rotate/Revoke · Add range) drawn in a deferred **"SOON"** state. Tenant-scoped, both themes. | **Reference** |
| [`fleet-overview-generic-v0.html`](fleet-overview-generic-v0.html) | The initial generic management dashboard, before brand alignment. Kept for provenance only. | Superseded |
| [`asset-live-activity.html`](asset-live-activity.html) | The asset live-activity tab — real-time process table and service list driven by the telemetry WebSocket; includes the `.rowkebab` per-row action menu pattern (applied to fleet rows in Story #2938). Both themes. | **Reference** |
| [`asset-shell.html`](asset-shell.html) | The asset interactive shell tab — terminal emulator panel with WebSocket-backed session, command history, and resize handling. Both themes. | **Reference** |
| [`workflow-studio.html`](workflow-studio.html) | The Workflow Studio surface (Epic #2859) — a browse/run/schedule **overlay** drawer over the workflow list, and a full-screen **flowchart builder**: typed nodes, parallel branches + fan-in joins, node palette, live run-state overlay, collapsible scheduler drawer, and an indent-guided YAML mirror. Renders directly (no iframe harness) with its own **View / Run-state / Theme** toggles; both themes. | **Reference** |
| [`refresh-queue.html`](refresh-queue.html) | The **Refresh requests** page (Epic #2931 · #2941) — its own nav entry / `/refresh` route (not a console tab). Pending steward device-credential rotations with a **provenance-match** column (partial match = amber, scrutinize); **Reject** live, **Approve** deferred ("SOON"). Tenant-scoped, both themes. | **Reference** |
| [`fleet-bulk.html`](fleet-bulk.html) | Fleet **bulk selection + actions** (Epic #2931 · #2939) — a checkbox column + select-all-on-page and a bulk-action bar layered on the fleet table: **Edit tags** live (one authorized call per steward), **Decommission** deferred ("SOON"). Selection clears on page/filter/sort. Both themes. | **Reference** |
| [`certificates.html`](certificates.html) | **Certificate lifecycle** (Epic #2858 · #3135) — list with days-remaining/amber/red expiry warnings, inline provision form, per-row revoke confirm, and a fleet-impact-worded, type-`ROTATE`-to-confirm signing-CA rotation modal. Both themes. | **Reference** |
| [`tenant-admin.html`](tenant-admin.html) | Tenant admin tree (Epic #2858 · #3131) — built against **ADR-025** (SaaS-operator ↔ MSP access boundary) and **ADR-027** (cascade suspend/restore + Suspend→Hold→Delete). A **Session** switcher demos all three: **MSP admin** — cascade-aware Suspend/Restore with direct-vs-cascade provenance (restoring an ancestor never restores an independently-suspended descendant), a "not fully suspended" delete rejection naming the offending descendant, a hold-eligibility countdown with Cancel, and a distinct dual-control "Approve deletion" action for a second principal; **Root — no grant** — the ADR-025 boundary/empty state; **Root — break-glass active** — the same subtree unlocked under a time-boxed, audited elevation. Both themes. | **Reference** |
| [`subject-roles.html`](subject-roles.html) | **Subject-role assignment** (Epic #2858 · #3134) — extends `AccountsView`'s account row with an expand panel (the same pattern `RolesView` uses for permissions) to view, assign, and revoke a subject's roles in place. Role picker + Assign, chip `×` + confirm to revoke, and a distinct 403 escalation-prevention message. Both themes. | **Reference** |
| [`visibility-surfaces.html`](visibility-surfaces.html) | **Visibility surfaces** (Epic #2860) — four screens behind a **Surface** switcher: **Reports** (hero score, KPI stat tiles, drift-trend line chart + table view, insights/actions, template list + generate), **Compliance** (observed drift from DNA snapshot history — labelled for what it measures, not "convergence"; per-tenant stacked drift mix, per-device detail with the honest empty-patches state), **Monitoring** (health + component grid, the always-empty anomalies and always-503 per-component states drawn as designed states, read-only config), and the **Alert center** (populated bell + popover, acknowledge and step-up-gated silence). Establishes the **validated** chart conventions — sequential for magnitude, reserved status scale for state (always icon + label), categorical capped at 4 series, 2px surface gaps/rings, table view on every chart. Ready / Loading / Error / Empty per surface; both themes. | **Reference** |
<!-- END GENERATED TABLE -->

> These are design references, not production code. The shipped UI is
> React + TypeScript + Vite (Epic #2344), built against
> [`../web-ui-design-tokens.css`](../web-ui-design-tokens.css) as the source of truth.
