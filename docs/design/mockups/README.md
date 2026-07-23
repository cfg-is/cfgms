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

| File | What it is | Status |
|------|------------|--------|
| [`troubleshooting-cockpit.html`](troubleshooting-cockpit.html) | The chosen direction — agentic troubleshooting cockpit: case bar, dense ticket quick-reference, tabbed Investigation/Chat rail, and an evidence→cause→action canvas (drift-diff, blast-radius graph, change timeline, remediation). Brand-aligned, both themes. | **Reference** |
| [`login.html`](login.html) | The authentication screen — terminal-window framing, single mTLS/session sign-in, with `signin` / `loading` / `invalid` / `expired` states and a **passkey/WebAuthn MFA seam** (`mfa` state) designed now, built later. Both themes. | **Reference** |
| [`fleet-overview.html`](fleet-overview.html) | The read-only fleet overview inside the app shell — tenant-scope switcher, live-filter search, sort, saved views, selectable **device-DNA columns**, scale-aware pagination, and a row drill-in **asset-DNA drawer**. Both themes; Ready / Loading / Error / Empty states. | **Reference** |
| [`fleet-overview-generic-v0.html`](fleet-overview-generic-v0.html) | The initial generic management dashboard, before brand alignment. Kept for provenance only. | Superseded |
| [`asset-live-activity.html`](asset-live-activity.html) | The asset live-activity tab — real-time process table and service list driven by the telemetry WebSocket; includes the `.rowkebab` per-row action menu pattern (applied to fleet rows in Story #2938). Both themes. | **Reference** |
| [`asset-shell.html`](asset-shell.html) | The asset interactive shell tab — terminal emulator panel with WebSocket-backed session, command history, and resize handling. Both themes. | **Reference** |

> These are design references, not production code. The shipped UI is
> React + TypeScript + Vite (Epic #2344), built against
> [`../web-ui-design-tokens.css`](../web-ui-design-tokens.css) as the source of truth.
