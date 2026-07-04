# Web UI — Reference Mockups

Self-contained HTML mockups for the CFGMS web UI design direction (Epic #2344).
Open any file directly in a browser — no build step, no external assets. Each
file wraps its mockup in a small preview harness:

- **Desktop / Tablet / Mobile** viewport toggle (renders the mockup in an
  iframe so its responsive breakpoints fire off the framed width, letting you
  review the desktop layout from a phone).
- The cockpit adds an **Auto / Light / Dark** theme toggle.

See [`../web-ui-design-system.md`](../web-ui-design-system.md) for the identity,
principles, and token rationale these mockups express.

| File | What it is | Status |
|------|------------|--------|
| [`troubleshooting-cockpit.html`](troubleshooting-cockpit.html) | The chosen direction — agentic troubleshooting cockpit: case bar, dense ticket quick-reference, tabbed Investigation/Chat rail, and an evidence→cause→action canvas (drift-diff, blast-radius graph, change timeline, remediation). Brand-aligned, both themes. | **Reference** |
| [`fleet-overview-generic-v0.html`](fleet-overview-generic-v0.html) | The initial generic management dashboard, before brand alignment. Kept for provenance only. | Superseded |

> These are design references, not production code. The shipped UI is
> React + TypeScript + Vite (Epic #2344), built against
> [`../web-ui-design-tokens.css`](../web-ui-design-tokens.css) as the source of truth.
