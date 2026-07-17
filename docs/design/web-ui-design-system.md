# CFGMS Web UI — Design System

This document is the founder-owned design direction for the CFGMS web UI and the
`docs/design/web-ui-design-system.md` deliverable named in Epic #2344. It defines
the visual identity, the working principle, the case model, and the reference
screens (login, fleet overview, troubleshooting cockpit) that the shipped
React + TypeScript + Vite app is built to match. It is a design reference, not
production code; the mockups express intent, the tokens are the source of truth.

Machine-readable tokens live in [`web-ui-design-tokens.css`](web-ui-design-tokens.css).
Reference mockups live in [`mockups/`](mockups/).

---

## 1. Identity: a warm terminal

Every other tool in the operations/RMM category dresses as a cold blue-black
control panel. CFGMS goes the other way on purpose: a **warm terminal** — a
calm, dense, instrument-grade surface that reads as purpose-built tooling, not
a generic SaaS dashboard. The identity is derived directly from the public
brand style guide (https://cfg.is/style-guide) and amplifies its most
distinctive traits.

**The four pillars:**

1. **Warm grounds, warm text.** Near-black `#1e1e1e` / warm-paper `#f7f4ef`
   grounds with **warm taupe** body text (`#c4b4a4` / `#6b5a4a`), never a cool
   grey or stark off-white. This is the single most identity-defining choice.
2. **Colour is information.** Semantic **state** (converged / drift / error /
   queued) owns the colour budget. When everything is coloured, nothing
   signals — so most surfaces stay warm-neutral and let a red *mean* a problem.
3. **The accent is for interaction only.** The muted slate-blue accent
   (`#7b9fb0` / `#4a6b7c`) marks what is interactive — focus, selection, links,
   primary actions — and is never spent on decoration or on conveying state.
4. **Mono carries machine data.** Every hostname, hash, timestamp, config key,
   ring name, and identifier is set in JetBrains Mono. Used heavily, it gives
   the UI its instrument texture and makes machine values unambiguous.

### Semantics (desaturated earth tones)

| Meaning              | Token           | Light     | Dark      |
|----------------------|-----------------|-----------|-----------|
| Converged / success  | `--state-ok`    | `#507055` | `#6d9472` |
| Drift / warning      | `--state-warn`  | `#a05a35` | `#d4864f` |
| Error (terracotta)   | `--state-crit`  | `#b56a5a` | `#c97a6a` |
| Error (mauve, alt)   | `--state-mauve` | `#7a5f6e` | `#a58198` |
| Queued / inert       | `--state-neutral`| `#7a6a5a`| `#a89888` |

### Card tints encode meaning, not decoration

The style guide's muted card-tint palette is used to give a card a **role at a
glance**: the problem card wears the red tint, the remediation card the green
tint, dependency/attention the orange, neutral context the blue, reference the
brown, summary the cream. A tint is never applied for visual variety alone.

### Typography

- **Inter** — UI and body (weights 400/500/600/700).
- **JetBrains Mono** — all machine data (400/500/700).
- **Ubuntu Mono** — reserved for logo / terminal accents.
- Uppercase micro-labels carry `letter-spacing: 0.09em`; numeric columns use
  `font-variant-numeric: tabular-nums`.
- Font delivery for the shipped app is an open item (see §6) — the mockups use
  a progressive stack that falls back to the platform UI/mono faces when the
  brand webfonts are not present.

### Theme model

Light is the default token set; dark is supplied under
`@media (prefers-color-scheme: dark)`; and `:root[data-theme="…"]` overrides the
media query in both directions so an in-app theme control can force either
theme. Both themes are first-class and equally tuned — dark is not a naive
inversion of light.

---

## 2. Working principle: Lean Six Sigma (reduce motion)

The UI is designed to get a technician to the information they need in far less
time than any other platform, by eliminating the classic wastes of RMM work:

| Waste           | Where it hides                              | Our answer                                            |
|-----------------|---------------------------------------------|-------------------------------------------------------|
| Transportation  | Swivel-chair across RMM / PSA / docs / remote | One surface; the case *is* the ticket *is* the asset |
| Motion          | Clicking down client→site→device→tab trees   | Info comes to the work; keyboard/command-palette entry |
| Waiting         | Page loads, agent check-ins, script runs     | Live/streaming; desired state already known           |
| Over-processing | Manually correlating drift ↔ change ↔ alert  | The system pre-correlates before the tech arrives     |
| Inventory       | Alert/ticket pile-up as WIP                  | Auto-triage; only actionable items surface            |
| Defects         | Wrong asset, stale data, fat-fingered fix    | Desired-state guardrails + preview/approve            |
| Non-used talent | Senior techs doing L1 triage                 | Automation handles rote; escalates only the novel     |

**The thesis:** other tools make you *browse to* the problem; CFGMS brings the
**assembled case** to you. Navigation itself is the waste to remove.

---

## 3. The case model and two intake modes

The atomic unit of work is a **case** (alert- or ticket-triggered). The same
case model and the same canvas cards serve two intake modes; only the direction
that evidence flows differs:

- **Email ticket (asynchronous).** CFGMS pre-investigates and the case *arrives
  with the evidence assembled*. The rail opens on the **Investigation** tab
  showing prepared findings; the technician confirms and resolves. Evidence
  flows agent → canvas.
- **Live call (synchronous).** The technician's hands and attention are on the
  phone, so the conversation leads. The rail opens on the **Chat** tab where the
  dispatcher narrates the call or `@`-summons specialist bots, and the canvas
  populates from the conversation. Evidence flows conversation → canvas.

Progressive disclosure serves both L1 and L2/L3 on one surface: L1 sees the
assembled answer; any card can be peeled back to raw telemetry for deeper tiers.

---

## 4. Component patterns (established in the mockups)

- **Case bar** — sticky header: case id + asset + tenant path (mono), intake
  toggle (Email / Live), SLA state.
- **Ticket quick-reference** — dense, top-left, always glanceable on a call.
  Mandatory fields (Title, Client, Primary contact, Priority, Category) show
  their source (`email`, `caller-ID`); missing fields stay highlighted until
  collected and can be filled from an existing ticket, a caller-ID / PSA lookup,
  chat input, or direct edit.
- **Tabbed rail** — Investigation and Chat share one column; the intake mode
  sets the default tab.
- **Evidence canvas** — reads top-to-bottom as **evidence → cause → action**:
  a desired-vs-actual **drift-diff** hero (the CFGMS-native object), a
  **dependency/blast-radius graph**, a **change timeline**, and a
  **remediation plan** with preview/approve.
- **State pills, stat tiles, sparklines** — semantic colour only.
- **Asset-page tab frame** (Story #2723) — the per-steward page at
  `/stewards/:id` wraps content in a horizontal tab strip: an active tab
  (underline + accent colour, font-weight 600) and inert placeholders
  carrying the same `soon` badge used in the sidebar nav (opacity 0.5,
  cursor disabled, `tag` span). The tab panel (`role="tabpanel"`) mounts
  the active tab's content. Inert tabs render a centred placeholder with
  the `soon` badge and a short label; they do not throw or navigate.
  Back-navigation is a breadcrumb `Fleet / {hostname}` above the `<h1>`;
  the browser's own back button and the link both return to `/`.

---

## 5. Screens (established in the mockups)

Three reference screens fix the identity for the parts of the app that gate
early development. Each mockup is responsive (Desktop / Tablet / Mobile) and
ships both themes.

### 5.1 Login — [`mockups/login.html`](mockups/login.html)

A single, quiet authentication surface framed as a **terminal window** (the one
place the Ubuntu-Mono terminal accent is spent). One credential path to start —
the mTLS/session sign-in that mirrors `cfg` — with the full set of states the
screen must handle already drawn:

- `signin` (default), `loading`, `invalid` (bad credential), and `expired`
  (session timed out — re-authenticate), so error and lifecycle copy are
  designed, not left to implementation.
- An **MFA seam**: a `mfa` state carrying a passkey/WebAuthn challenge. The
  layout, copy, and control are designed **now** so the flow has a home; the
  actual second-factor enforcement is built later (see **ADR-018 — web-session
  semantics**, PR #2350, for the session model this feeds).

### 5.2 App shell + fleet overview — [`mockups/fleet-overview.html`](mockups/fleet-overview.html)

The **app shell** every authenticated screen lives in: left sidebar, a top
**app bar** with a **tenant-scope switcher** (the `root / msp-a` path selector),
global **search**, an **alert/notification center**, and a **user menu**. On
phones the search drops to its own full-width row; the sidebar becomes an
off-canvas drawer.

The first screen inside the shell is the **read-only fleet overview** — stewards
enrolled to the controller — carrying the patterns early development needs:

- **Live-filter search**, not a command bar: typing narrows the visible rows in
  place (name, company, last user, IP, OS, health, ring, agent) and updates the
  match count and pager live. Clearing restores the full list.
- **Selectable device-DNA columns.** A column picker chooses which DNA a
  technician sees. Defaults are Name, Company, Last user, IP, Health, Last
  check-in; additional DNA (OS, Agent, Ring, Model, Serial, MAC) is opt-in. Name
  is pinned. A trailing spacer column absorbs slack so columns hug their content
  and the name column never balloons as DNA is added.
- **Sort, saved views, and scale-aware pagination** — the count and pager are
  written for 48k+ stewards, not a demo-sized list.
- **Row drill-in → asset-DNA drawer.** Selecting a steward opens a side drawer
  showing the **full device DNA** for that host (the early-development need for
  "view all asset DNA" before deeper asset screens exist), with a raw-values
  disclosure and export.
- **Ready / Loading (skeleton) / Error / Empty** states are all drawn; the
  mockup's `preview state` strip is a harness affordance for reviewing them and
  is not part of the product UI.

### 5.3 Troubleshooting cockpit — [`mockups/troubleshooting-cockpit.html`](mockups/troubleshooting-cockpit.html)

The differentiator described in §3–§4: the agentic case surface. This is the
primary working screen the fleet overview and login lead into.

---

## 6. Provenance — directions considered

Three interface directions were explored in-session before converging:

1. **Modern management dashboard** — competent but generic; rejected as not
   memorable ([`mockups/fleet-overview-generic-v0.html`](mockups/fleet-overview-generic-v0.html),
   pre-brand-alignment).
2. **Traditional RMM asset-browser** — easy asset browsing, but browsing is the
   motion waste we want to remove; retained only as a fast *finder*, not the
   primary surface.
3. **Agentic troubleshooting cockpit** — chosen. The differentiator, and where
   the Lean payoff is largest ([`mockups/troubleshooting-cockpit.html`](mockups/troubleshooting-cockpit.html)).

---

## 7. Open items

- [ ] **Converge the app identity with the public-site style guide.** The app
      currently *derives from* the published guide; at some point the two style
      guides should be reconciled into one source of truth. (Founder note,
      2026-07-03 — "good enough for now.")
- [ ] **Webfont delivery decision** — ship/subset Inter + JetBrains Mono vs.
      rely on the progressive platform-font fallback used in the mockups.
- [ ] **Remediation authority model** — how much can be one-click *Approve &
      run* at L1 vs. always routed through preview / second-eye.
- [ ] Translate the mockups into the React + TypeScript + Vite component library
      (the stack fixed for Epic #2344) with these tokens as the source of truth.

---

## 8. How to view the mockups

The mockups are self-contained HTML — open any file in [`mockups/`](mockups/)
directly in a browser. Each is wrapped in a small preview harness with a
**Desktop / Tablet / Mobile** viewport toggle; the cockpit, login, and
fleet-overview add an **Auto / Light / Dark** theme toggle, so both responsive
breakpoints and both themes can be reviewed from a single file — including from
a phone.
