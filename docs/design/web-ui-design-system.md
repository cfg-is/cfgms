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
- **Terminal panel** (Story #2762, mockup [`mockups/asset-shell.html`](mockups/asset-shell.html)) —
  the Shell tab in the asset-page tab frame renders an interactive remote shell
  with `@xterm/xterm` + `FitAddon`, sized to its container via `ResizeObserver`.
  Chrome around the terminal matches the mockup: a connection-status pill
  (Connected / Connecting / Disconnected / Denied using the same state-pill
  semantics as §4's other pills), session meta, and a Clear / Copy / Disconnect
  header. Non-happy states are first-class, not fallback text — **Disconnected**
  offers Reconnect, **Denied** explains the RBAC rejection. Warm-terminal tokens
  (light-mode only today; dark-mode xterm theming is an open item, tracked
  alongside the other §7 items) come from `web-ui-design-tokens.css`, not a
  separate xterm theme file.
- **Sortable data table** (Story #2766; convention established in `FleetTable.tsx`) —
  click any `<th>` to sort by that column; a second click on the same header reverses
  direction. Sort state is `{ key: string; direction: 1 | -1 }` (from `FleetTable.tsx`)
  where `direction=1` is ascending and `direction=-1` is descending. The active column
  carries `aria-sort="ascending"|"descending"` on the `<th>` (no attribute when inactive)
  and a `sort` CSS class. All sort interactions remain client-side — no re-fetch on sort.
- **Data visualization** — a computed, validated layer for chart marks, stat tiles,
  and palettes. The values below were measured (OKLCH lightness band, chroma floor,
  Machado–Oliveira–Fernandes 2009 CVD separation, normal-vision floor, WCAG contrast)
  and must be shipped verbatim; do not substitute hand-picked hexes. Ship the values
  in `web-ui-design-tokens.css` as `--ordinal-*` and `--cat-*` custom properties.

  **The finding that shapes everything.** The six shipped state/accent tokens
  (`#4a6b7c`, `#507055`, `#8f4f2e`, `#965044`, `#7a5f6e`, `#6b5c4d`) fail as a
  categorical series palette — measured, light mode: chroma floor FAIL (all six below
  the 0.10 floor, 0.030–0.098); CVD separation FAIL (worst adjacent pair `--state-crit`
  ↔ `--state-warn` ΔE 2.5 deutan); normal-vision floor FAIL (same pair ΔE 3.1 —
  full-colour readers cannot reliably tell drift-orange from error-terracotta apart
  either). This is a property of the warm-terminal identity (deliberately desaturated
  earth tones), not a tokens defect. The resolution is a *separate data layer*: chart
  marks get their own validated palette, held to low chroma so it still reads as CFGMS.

  **Hard rules — no exceptions:**

  - **Warn/crit never adjacent by colour alone.** `--state-warn` and `--state-crit`
    must never be adjacent segments distinguished by colour alone — not in a stacked
    bar, not in a donut, not in a legend. Where both appear they carry an icon + text
    label and a 2 px surface gap. At ΔE 3.1 the two states are visually the same
    colour to most readers.
  - **Ignore server-supplied colours.** `ChartData.Config.Colors` and
    `SeriesData.Color` (`features/reports/interfaces/interfaces.go:143,165`) come off
    the wire and must not be used by the client. Map by series index into the palettes
    below instead.
  - **No dual-axis charts.** Two measures of different scale → two charts, small
    multiples, or index to a common base.
  - **Colour follows the entity, not its rank.** A filter that changes series count
    must not repaint survivors.
  - **Never colour nominal bars by their value.**
  - **Text never wears the data colour.** Values, labels, legends, and axis text use
    `--text-primary` / `--text-secondary` / `--text-faint`; identity comes from a
    coloured mark beside the text. Exception: a label inside a filled segment picks
    white or ink by the fill's luminance.

  **Colour-job table** — which chart job gets which treatment:

  | Job | Treatment |
  |-----|-----------|
  | A single current value | Stat tile — never a one-bar chart |
  | Magnitude low→high | Sequential ramp (below) |
  | Trend over time, one series | Sequential mid-step (3 or 4) or accent |
  | Categories *are states* (converged/drift/error/queued) | Status tokens + icon + label mandatory, never "series N" |
  | Distinct non-state series (tenants, rings, OS families) | Categorical (below), capped |
  | One series is the point | Accent for it, `--text-faint` for the rest |

  Categorical is the exception in this product. Default to sequential / status /
  emphasis.

  **Sequential ramp** (`--ordinal-*`, magnitude, the default) — one hue, accent slate
  (OKLCH H≈234), light→dark, 5 steps. Validated: lightness monotone, adjacent ΔL ≥0.06,
  light-end contrast 2.05:1 light / 2.07:1 dark (floor 2.0), single hue (spread 1°) —
  all PASS. Use for compliance/coverage magnitude, drift-event counts, heatmap cells,
  meter fills.

  | Step | Light | Dark |
  |------|-------|------|
  | 1 (lowest) | `#96bad0` | `#095b7e` |
  | 2 | `#659dbd` | `#0475a1` |
  | 3 | `#2e80a9` | `#378eba` |
  | 4 | `#0a6388` | `#62a8ce` |
  | 5 (highest) | `#054561` | `#93c0da` |

  **Categorical theme** (`--cat-*`, identity, the exception) — fixed order, assigned in
  sequence, never cycled, brand-anchored (each slot on a shipped token's OKLCH hue
  family, held to the lowest chroma that clears the floor). Validated — all six checks
  PASS both modes: light adjacent CVD ΔE 18.5 / normal 19.7; light all-pairs slots 1–3
  CVD 18.5 / normal 19.7; dark adjacent CVD 8.2 / normal 18.4; dark all-pairs slots 1–3
  CVD 8.2 / normal 19.2.

  | Slot | Family | Light | Dark |
  |------|--------|-------|------|
  | 1 | slate | `#0171a3` | `#3674a5` |
  | 2 | green | `#4f9d60` | `#5ba269` |
  | 3 | amber | `#7e3e1b` | `#d57018` |
  | 4 | mauve | `#c27fb0` | `#a55e93` |

  **Series caps — load-bearing, not guidance:**
  - **4 max** for stacked/grouped bars and multi-line (adjacent pairlist).
  - **3 max** for any form where two marks can sit side by side — scatter, bubble,
    graph/node views, small multiples (all-pairs pairlist; slots 1–3 are the validated
    subset).
  - **There is no 5th slot.** Fold the tail into "Other", facet into small multiples,
    or switch form. Never generate another hue — a generated 5th is indistinguishable
    under CVD and voids every number above.

  **Status scale** (reserved) — the shipped state tokens (`--state-ok` converged,
  `--state-warn` drift, `--state-crit` error, `--state-neutral` queued/inert) are used
  *only* for state, never as "series 4." Always icon + text label, per the hard rule
  above.

  **Stat tile** (formalizes `fleet-overview.html:149–151`'s `.tiles` / `.tile` / `.n`
  / `.sw` shipped CSS — **Reference** status per `mockups/README.md`):

  - `label` — sentence case, no trailing colon.
  - `value` — Inter semibold, `font-variant-numeric: tabular-nums`; auto-compact
    display (1,284 / 12.9 K).
  - `delta` — optional; signed, vs. a named period; colour = direction × whether up
    is good.
  - `trend` — optional; 12-point sparkline. Mark spec: see "Chart marks &
    interaction" below (Story #3269).

  Tiles use existing `--state-*` tokens only. No new tokens are introduced for the
  tile itself.

- **Chart marks & interaction** (Story #3269 — decided, not a founder taste call):

  **Mark specs — fixed across every CFGMS chart:**

  | Mark | Spec |
  |---|---|
  | Bar / column | ≤24px thick; 4px rounded data-end, square at the baseline; single baseline |
  | Line | 2px, `stroke-linecap: round`, `stroke-linejoin: round` |
  | Marker / end-dot | ≥8px (r≥4), filled with the series colour |
  | Area fill | series hue at ~10% opacity — a wash, never a saturated block |
  | Gridlines / axes | `--border`, hairline 1px solid (never dashed), recessive |

  **Two spacers — white does the separating, never a stroke:** a 2px gap in the
  surface colour between touching marks (every stacked-bar segment, every adjacent
  bar); a 2px ring in the surface colour around dots/end-markers so they stay
  legible crossing a line (the ring is part of the hover target). Never draw a
  border around a mark to separate it.

  **Sparkline mark:** 2px line, `--text-faint` for history with the current period
  end marked in `--accent`; end marker ≥8px (r≥4) with the 2px surface ring;
  optional ~10% area wash; no axis, no gridlines, no per-point labels — the tile's
  value is the label.

  **Hero figure:** the one number a view leads with, ≥48px, in Inter (never the
  display/terminal face) — exactly one per view.

  **Labels, legend, interaction:**
  - Legend always present for ≥2 series; a single series needs no legend box (the
    title names it).
  - Label selectively (endpoint, extreme, or the one series the story is about) —
    never a value on every point.
  - A label that won't fit is never clipped (`overflow: hidden` on a segment is
    banned) — move it outside or drop to tooltip.
  - Hover is default (crosshair+tooltip on line/area, per-mark tooltip on
    bar/dot/cell, hit targets larger than the mark) except a bare stat tile with
    no plot.
  - Filters in one row above the charts; time-range control shared across a view.
  - Every chart has a table view — identity is never colour-alone, and the table
    is what makes a sub-3:1 fill or a skipped label legal.

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
