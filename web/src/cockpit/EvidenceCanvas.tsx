// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Evidence Canvas (Story #3607) — the right-hand card grid of the troubleshooting
 * cockpit. Mounts every component found under ./cards/ via Vite's import.meta.glob
 * and renders each with the full pin list. A new card story drops a file into
 * cards/ and is picked up automatically — no edit to this file is ever required.
 *
 * Layout grid mirrors the .canvas section of
 * docs/design/mockups/troubleshooting-cockpit.html; spacing/colour tokens from
 * docs/design/web-ui-design-tokens.css.
 *
 * Empty state (pins=[]) is canvas-level: when no pins have been added to a case
 * the canvas shows "no pins yet" rather than delegating to individual cards, since
 * a card cannot meaningfully render evidence without a pin to anchor it. Once at
 * least one pin exists, each card receives the full list and decides for itself
 * whether it has relevant evidence to display.
 */
import type { ComponentType } from 'react'
import type { EvidenceCardProps, Pin } from './evidenceTypes.ts'
import './EvidenceCanvas.css'

interface EvidenceCanvasProps {
  pins: Pin[]
}

// Eager glob — resolved by Vite at transform time. Each value is a module with a
// default export that implements EvidenceCardProps. Cards drop a file here and are
// automatically included; no change to this file is ever needed.
//
// Colocated *.test.tsx files are excluded explicitly. A bare './cards/*.tsx' also
// matches './cards/DriftDiffCard.test.tsx', and an eager glob *imports* every match
// for its side effects — so a card story following this repo's colocated-test
// convention would pull its test module (and its vitest / @testing-library imports)
// into the application graph and the production bundle. The `!` pattern keeps the
// seam to card components only.
const cardModules = import.meta.glob(['./cards/*.tsx', '!./cards/*.test.tsx'], {
  eager: true,
}) as Record<string, { default: ComponentType<EvidenceCardProps> }>

// Stable array of (path, Card) pairs for keyed rendering.
const cardEntries = Object.entries(cardModules)
  .filter(([, m]) => Boolean(m.default))
  .map(([path, m]) => ({ path, Card: m.default as ComponentType<EvidenceCardProps> }))

/**
 * Every module path the discovery glob actually imported — the raw glob keys, not
 * the renderable subset. Exported so the seam is assertable at the point where it
 * can go wrong: a test module swept in by too broad a pattern is dropped from
 * `cardEntries` by the `default` filter above and so never renders, but it has
 * still been imported for its side effects by then. Only the glob keys show that.
 */
export const importedCardModulePaths: string[] = Object.keys(cardModules)

export default function EvidenceCanvas({ pins }: EvidenceCanvasProps) {
  if (pins.length === 0) {
    return (
      <div className="evidence-canvas evidence-canvas--empty">
        <p className="evidence-canvas__empty-message">
          No pins yet — add a pin to surface evidence.
        </p>
      </div>
    )
  }

  return (
    <div className="evidence-canvas">
      {cardEntries.map(({ path, Card }) => (
        <Card key={path} pins={pins} />
      ))}
    </div>
  )
}
