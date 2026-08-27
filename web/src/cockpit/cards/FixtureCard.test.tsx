// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Colocated test for FixtureCard (Story #3607).
 *
 * Deliberately colocated inside cards/, matching the convention used elsewhere in
 * this feature (EvidenceCanvas.test.tsx sits beside EvidenceCanvas.tsx). Stories 8
 * through 11 are expected to follow it, so cards/ will hold *.test.tsx files next
 * to card components.
 *
 * That makes this file the canary for EvidenceCanvas's discovery glob: it is the
 * only *.test.tsx in cards/, so the `discoveredCardPaths` exclusion assertion in
 * EvidenceCanvas.test.tsx has something real to exclude. If that glob ever widens
 * back to a bare './cards/*.tsx', this module gets eagerly imported into the
 * application graph and that assertion fails.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import FixtureCard from './FixtureCard.tsx'

describe('FixtureCard', () => {
  it('renders the seam marker carrying the pin count it was handed', () => {
    render(<FixtureCard pins={[]} />)
    const card = screen.getByTestId('evidence-fixture-card')
    expect(card).toBeInTheDocument()
    expect(card).toHaveAttribute('data-pin-count', '0')
  })
})
