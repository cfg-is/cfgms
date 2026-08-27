// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Fixture card — test infrastructure for Story #3607 (EvidenceCanvas auto-discovery seam).
 *
 * This file exists to prove that dropping a file into cards/ auto-registers it with
 * EvidenceCanvas without any change to EvidenceCanvas.tsx. It renders a data-testid
 * element that the EvidenceCanvas test uses to assert the glob discovery mechanism
 * works. It has no evidence card content of its own — real evidence cards are
 * Stories 8–11.
 *
 * Never add business logic here. If this file is still present when Story 8+ cards
 * exist, it can be removed once the test coverage it provides is superseded.
 */
import type { EvidenceCardProps } from '../evidenceTypes.ts'

export default function FixtureCard({ pins }: EvidenceCardProps) {
  // Render nothing in production — this fixture exists only to verify the
  // glob-based self-registration seam during development and tests.
  if (!import.meta.env.DEV) return null
  return <div data-testid="evidence-fixture-card" data-pin-count={pins.length} />
}
