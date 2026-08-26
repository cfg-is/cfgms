// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Shared TypeScript contract for the Evidence Canvas and its cards (Story #3607).
 *
 * Pin and PinRef mirror the JSON shape returned by GET /api/v1/cases/{id}'s
 * embedded pin array (Story #3605 — pinResponse/pinRefResponse in
 * features/controller/api/handlers_cases.go). Fixture pins for tests must be
 * drawn from that source so a shape change in Story 4 is easy to cross-reference.
 *
 * PinRefKind covers all five discriminant values from Story 1's Pin.Ref shape and
 * ADR-022 §8: eid, edge-identity, observation-version, drift-record, subject-time-range.
 */

/** All five PinRef discriminant values from ADR-022 §8 / Story 1 / Story 4. */
export type PinRefKind =
  | 'eid'
  | 'edge-identity'
  | 'observation-version'
  | 'drift-record'
  | 'subject-time-range'

/**
 * Discriminated graph reference. Only fields relevant to `kind` are populated;
 * others are absent or empty strings. Mirrors pinRefResponse in handlers_cases.go.
 */
export interface PinRef {
  kind: PinRefKind
  eid?: string
  edge_identity?: string
  observation_version?: string
  drift_record?: string
  subject?: string
  /** ISO 8601 timestamp string. Populated when kind === 'subject-time-range'. */
  time_range_start?: string
  /** ISO 8601 timestamp string. Populated when kind === 'subject-time-range'. */
  time_range_end?: string
}

/**
 * A single pin from GET /api/v1/cases/{id}. Mirrors pinResponse in
 * features/controller/api/handlers_cases.go (Issue #3605).
 */
export interface Pin {
  id: string
  case_id: string
  ref: PinRef
  annotation: string
  author: string
  /** ISO 8601 timestamp string. */
  pinned_at: string
}

/**
 * Props every Evidence Canvas card must accept (Story #3607 contract).
 * Cards receive the full case pin list and decide for themselves which pins
 * are relevant — the canvas does not pre-filter. A card that finds no relevant
 * pins should render its own "no evidence of this kind yet" state.
 */
export interface EvidenceCardProps {
  pins: Pin[]
}
