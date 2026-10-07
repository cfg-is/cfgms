// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TypeScript types for the Case REST API (Story #3608).
 *
 * These mirror the JSON response shapes from handlers_cases.go (Issue #3605).
 * All fields are camelCase in TypeScript; the actual JSON uses snake_case.
 * The type shapes here are consumed read-only — they must match the Go handler
 * response types exactly. A schema change in handlers_cases.go must be reflected
 * here or the UI silently shows stale/empty data.
 *
 * TicketFieldSource values: email | caller-id | psa | operator | inferred
 * CaseStatus values: open | closed
 * ContentKind values: finding | transcript-entry | note
 */

import type { Pin } from './evidenceTypes.ts'

export interface TicketField {
  value: string
  source: string
  filled: boolean
}

export interface Ticket {
  title: TicketField
  client: TicketField
  contact: TicketField
  priority: TicketField
  category: TicketField
}

export interface ContentEntry {
  id: string
  case_id: string
  kind: string
  body: string
  author: string
  created_at: string
}

export interface Case {
  id: string
  tenant_id: string
  status: string
  ticket: Ticket
  pins: Pin[]
  content: ContentEntry[]
  created_at: string
  updated_at: string
}
