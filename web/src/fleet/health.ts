// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { apiFetch } from '../api/client.ts'

/*
 * Health derivation for the fleet view (Story #2497).
 *
 * The API payload carries a lifecycle `status` (business.StewardStatus:
 * registered/active/lost/dormant/archived/revoked — plus online/offline on
 * the filtered fleet-query path) and a `last_seen` heartbeat timestamp. The
 * Health column folds both into one signal using the same taxonomy as the
 * server-side handleFleetHealth aggregate (handlers_fleet.go):
 *   - active + fresh heartbeat  → Healthy (ok)
 *   - active + stale heartbeat  → Degraded (warn)
 *   - lost                      → Unreachable (crit)
 *
 * Colors carry meaning only (design-system pillar 2): each tone maps to a
 * semantic state token (--state-ok/-warn/-crit/-neutral), never a decorative
 * color.
 */

export type HealthTone = 'ok' | 'warn' | 'crit' | 'neutral'

export interface Health {
  label: string
  tone: HealthTone
}

/*
 * Heartbeat age beyond which an otherwise-active steward is presented as
 * Degraded. Must match DegradedHeartbeatAge in
 * features/controller/api/handlers_fleet.go (currently 5 minutes); drift
 * between these two constants re-introduces the tile/row disagreement fixed
 * in Issue #2920.
 */
export const STALE_AFTER_MS = 5 * 60_000

/*
 * Timestamps earlier than this are treated as "never seen". Go's zero
 * time.Time serializes as 0001-01-01T00:00:00Z (a registered-but-never-
 * connected steward), which must not render as "seen 700,000 days ago".
 */
const MIN_VALID_MS = Date.UTC(2000, 0, 1)

/** Parse a last-seen timestamp; null means never seen (or unparseable). */
export function parseLastSeen(lastSeen: string | undefined): number | null {
  if (!lastSeen) return null
  const ms = Date.parse(lastSeen)
  if (Number.isNaN(ms) || ms < MIN_VALID_MS) return null
  return ms
}

/** Fold lifecycle status + heartbeat staleness into the Health cell value. */
export function deriveHealth(
  status: string | undefined,
  lastSeen: string | undefined,
  nowMs: number,
): Health {
  const normalized = (status ?? '').trim().toLowerCase()
  switch (normalized) {
    case 'active':
    case 'online':
    case 'connected':
    case 'healthy': {
      const seen = parseLastSeen(lastSeen)
      const fresh = seen !== null && nowMs - seen <= STALE_AFTER_MS
      return fresh
        ? { label: 'Healthy', tone: 'ok' }
        : { label: 'Degraded', tone: 'warn' }
    }
    case 'degraded':
      return { label: 'Degraded', tone: 'warn' }
    case 'lost':
    case 'offline':
    case 'unhealthy':
      return { label: 'Unreachable', tone: 'crit' }
    case 'revoked':
      return { label: 'Revoked', tone: 'crit' }
    case 'registered':
      return { label: 'Registered', tone: 'neutral' }
    case 'dormant':
      return { label: 'Dormant', tone: 'neutral' }
    case 'archived':
      return { label: 'Archived', tone: 'neutral' }
    default:
      // Unknown lifecycle states render as inert text, never a guessed tone.
      return { label: status?.trim() ? status.trim() : 'Unknown', tone: 'neutral' }
  }
}

// ── Fleet health aggregate (Issue #2729) ─────────────────────────────────────

/**
 * Server-side fleet health aggregate returned by GET /api/v1/fleet/health.
 * Counts are tenant-scoped and classified by the same degradation rule as
 * DegradedHeartbeatAge on the controller (5 min stale heartbeat).
 * hidden is always present (non-suppressible): the operator must always see
 * that concealment is in effect (Issue #2918).
 */
export interface FleetHealth {
  healthy: number
  degraded: number
  unreachable: number
  hidden: number
}

/**
 * Fetch the fleet health aggregate from GET /api/v1/fleet/health.
 * Throws on non-2xx or an unrecognized response shape.
 */
export async function fetchFleetHealth(): Promise<FleetHealth> {
  const resp = await apiFetch('/api/v1/fleet/health')
  if (!resp.ok) {
    throw new Error(`GET /api/v1/fleet/health — ${resp.status}`)
  }
  const body: unknown = await resp.json()
  const d = (body as Record<string, unknown> | null)?.['data']
  const rec = d as Record<string, unknown> | null | undefined
  if (
    typeof rec?.['healthy'] !== 'number' ||
    typeof rec?.['degraded'] !== 'number' ||
    typeof rec?.['unreachable'] !== 'number'
  ) {
    throw new Error('unexpected health response shape')
  }
  return {
    healthy: rec['healthy'] as number,
    degraded: rec['degraded'] as number,
    unreachable: rec['unreachable'] as number,
    hidden: typeof rec?.['hidden'] === 'number' ? (rec['hidden'] as number) : 0,
  }
}

/** Relative check-in age for the Last check-in column; em-dash when never. */
export function formatLastSeen(
  lastSeen: string | undefined,
  nowMs: number,
): string {
  const seen = parseLastSeen(lastSeen)
  if (seen === null) return '—'
  const diff = Math.max(0, nowMs - seen)
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`
  return `${Math.floor(diff / 86_400_000)}d ago`
}
