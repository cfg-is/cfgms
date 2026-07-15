// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Health derivation for the fleet view (Story #2497).
 *
 * The API payload carries a lifecycle `status` (business.StewardStatus:
 * registered/active/lost/dormant/archived/revoked — plus online/offline on
 * the filtered fleet-query path) and a `last_seen` heartbeat timestamp. The
 * Health column folds both into one signal: an "active" steward whose
 * heartbeat has gone stale is presented as Unreachable, because a healthy
 * label next to a 20-minute-old check-in would be a lie.
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
 * Unreachable. The payload pins no heartbeat contract, so this is a display
 * threshold, not protocol truth; 5 minutes matches the reference mockup's
 * semantics (a 6-minute-old check-in renders critical).
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
        : { label: 'Unreachable', tone: 'crit' }
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
