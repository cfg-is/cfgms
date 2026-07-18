// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  STALE_AFTER_MS,
  deriveHealth,
  fetchFleetHealth,
  formatLastSeen,
  parseLastSeen,
} from './health.ts'

const NOW = Date.UTC(2026, 6, 15, 12, 0, 0)
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString()

describe('deriveHealth', () => {
  it('maps a fresh active steward to Healthy/ok', () => {
    expect(deriveHealth('active', iso(30_000), NOW)).toEqual({
      label: 'Healthy',
      tone: 'ok',
    })
  })

  it('maps an active steward with a stale heartbeat to Unreachable/crit', () => {
    expect(deriveHealth('active', iso(STALE_AFTER_MS + 60_000), NOW)).toEqual({
      label: 'Unreachable',
      tone: 'crit',
    })
  })

  it('treats exactly-at-threshold as still fresh, one ms past as stale', () => {
    expect(deriveHealth('active', iso(STALE_AFTER_MS), NOW).tone).toBe('ok')
    expect(deriveHealth('active', iso(STALE_AFTER_MS + 1), NOW).tone).toBe('crit')
  })

  it('maps an active steward that has never checked in to Unreachable', () => {
    expect(deriveHealth('active', '0001-01-01T00:00:00Z', NOW).tone).toBe('crit')
    expect(deriveHealth('active', undefined, NOW).tone).toBe('crit')
  })

  it('maps lifecycle states independently of staleness', () => {
    expect(deriveHealth('degraded', iso(0), NOW)).toEqual({
      label: 'Degraded',
      tone: 'warn',
    })
    expect(deriveHealth('lost', iso(0), NOW).label).toBe('Unreachable')
    expect(deriveHealth('offline', iso(0), NOW).tone).toBe('crit')
    expect(deriveHealth('revoked', iso(0), NOW).tone).toBe('crit')
    expect(deriveHealth('registered', undefined, NOW)).toEqual({
      label: 'Registered',
      tone: 'neutral',
    })
    expect(deriveHealth('dormant', iso(0), NOW).tone).toBe('neutral')
    expect(deriveHealth('archived', iso(0), NOW).tone).toBe('neutral')
  })

  it('is case-insensitive on status', () => {
    expect(deriveHealth('Active', iso(0), NOW).label).toBe('Healthy')
    expect(deriveHealth('ONLINE', iso(0), NOW).label).toBe('Healthy')
  })

  it('renders unknown statuses as neutral with the raw label', () => {
    expect(deriveHealth('quarantined', iso(0), NOW)).toEqual({
      label: 'quarantined',
      tone: 'neutral',
    })
    expect(deriveHealth(undefined, iso(0), NOW)).toEqual({
      label: 'Unknown',
      tone: 'neutral',
    })
  })
})

describe('parseLastSeen', () => {
  it('rejects the Go zero time, garbage, and empty values as never-seen', () => {
    expect(parseLastSeen('0001-01-01T00:00:00Z')).toBeNull()
    expect(parseLastSeen('not-a-date')).toBeNull()
    expect(parseLastSeen(undefined)).toBeNull()
    expect(parseLastSeen('')).toBeNull()
  })

  it('parses a real timestamp', () => {
    expect(parseLastSeen(new Date(NOW).toISOString())).toBe(NOW)
  })
})

describe('formatLastSeen', () => {
  it('renders an em-dash for never-seen', () => {
    expect(formatLastSeen('0001-01-01T00:00:00Z', NOW)).toBe('—')
    expect(formatLastSeen(undefined, NOW)).toBe('—')
  })

  it('buckets seconds, minutes, hours, and days', () => {
    expect(formatLastSeen(iso(12_000), NOW)).toBe('12s ago')
    expect(formatLastSeen(iso(3 * 60_000), NOW)).toBe('3m ago')
    expect(formatLastSeen(iso(5 * 3_600_000), NOW)).toBe('5h ago')
    expect(formatLastSeen(iso(2 * 86_400_000), NOW)).toBe('2d ago')
  })

  it('clamps clock skew (future last_seen) to 0s ago', () => {
    expect(formatLastSeen(iso(-30_000), NOW)).toBe('0s ago')
  })
})

// ── fetchFleetHealth (Issue #2729) ────────────────────────────────────────────

const fetchMock = vi.fn<typeof fetch>()

describe('fetchFleetHealth', () => {
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    // stub document.cookie so apiFetch doesn't throw in the test environment
    vi.stubGlobal('document', { cookie: '' })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('returns healthy/degraded/unreachable counts from a valid response', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { healthy: 5, degraded: 2, unreachable: 1 } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    const result = await fetchFleetHealth()
    expect(result).toEqual({ healthy: 5, degraded: 2, unreachable: 1 })
  })

  it('returns zeros when all counts are zero', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { healthy: 0, degraded: 0, unreachable: 0 } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    const result = await fetchFleetHealth()
    expect(result).toEqual({ healthy: 0, degraded: 0, unreachable: 0 })
  })

  it('throws when the server returns a non-2xx status', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 503 }))
    await expect(fetchFleetHealth()).rejects.toThrow('GET /api/v1/fleet/health — 503')
  })

  it('throws when the response data shape is unexpected', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ data: { wrong: true } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    await expect(fetchFleetHealth()).rejects.toThrow('unexpected health response shape')
  })

  it('throws when data is missing entirely', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await expect(fetchFleetHealth()).rejects.toThrow('unexpected health response shape')
  })
})
