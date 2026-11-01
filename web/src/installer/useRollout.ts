// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useRollout (Issue #5452, Epic #5300) — ringed fleet rollout start, status
 * polling and halt for the Installer page.
 *
 *   POST /api/v1/rollout                    Strong + presence tap
 *   GET  /api/v1/rollout/{rollout_id}       status
 *   POST /api/v1/rollout/{rollout_id}/halt  Strong, tap-exempt
 *
 * apiFetch runs the step-up ceremony; a cancelled one comes back as the
 * original 401 and surfaces here as a worded message, with no second request.
 * Wire data passes through parse* validators before it reaches state.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export const ROLLOUT_POLL_MS = 3000

/** Mirrors business.RolloutStatusInProgress; any other status is final. */
export function isTerminalRolloutStatus(status: string): boolean {
  return status !== 'in-progress'
}

export interface RolloutStart {
  rolloutId: string
  status: string
}

export interface RolloutStatus {
  rolloutId: string
  targetVersion: string
  currentRing: string
  status: string
  onVersionPct: number
  failedCount: number
  pendingCount: number
  healthMetricsAvailable: boolean
  healthMetricsError: string
  ringsCompleted: number
  ringsTotal: number
  startedAt: string
  haltedAt: string
  error: string
}

function envelopeData(body: unknown): Record<string, unknown> | null {
  if (typeof body !== 'object' || body === null) return null
  const data = (body as Record<string, unknown>).data
  return typeof data === 'object' && data !== null ? (data as Record<string, unknown>) : null
}

export function parseRolloutStart(body: unknown): RolloutStart | null {
  const d = envelopeData(body)
  if (d === null || typeof d.rollout_id !== 'string' || d.rollout_id === '') return null
  return { rolloutId: d.rollout_id, status: typeof d.status === 'string' ? d.status : '' }
}

export function parseRolloutStatus(body: unknown): RolloutStatus | null {
  const d = envelopeData(body)
  if (d === null || typeof d.status !== 'string' || d.status === '') return null
  if (typeof d.rollout_id !== 'string' || d.rollout_id === '') return null
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
  return {
    rolloutId: d.rollout_id,
    targetVersion: str(d.target_version),
    currentRing: str(d.current_ring),
    status: d.status,
    onVersionPct: num(d.on_version_pct),
    failedCount: num(d.failed_count),
    pendingCount: num(d.pending_count),
    // Strictly true only: anything else means the counts are unknown.
    healthMetricsAvailable: d.health_metrics_available === true,
    healthMetricsError: str(d.health_metrics_error),
    ringsCompleted: num(d.rings_completed),
    ringsTotal: num(d.rings_total),
    startedAt: str(d.started_at),
    haltedAt: str(d.halted_at),
    error: str(d.error),
  }
}

async function failure(response: Response, fallback: string): Promise<string> {
  if (response.status === 401) return 'The passkey check was cancelled — nothing was sent.'
  try {
    const body: unknown = await response.json()
    const err = (body as { error?: { message?: unknown } | unknown } | null)?.error
    const message = typeof err === 'object' && err !== null ? (err as { message?: unknown }).message : err
    if (typeof message === 'string' && message !== '') return `${fallback} — ${message}`
  } catch {
    // fall through to the status-only message
  }
  return `${fallback} — ${response.status}`
}

export interface UseRollout {
  start: RolloutStart | null
  status: RolloutStatus | null
  busy: boolean
  error: string | null
  haltNote: string | null
  pollError: string | null
  startRollout: (params: { targetVersion: string; tenantId: string }) => Promise<void>
  halt: () => Promise<void>
}

export function useRollout(): UseRollout {
  const [start, setStart] = useState<RolloutStart | null>(null)
  const [status, setStatus] = useState<RolloutStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [haltNote, setHaltNote] = useState<string | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  const rolloutId = start?.rolloutId ?? null

  useEffect(() => {
    if (rolloutId === null) return
    let cancelled = false
    let timer: ReturnType<typeof setInterval> | null = null
    const stop = () => {
      if (timer !== null) clearInterval(timer)
      timer = null
    }
    const poll = async () => {
      try {
        const response = await apiFetch(`/api/v1/rollout/${encodeURIComponent(rolloutId)}`)
        if (!response.ok) throw new Error(`status ${response.status}`)
        const parsed = parseRolloutStatus(await response.json())
        if (cancelled) return
        if (parsed === null) throw new Error('unexpected response shape')
        setPollError(null)
        setStatus(parsed)
        if (isTerminalRolloutStatus(parsed.status)) stop()
      } catch {
        if (!cancelled) setPollError('Could not read the rollout status — retrying.')
      }
    }
    void poll()
    timer = setInterval(() => void poll(), ROLLOUT_POLL_MS)
    return () => {
      cancelled = true
      stop()
    }
  }, [rolloutId])

  const startRollout = useCallback(async (params: { targetVersion: string; tenantId: string }) => {
    setBusy(true)
    setError(null)
    setHaltNote(null)
    try {
      const response = await apiFetch('/api/v1/rollout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_version: params.targetVersion, tenant_id: params.tenantId }),
      })
      if (!response.ok) {
        setError(await failure(response, 'Rollout start failed'))
        return
      }
      const parsed = parseRolloutStart(await response.json())
      if (parsed === null) {
        setError('Rollout start failed — unexpected response')
        return
      }
      setStatus(null)
      setPollError(null)
      setStart(parsed)
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Rollout start failed')
    } finally {
      setBusy(false)
    }
  }, [])

  const halt = useCallback(async () => {
    if (rolloutId === null) return
    setBusy(true)
    setError(null)
    setHaltNote(null)
    try {
      const response = await apiFetch(`/api/v1/rollout/${encodeURIComponent(rolloutId)}/halt`, {
        method: 'POST',
      })
      if (!response.ok) {
        setError(await failure(response, 'Halt failed'))
        return
      }
      setHaltNote('Halt sent.')
      // Show the halted state straight away rather than waiting for a poll.
      const refreshed = await apiFetch(`/api/v1/rollout/${encodeURIComponent(rolloutId)}`)
      if (refreshed.ok) {
        const parsed = parseRolloutStatus(await refreshed.json())
        if (parsed !== null) setStatus(parsed)
      }
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Halt failed')
    } finally {
      setBusy(false)
    }
  }, [rolloutId])

  return { start, status, busy, error, haltNote, pollError, startRollout, halt }
}
