// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useUpgrade (Issue #5445, Epic #5300) — steward upgrade dispatch, status
 * polling and rollback for the Installer page.
 *
 *   POST /api/v1/stewards/upgrade                       Strong + presence tap
 *   GET  /api/v1/stewards/upgrade/{upgrade_id}          installer:read
 *   POST /api/v1/stewards/upgrade/{upgrade_id}/rollback Strong, tap-exempt
 *
 * apiFetch runs the step-up ceremony; a cancelled one comes back as the
 * original 401 and surfaces here as a worded message, with no second request.
 * Wire data passes through parse* validators before it reaches state.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

export const UPGRADE_POLL_MS = 3000

export const PLATFORMS = ['windows', 'darwin', 'linux'] as const
export const ARCHES = ['amd64', 'arm64'] as const

const TERMINAL = new Set(['committed', 'rolled_back', 'failed'])

/** Mirrors isTerminalUpgradeStatus in handlers_upgrade.go. */
export function isTerminalUpgradeStatus(status: string): boolean {
  return TERMINAL.has(status)
}

export interface UpgradeDispatch {
  upgradeId: string
  stewardCount: number
  status: string
}

export interface UpgradeRecord {
  id: string
  stewardId: string
  version: string
  platform: string
  arch: string
  status: string
  errorMessage: string
}

export interface DispatchParams {
  selector: string
  version: string
  platform: string
  arch: string
}

function envelopeData(body: unknown): Record<string, unknown> | null {
  if (typeof body !== 'object' || body === null) return null
  const data = (body as Record<string, unknown>).data
  return typeof data === 'object' && data !== null ? (data as Record<string, unknown>) : null
}

export function parseUpgradeDispatch(body: unknown): UpgradeDispatch | null {
  const d = envelopeData(body)
  if (d === null || typeof d.upgrade_id !== 'string' || d.upgrade_id === '') return null
  return {
    upgradeId: d.upgrade_id,
    stewardCount: typeof d.steward_count === 'number' ? d.steward_count : 0,
    status: typeof d.status === 'string' ? d.status : '',
  }
}

// The controller serialises the stored record with its Go field names.
export function parseUpgradeRecord(body: unknown): UpgradeRecord | null {
  const d = envelopeData(body)
  if (d === null || typeof d.Status !== 'string' || d.Status === '') return null
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  return {
    id: str(d.ID),
    stewardId: str(d.StewardID),
    version: str(d.Version),
    platform: str(d.Platform),
    arch: str(d.Arch),
    status: d.Status,
    errorMessage: str(d.ErrorMessage),
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

export interface UseUpgrade {
  dispatch: UpgradeDispatch | null
  record: UpgradeRecord | null
  busy: boolean
  error: string | null
  rollbackNote: string | null
  pollError: string | null
  startUpgrade: (params: DispatchParams) => Promise<void>
  rollback: (version: string) => Promise<void>
}

export function useUpgrade(): UseUpgrade {
  const [dispatch, setDispatch] = useState<UpgradeDispatch | null>(null)
  const [record, setRecord] = useState<UpgradeRecord | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [rollbackNote, setRollbackNote] = useState<string | null>(null)
  const [pollError, setPollError] = useState<string | null>(null)
  // Bumped by a rollback so polling restarts after a terminal state.
  const [pollEpoch, setPollEpoch] = useState(0)
  const upgradeId = dispatch?.upgradeId ?? null

  useEffect(() => {
    if (upgradeId === null) return
    let cancelled = false
    let timer: ReturnType<typeof setInterval> | null = null
    const stop = () => {
      if (timer !== null) clearInterval(timer)
      timer = null
    }
    const poll = async () => {
      try {
        const response = await apiFetch(`/api/v1/stewards/upgrade/${encodeURIComponent(upgradeId)}`)
        if (!response.ok) throw new Error(`status ${response.status}`)
        const parsed = parseUpgradeRecord(await response.json())
        if (cancelled) return
        if (parsed === null) throw new Error('unexpected response shape')
        setPollError(null)
        setRecord(parsed)
        if (isTerminalUpgradeStatus(parsed.status)) {
          stop()
        }
      } catch {
        if (!cancelled) setPollError('Could not read the upgrade status — retrying.')
      }
    }
    void poll()
    timer = setInterval(() => void poll(), UPGRADE_POLL_MS)
    return () => {
      cancelled = true
      stop()
    }
  }, [upgradeId, pollEpoch])

  const startUpgrade = useCallback(async (params: DispatchParams) => {
    setBusy(true)
    setError(null)
    setRollbackNote(null)
    try {
      const response = await apiFetch('/api/v1/stewards/upgrade', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      })
      if (!response.ok) {
        setError(await failure(response, 'Upgrade dispatch failed'))
        return
      }
      const parsed = parseUpgradeDispatch(await response.json())
      if (parsed === null) {
        setError('Upgrade dispatch failed — unexpected response')
        return
      }
      setRecord(null)
      setPollError(null)
      setDispatch(parsed)
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'Upgrade dispatch failed')
    } finally {
      setBusy(false)
    }
  }, [])

  const rollback = useCallback(
    async (version: string) => {
      if (upgradeId === null) return
      setBusy(true)
      setError(null)
      setRollbackNote(null)
      try {
        const response = await apiFetch(
          `/api/v1/stewards/upgrade/${encodeURIComponent(upgradeId)}/rollback`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ version }),
          },
        )
        if (!response.ok) {
          setError(await failure(response, 'Rollback failed'))
          return
        }
        setRollbackNote(`Rollback to ${version} sent.`)
        setPollEpoch((n) => n + 1)
      } catch (cause: unknown) {
        setError(cause instanceof Error && cause.message ? cause.message : 'Rollback failed')
      } finally {
        setBusy(false)
      }
    },
    [upgradeId],
  )

  return { dispatch, record, busy, error, rollbackNote, pollError, startUpgrade, rollback }
}
