// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Active break-glass banner (Issue #4588, ADR-025 Decision 2(b)).
 *
 * Shows the target, the reason and a live countdown to the server-supplied
 * `expires_at`. Reaching zero asks the parent to refetch instead of trusting the
 * client clock to end access; End session issues the DELETE (step-up via apiFetch).
 */
import { useEffect, useRef, useState } from 'react'
import { endCrossing, type BannerEntry } from './useTenantCrossings.ts'

function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000))
  const m = Math.floor(total / 60)
  const sec = total % 60
  return `${m}:${String(sec).padStart(2, '0')}`
}

export default function CrossingBanner({
  entry,
  onEnded,
  onExpired,
}: {
  entry: BannerEntry
  onEnded: () => void
  onExpired: () => void
}) {
  const expiresMs = Date.parse(entry.expiresAt)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [ending, setEnding] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const firedFor = useRef<string | null>(null)

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  const remaining = Number.isFinite(expiresMs) ? expiresMs - nowMs : 0
  const expired = remaining <= 0
  const fireKey = `${entry.crossingId}:${entry.expiresAt}`

  useEffect(() => {
    if (!expired || firedFor.current === fireKey) return
    firedFor.current = fireKey
    onExpired()
  }, [expired, fireKey, onExpired])

  async function handleEnd() {
    setEnding(true)
    setError(null)
    try {
      await endCrossing(entry.tenantId, entry.crossingId)
      onEnded()
    } catch (cause: unknown) {
      setError(cause instanceof Error && cause.message ? cause.message : 'End session failed')
      setEnding(false)
    }
  }

  return (
    <div className="notice err" role="status" data-testid="crossing-banner">
      <div className="ic">⚠</div>
      <h3>
        Break-glass session active on <span data-testid="crossing-banner-target">{entry.tenantId}</span>
      </h3>
      <p>
        Reason: <span data-testid="crossing-banner-reason">{entry.reason || '—'}</span>
      </p>
      <p>
        Expires in <b data-testid="crossing-banner-countdown">{formatCountdown(remaining)}</b>
      </p>
      {error && (
        <div className="wf-form-error" role="alert" data-testid="crossing-banner-error">
          {error}
        </div>
      )}
      <button
        type="button"
        className="wf-btn-danger"
        disabled={ending}
        onClick={() => void handleEnd()}
        data-testid="crossing-end-btn"
      >
        {ending ? 'Ending…' : 'End session'}
      </button>
    </div>
  )
}
