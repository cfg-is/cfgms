// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Elevation banner (Issue #4725, Epic #4701) — docs/design/mockups/tenant-admin.html
 * `.bgbanner`. Rendered at the top of the authenticated shell while the active
 * crossings feed lists at least one crossing the signed-in principal may see.
 *
 * Root operator: a break-glass is active; the tenant is named only when the
 * server supplied a name (an MSP visible to root — a client tenant arrives with
 * an empty name and is never named, nor is its ID shown); live countdown, reason
 * category and an End action for the principal's own break-glass.
 * MSP administrator: CFGMS support access is active; who holds it (principal name
 * for a break-glass, "All root support" for a grant), reason category, expiry and
 * a link to the Support access page.
 *
 * The countdown derives from the server `expires_at` and ticks locally each
 * second; the shell's 30-second poll reconciles it. Every server string renders
 * as a JSX text node.
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { breakGlassReasons, endCrossing, type ActiveCrossing } from '../tenants/useTenantCrossings.ts'
import './ElevationBanner.css'

const kindBreakGlass = 'break_glass'

function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const mmss = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  return h > 0 ? `${String(h).padStart(2, '0')}:${mmss}` : mmss
}

function reasonLabel(category: string): string {
  const hit = breakGlassReasons.find((r) => r.value === category)
  return hit !== undefined ? hit.label : category
}

function useNow(): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  return now
}

function holder(c: ActiveCrossing): string {
  if (c.kind !== kindBreakGlass) return 'All root support'
  return c.principalName !== '' ? c.principalName : 'CFGMS support'
}

function Row({
  crossing,
  nowMs,
  root,
  onEnd,
  ending,
  error,
}: {
  crossing: ActiveCrossing
  nowMs: number
  root: boolean
  onEnd: (c: ActiveCrossing) => void
  ending: boolean
  error: string | null
}) {
  const isBreakGlass = crossing.kind === kindBreakGlass
  const remaining = Date.parse(crossing.expiresAt) - nowMs
  const countdown = formatCountdown(Number.isFinite(remaining) ? remaining : 0)
  const reason = isBreakGlass && crossing.reasonCategory !== '' ? reasonLabel(crossing.reasonCategory) : ''

  return (
    <div className="elevbanner-row" data-testid="elevation-row" data-kind={crossing.kind}>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path
          d="M12 4l9 16H3L12 4zM12 10v4M12 17v.5"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="elevbanner-text">
        {root ? (
          <>
            <b>Break-glass access active</b>
            {crossing.tenantName !== '' && (
              <>
                {' — '}
                <span data-testid="elevation-tenant">{crossing.tenantName}</span>
              </>
            )}
          </>
        ) : (
          <>
            <b>CFGMS support access active</b>
            {crossing.tenantName !== '' && (
              <>
                {' on '}
                <span data-testid="elevation-tenant">{crossing.tenantName}</span>
              </>
            )}
            {' — held by '}
            <span data-testid="elevation-holder">{holder(crossing)}</span>
          </>
        )}
        {reason !== '' && (
          <>
            {' · reason: '}
            <span data-testid="elevation-reason">{reason}</span>
          </>
        )}
      </span>
      <span className="elevbanner-timer">
        expires in <span data-testid="elevation-countdown">{countdown}</span>
      </span>
      {!root && (
        <Link to="/support-access" className="elevbanner-link">
          Support access
        </Link>
      )}
      {root && isBreakGlass && (
        <button
          type="button"
          className="elevbanner-end"
          disabled={ending}
          onClick={() => onEnd(crossing)}
          data-testid="elevation-end-btn"
        >
          {ending ? 'Ending…' : 'End session'}
        </button>
      )}
      {error !== null && (
        <div className="elevbanner-error" role="alert" data-testid="elevation-error">
          {error}
        </div>
      )}
    </div>
  )
}

export interface ElevationBannerProps {
  crossings: ActiveCrossing[]
  /** True for a root-scoped operator; false for an MSP administrator. */
  root: boolean
  /** Refetch the feed (after an End). */
  onChanged: () => void
}

export default function ElevationBanner({ crossings, root, onChanged }: ElevationBannerProps) {
  const nowMs = useNow()
  const [endingId, setEndingId] = useState<string | null>(null)
  const [errors, setErrors] = useState<Record<string, string>>({})

  if (crossings.length === 0) return null

  async function handleEnd(c: ActiveCrossing) {
    setEndingId(c.id)
    setErrors((prev) => {
      const next = { ...prev }
      delete next[c.id]
      return next
    })
    try {
      await endCrossing(c.tenantId, c.id)
      onChanged()
    } catch (cause: unknown) {
      const message = cause instanceof Error && cause.message ? cause.message : 'End session failed'
      setErrors((prev) => ({ ...prev, [c.id]: message }))
    } finally {
      setEndingId(null)
    }
  }

  return (
    <div
      className={`elevbanner${crossings.length > 1 ? ' compact' : ''}`}
      role="status"
      data-testid="elevation-banner"
    >
      {crossings.map((c) => (
        <Row
          key={c.id}
          crossing={c}
          nowMs={nowMs}
          root={root}
          onEnd={(x) => void handleEnd(x)}
          ending={endingId === c.id}
          error={errors[c.id] ?? null}
        />
      ))}
    </div>
  )
}
