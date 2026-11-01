// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Controller status chip (Story #4596) — mockups/fleet-overview.html
 * `.cfoot` chip + `#pop-ctrl` popover. Shows controller health (dot + text,
 * never colour alone) and version from GET /api/v1/health, polled every 30s
 * and paused while the tab is hidden. The popover's endpoint is the browser's
 * own origin; no internal addresses are exposed.
 */
import { useEffect, useRef, useState } from 'react'
import { unwrapEnvelope } from '../api/client.ts'

const POLL_INTERVAL_MS = 30_000

type ChipState =
  | { kind: 'loading' }
  | { kind: 'healthy' | 'degraded'; version: string }
  | { kind: 'unreachable' }

interface HealthBody {
  status?: unknown
  version?: unknown
}

async function fetchHealth(signal: AbortSignal): Promise<ChipState> {
  try {
    // Health is unauthenticated; a plain fetch keeps a 401/503 from touching
    // the session-expiry listeners. Degraded controllers answer 503 with a body.
    const response = await fetch('/api/v1/health', { signal, credentials: 'same-origin' })
    const body = unwrapEnvelope<HealthBody>(await response.json())
    if (body.status !== 'healthy' && body.status !== 'degraded') {
      return { kind: 'unreachable' }
    }
    const version = typeof body.version === 'string' ? body.version : ''
    return { kind: body.status, version }
  } catch {
    return { kind: 'unreachable' }
  }
}

const LABELS = {
  loading: 'checking',
  healthy: 'healthy',
  degraded: 'degraded',
  unreachable: 'unreachable',
} as const

const TONES = {
  loading: 'var(--text-faint)',
  healthy: 'var(--state-ok)',
  degraded: 'var(--state-warn)',
  unreachable: 'var(--state-crit)',
} as const

export default function ControllerChip() {
  const [state, setState] = useState<ChipState>({ kind: 'loading' })
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null
    let controller: AbortController | null = null

    function poll() {
      controller?.abort()
      const c = new AbortController()
      controller = c
      void fetchHealth(c.signal).then((next) => {
        if (!c.signal.aborted) setState(next)
      })
    }
    function start() {
      if (timer !== null) return
      poll()
      timer = setInterval(poll, POLL_INTERVAL_MS)
    }
    function stop() {
      if (timer !== null) clearInterval(timer)
      timer = null
    }
    function onVisibility() {
      if (document.hidden) stop()
      else start()
    }

    if (!document.hidden) start()
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      stop()
      controller?.abort()
    }
  }, [])

  useEffect(() => {
    if (!open) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false)
    }
    function onClickAway(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    document.addEventListener('mousedown', onClickAway)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.removeEventListener('mousedown', onClickAway)
    }
  }, [open])

  const version =
    state.kind === 'healthy' || state.kind === 'degraded' ? state.version : ''
  const versionText = version ? `v${version.replace(/^v/, '')}` : ''

  return (
    <div className="ctrlchip-root" ref={rootRef}>
      <button
        type="button"
        className="ctrlchip"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Controller ${LABELS[state.kind]}`}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="dot" style={{ color: TONES[state.kind] }} aria-hidden="true" />
        <span className="ctrlchip-txt">
          <span className="cn">controller</span>
          <small>
            {LABELS[state.kind]}
            {versionText ? ` · ${versionText}` : ''}
          </small>
        </span>
      </button>
      {open && (
        <div className="pop open right" role="menu">
          <h4>Controller</h4>
          <div className="row ctrlchip-row">
            <span className="sub">Endpoint</span>
            <span className="mono">{window.location.origin}</span>
          </div>
          <div className="row ctrlchip-row">
            <span className="sub">Version</span>
            <span className="mono">{versionText || '—'}</span>
          </div>
        </div>
      )}
    </div>
  )
}
