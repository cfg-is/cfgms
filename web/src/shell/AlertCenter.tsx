// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Alert / notification center (Story #2496) —
 * mockups/fleet-overview.html `#pop-notif`. There is no alerting backend
 * (story Out of Scope), so this renders its designed EMPTY state rather
 * than fabricated sample alerts; a later epic wires a real feed in.
 */
import { useEffect, useRef, useState } from 'react'

export default function AlertCenter() {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const alertCount = 0

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

  return (
    <div className="alertcenter-root" ref={rootRef}>
      <button
        type="button"
        className="icobtn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Notifications"
        onClick={() => setOpen((v) => !v)}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path
            d="M6 9a6 6 0 1112 0c0 5 2 6 2 6H4s2-1 2-6z"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
          <path d="M10 20a2 2 0 004 0" stroke="currentColor" strokeWidth="1.6" />
        </svg>
        {alertCount > 0 && (
          <span className="badge" data-testid="alert-badge">
            {alertCount}
          </span>
        )}
      </button>
      {open && (
        <div className="pop right open" role="menu">
          <h4>Notifications</h4>
          <div className="notice empty">
            <p>No notifications.</p>
          </div>
        </div>
      )}
    </div>
  )
}
