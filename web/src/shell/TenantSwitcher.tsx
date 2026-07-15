// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant-scope switcher (Story #2496) — mockups/fleet-overview.html
 * `.scope` button + `#pop-tenant` popover. A display convenience; the
 * selected scope publishes via TenantScopeContext for views to filter by.
 */
import { useEffect, useRef, useState } from 'react'
import { useTenantScope } from './TenantScopeContext.tsx'

export default function TenantSwitcher() {
  const { scope, observedPaths, setScope } = useTenantScope()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

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

  const segments = scope.split('/')
  const leaf = segments[segments.length - 1]
  const ancestry = segments.slice(0, -1).join('/')

  return (
    <div className="scope-root" ref={rootRef}>
      <button
        type="button"
        className="scope"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="scope-lbl">scope</span>
        <span className="scope-path mono">
          {ancestry ? `${ancestry}/` : ''}
          <b>{leaf}</b>
        </span>
      </button>
      {open && (
        <div className="pop open" role="menu">
          <h4>Switch scope</h4>
          {observedPaths.map((path) => (
            <div
              key={path}
              role="menuitem"
              tabIndex={0}
              className={`row${path === scope ? ' cur' : ''}`}
              onClick={() => {
                setScope(path)
                setOpen(false)
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  setScope(path)
                  setOpen(false)
                }
              }}
            >
              <span className="mono">{path}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
