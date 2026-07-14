// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * User menu (Story #2496) — mockups/fleet-overview.html `#pop-user`.
 * Shows the signed-in principal (via #2495 auth context) and hosts logout,
 * plus the design-system theme toggle (auto/light/dark via
 * :root[data-theme]). Theme choice persists in localStorage — a display
 * preference, not auth data, so it's explicitly allowlisted in the A7.2
 * source scan (Login.test.tsx STORAGE_ALLOWLIST) rather than exempt from
 * it. The scan requires the key to be a plain string literal at each call
 * site (not a shared constant) so both the automated check and a human
 * reviewer can see the exact key without following indirection — write
 * 'cfgms.theme' inline every time, never factor it into a variable.
 */
import { useEffect, useRef, useState } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'

type ThemeMode = 'auto' | 'light' | 'dark'

function loadThemeMode(): ThemeMode {
  const stored = localStorage.getItem('cfgms.theme')
  return stored === 'light' || stored === 'dark' || stored === 'auto' ? stored : 'auto'
}

function applyTheme(mode: ThemeMode) {
  if (mode === 'auto') {
    document.documentElement.removeAttribute('data-theme')
  } else {
    document.documentElement.setAttribute('data-theme', mode)
  }
}

function initials(username: string | undefined): string {
  if (!username) return '?'
  const local = username.split('@')[0] ?? username
  const parts = local.split(/[._-]/).filter(Boolean)
  const text = parts.length >= 2 ? `${parts[0]?.[0] ?? ''}${parts[1]?.[0] ?? ''}` : local.slice(0, 2)
  return text.toUpperCase()
}

export default function UserMenu() {
  const { principal, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const [themeMode, setThemeMode] = useState<ThemeMode>(loadThemeMode)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    applyTheme(themeMode)
    localStorage.setItem('cfgms.theme', themeMode)
  }, [themeMode])

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
    <div className="usermenu-root" ref={rootRef}>
      <button
        type="button"
        className="uav"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        onClick={() => setOpen((v) => !v)}
      >
        {initials(principal?.username)}
      </button>
      {open && (
        <div className="pop right open" role="menu">
          <div className="row" style={{ cursor: 'default' }}>
            <div className="uav" style={{ width: 30, height: 30, fontSize: 11 }}>
              {initials(principal?.username)}
            </div>
            <div>{principal?.username ?? 'Not signed in'}</div>
          </div>
          <div className="sep" />
          <h4>Theme</h4>
          <div className="miniseg">
            {(['light', 'auto', 'dark'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                className={themeMode === mode ? 'on' : ''}
                onClick={() => setThemeMode(mode)}
              >
                {mode.slice(0, 1).toUpperCase() + mode.slice(1)}
              </button>
            ))}
          </div>
          <div className="sep" />
          <div
            role="menuitem"
            tabIndex={0}
            className="row"
            style={{ color: 'var(--state-crit)' }}
            onClick={() => void logout()}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') void logout()
            }}
          >
            Sign out
          </div>
        </div>
      )}
    </div>
  )
}
