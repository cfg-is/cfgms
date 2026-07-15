// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App shell (Story #2496) — mockups/fleet-overview.html lines ~102-266.
 * The persistent chrome every authenticated screen mounts into: sidebar +
 * top bar at desktop width, hamburger + off-canvas drawer + scrim below
 * 1024px, Escape closes overlays. Fleet overview (#2497) is the first real
 * occupant of `.content` — this story renders its empty-state placeholder.
 */
import { useEffect, useState } from 'react'
import { TenantScopeProvider } from './TenantScopeContext.tsx'
import TenantSwitcher from './TenantSwitcher.tsx'
import GlobalSearch from './GlobalSearch.tsx'
import AlertCenter from './AlertCenter.tsx'
import UserMenu from './UserMenu.tsx'
import './AppShell.css'

const NAV_ITEMS = [
  { label: 'Fleet', active: true, soon: false },
  { label: 'Modules', active: false, soon: true },
  { label: 'Config', active: false, soon: true },
  { label: 'Audit', active: false, soon: true },
] as const

export default function AppShell() {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [search, setSearch] = useState('')

  useEffect(() => {
    document.body.classList.toggle('drawer', drawerOpen)
    return () => document.body.classList.remove('drawer')
  }, [drawerOpen])

  useEffect(() => {
    if (!drawerOpen) return
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setDrawerOpen(false)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [drawerOpen])

  return (
    <TenantScopeProvider rootPath="root">
      <div
        className="scrim"
        data-testid="shell-scrim"
        onClick={() => setDrawerOpen(false)}
      />
      <div className="shell">
        <aside className="side">
          <div className="logo">
            <div className="l">
              <b>CFGMS</b>
              <i>controller</i>
            </div>
            <button
              type="button"
              className="icobtn drawer-close"
              aria-label="Close navigation"
              onClick={() => setDrawerOpen(false)}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M6 6l12 12M18 6L6 18"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              </svg>
            </button>
          </div>
          <nav>
            {NAV_ITEMS.map((item) => (
              <a
                key={item.label}
                role="link"
                tabIndex={0}
                className={`${item.active ? 'active' : ''}${item.soon ? ' soon' : ''}`}
              >
                {item.label}
                {item.soon && <span className="tag">soon</span>}
              </a>
            ))}
          </nav>
        </aside>

        <div className="main">
          <div className="appbar">
            <button
              type="button"
              className="icobtn ham"
              aria-label="Open navigation"
              onClick={() => setDrawerOpen(true)}
            >
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M4 7h16M4 12h16M4 17h16"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              </svg>
            </button>
            <TenantSwitcher />
            <GlobalSearch value={search} onChange={setSearch} />
            <div className="abspacer" />
            <AlertCenter />
            <UserMenu />
          </div>

          <div className="content">
            <div className="htitle">
              <h1>Fleet</h1>
              <p>Stewards enrolled to this controller, with the device DNA you choose.</p>
            </div>
            <section className="panel">
              <div className="notice empty">
                <h3>Fleet overview lands in Story #2497</h3>
                <p>This screen will list enrolled stewards once that story ships.</p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </TenantScopeProvider>
  )
}
