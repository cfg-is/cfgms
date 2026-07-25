// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * App shell (Story #2496) — mockups/fleet-overview.html lines ~102-266.
 * The persistent chrome every authenticated screen mounts into: sidebar +
 * top bar at desktop width, hamburger + off-canvas drawer + scrim below
 * 1024px, Escape closes overlays. Routed content occupies `.content` via
 * <Outlet> (Story #2723); the global search box is passed to the outlet
 * context so FleetOverview can live-filter without prop drilling through
 * the route table.
 */
import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router'
import { TenantScopeProvider } from './TenantScopeContext.tsx'
import TenantSwitcher from './TenantSwitcher.tsx'
import GlobalSearch from './GlobalSearch.tsx'
import AlertCenter from './AlertCenter.tsx'
import UserMenu from './UserMenu.tsx'
import { useAuth } from '../auth/AuthContext.tsx'
import './AppShell.css'

/** Context type exposed to outlet children via useOutletContext. */
export interface AppShellContext {
  search: string
  onSearchChange: (value: string) => void
}

const NAV_ITEMS = [
  { label: 'Fleet', to: '/', soon: false },
  { label: 'Modules', to: '/modules', soon: false },
  { label: 'Config', to: '/config', soon: false },
  { label: 'Workflows', to: '/workflows', soon: false },
  { label: 'Audit', to: '/audit', soon: false },
  { label: 'Accounts', to: '/accounts', soon: false },
] as const

export default function AppShell() {
  const { principal } = useAuth()
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
    <TenantScopeProvider rootPath={principal?.tenantId ?? ''}>
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
            {NAV_ITEMS.map((item) =>
              item.soon ? (
                <a
                  key={item.label}
                  role="link"
                  tabIndex={0}
                  className="soon"
                >
                  {item.label}
                  <span className="tag">soon</span>
                </a>
              ) : (
                <NavLink
                  key={item.label}
                  to={item.to}
                  className={({ isActive }) => (isActive ? 'active' : '')}
                >
                  {item.label}
                </NavLink>
              ),
            )}
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
            <Outlet context={{ search, onSearchChange: setSearch } satisfies AppShellContext} />
          </div>
        </div>
      </div>
    </TenantScopeProvider>
  )
}
