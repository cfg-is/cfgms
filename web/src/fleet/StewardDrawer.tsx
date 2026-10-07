// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * StewardDrawer (Story #2917) — overlay drawer shown when a fleet row is
 * clicked. Renders the asset tab strip (DNA, Config, Shell, Live Activity)
 * over the still-visible fleet list, without changing the URL.
 *
 * Expand toggle: promotes the 400px side drawer to full-width in-place view
 * and collapses back. ESC and the scrim close the drawer.
 *
 * The deep-link / new-tab path (`/stewards/:id`) continues to render the full
 * StewardAssetPage — this drawer is only the in-app overlay.
 */
import { useEffect, useRef, useState } from 'react'
import DnaDrawer from './DnaDrawer.tsx'
import LiveActivityTab from './LiveActivityTab.tsx'

type DrawerTabKey = 'dna' | 'config' | 'shell' | 'live'

interface DrawerTabSpec {
  key: DrawerTabKey
  label: string
  soon: boolean
}

const DRAWER_TABS: readonly DrawerTabSpec[] = [
  { key: 'dna', label: 'DNA', soon: false },
  { key: 'config', label: 'Config', soon: true },
  { key: 'shell', label: 'Shell', soon: true },
  { key: 'live', label: 'Live Activity', soon: false },
]

function SoonPanel({ label }: { label: string }) {
  return (
    <div className="notice">
      <span className="tag">soon</span>
      <p>{label} is not yet available.</p>
    </div>
  )
}

function DrawerTabPanel({
  tabKey,
  stewardId,
}: {
  tabKey: DrawerTabKey
  stewardId: string
}) {
  if (tabKey === 'dna') return <DnaDrawer stewardId={stewardId} />
  if (tabKey === 'live') return <LiveActivityTab stewardId={stewardId} />
  if (tabKey === 'config') return <SoonPanel label="Config" />
  return <SoonPanel label="Shell" />
}

export default function StewardDrawer({
  stewardId,
  onClose,
}: {
  stewardId: string
  onClose: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [activeTab, setActiveTab] = useState<DrawerTabKey>('dna')
  const tabRefs = useRef<Map<DrawerTabKey, HTMLButtonElement>>(new Map())

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  function activateTab(key: DrawerTabKey) {
    setActiveTab(key)
    tabRefs.current.get(key)?.focus()
  }

  function onTabKeyDown(e: React.KeyboardEvent) {
    const keys = DRAWER_TABS.map((t) => t.key)
    const idx = keys.indexOf(activeTab)
    if (e.key === 'ArrowRight') {
      activateTab(keys[(idx + 1) % keys.length]!)
      e.preventDefault()
    } else if (e.key === 'ArrowLeft') {
      activateTab(keys[(idx - 1 + keys.length) % keys.length]!)
      e.preventDefault()
    }
  }

  return (
    <>
      {/* Scrim closes drawer on click */}
      <div
        className="scrim det-scrim"
        data-testid="drawer-scrim"
        onClick={onClose}
        aria-hidden="true"
      />

      <aside
        className={`det${expanded ? ' det-expanded' : ''}`}
        data-testid="steward-drawer"
        role="dialog"
        aria-label={`Asset details: ${stewardId}`}
      >
        {/* Drawer header */}
        <div className="dh">
          <span className="nm">{stewardId}</span>

          <button
            type="button"
            className="icobtn"
            style={{ width: 30, height: 30, marginLeft: 'auto' }}
            aria-label={expanded ? 'Collapse drawer' : 'Expand drawer'}
            data-testid="drawer-expand-toggle"
            onClick={() => setExpanded((e) => !e)}
          >
            {expanded ? (
              /* collapse arrows */
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M15 9l-6 6M9 9l6 6"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                />
              </svg>
            ) : (
              /* expand arrows */
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M3 9V3h6M21 9V3h-6M3 15v6h6M21 15v6h-6"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            )}
          </button>

          <button
            type="button"
            className="icobtn x"
            style={{ width: 30, height: 30 }}
            aria-label="Close drawer"
            data-testid="drawer-close"
            onClick={onClose}
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

        {/* Tab strip */}
        <div role="tablist" aria-label="Asset sections" onKeyDown={onTabKeyDown}>
          {DRAWER_TABS.map((tab) => (
            <button
              key={tab.key}
              role="tab"
              id={`drawer-tab-${tab.key}`}
              type="button"
              tabIndex={activeTab === tab.key ? 0 : -1}
              aria-selected={activeTab === tab.key}
              ref={(el) => {
                if (el) tabRefs.current.set(tab.key, el)
                else tabRefs.current.delete(tab.key)
              }}
              className={[
                'asset-tab',
                activeTab === tab.key ? 'active' : '',
                tab.soon ? 'soon' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              onClick={() => activateTab(tab.key)}
            >
              {tab.label}
              {tab.soon && <span className="tag">soon</span>}
            </button>
          ))}
        </div>

        {/* Tab panel */}
        <div
          id={`drawer-panel-${activeTab}`}
          role="tabpanel"
          aria-labelledby={`drawer-tab-${activeTab}`}
          className="db"
          style={{ flex: 1, overflow: 'auto' }}
        >
          <DrawerTabPanel tabKey={activeTab} stewardId={stewardId} />
        </div>
      </aside>
    </>
  )
}
