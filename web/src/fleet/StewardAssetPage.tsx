// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Asset page tab frame (Story #2723) — the per-steward page at /stewards/:id.
 *
 * Renders a horizontal tab strip: DNA (active by default), plus Config, Shell,
 * and Live Activity as inert "coming soon" placeholders. The DNA tab mounts
 * DnaDrawer, which fetches its own data via the route :id param. Inert tabs
 * render a centred placeholder panel with the `soon` badge — same visual
 * pattern as the sidebar nav's `soon` items.
 *
 * Back-navigation: a "Fleet" breadcrumb link above the h1 returns to `/`.
 * The browser back button also works because this is a real route.
 *
 * ARIA: uses the implicit-association pattern (aria-labelledby only, no
 * aria-controls) so inactive panels can be lazily rendered without leaving
 * broken aria-controls references in the DOM. Roving tabindex keeps Tab focus
 * on a single active tab; ArrowLeft/ArrowRight cycle between tabs.
 */
import { useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import DnaDrawer from './DnaDrawer.tsx'

type TabKey = 'dna' | 'config' | 'shell' | 'live'

interface TabSpec {
  key: TabKey
  label: string
  soon: boolean
}

const TABS: readonly TabSpec[] = [
  { key: 'dna', label: 'DNA', soon: false },
  { key: 'config', label: 'Config', soon: true },
  { key: 'shell', label: 'Shell', soon: true },
  { key: 'live', label: 'Live Activity', soon: true },
]

function SoonPanel({ label }: { label: string }) {
  return (
    <div className="notice">
      <span className="tag">soon</span>
      <p>{label} is not yet available.</p>
    </div>
  )
}

export default function StewardAssetPage() {
  // useParams returns an already-decoded value from React Router — do not
  // call decodeURIComponent again or bare % chars in IDs throw URIError.
  const { id: stewardId = '' } = useParams<{ id: string }>()
  const [activeTab, setActiveTab] = useState<TabKey>('dna')
  const tabRefs = useRef<Map<TabKey, HTMLButtonElement>>(new Map())

  const activeSpec = TABS.find((t) => t.key === activeTab) ?? TABS[0]

  function activateTab(key: TabKey) {
    setActiveTab(key)
    tabRefs.current.get(key)?.focus()
  }

  function onKeyDown(event: React.KeyboardEvent) {
    const keys = TABS.map((t) => t.key)
    const current = keys.indexOf(activeTab)
    if (event.key === 'ArrowRight') {
      activateTab(keys[(current + 1) % keys.length]!)
      event.preventDefault()
    } else if (event.key === 'ArrowLeft') {
      activateTab(keys[(current - 1 + keys.length) % keys.length]!)
      event.preventDefault()
    }
  }

  return (
    <div className="asset-page">
      <div className="htitle">
        <p className="breadcrumb">
          <Link to="/">Fleet</Link>
          {' / '}
          <span className="mono2">{stewardId}</span>
        </p>
        <h1>Device</h1>
      </div>

      <div role="tablist" aria-label="Asset sections" onKeyDown={onKeyDown}>
        {TABS.map((tab) => (
          <button
            key={tab.key}
            role="tab"
            id={`asset-tab-${tab.key}`}
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

      <div
        id={`asset-panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`asset-tab-${activeTab}`}
      >
        {activeSpec?.soon ? (
          <SoonPanel label={activeSpec.label} />
        ) : (
          <DnaDrawer />
        )}
      </div>
    </div>
  )
}
