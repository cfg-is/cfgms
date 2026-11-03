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
import { type ComponentType, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { apiFetch } from '../api/client.ts'
import type { HealthReason } from './health.ts'
import { parseHealthReasons } from './useStewards.ts'
import ComplianceTab from './ComplianceTab.tsx'
import DnaDrawer from './DnaDrawer.tsx'
import LiveActivityTab from './LiveActivityTab.tsx'
import LogsPanel from './LogsPanel.tsx'
import ModulesPanel from './ModulesPanel.tsx'
import ShellTab from './ShellTab.tsx'

type TabKey = 'dna' | 'config' | 'shell' | 'logs' | 'modules' | 'live' | 'compliance'

interface TabSpec {
  key: TabKey
  label: string
  soon: boolean
  Panel?: ComponentType<PanelProps & { stewardId?: string }>
}

interface PanelProps {
  onSelectTab?: (key: TabKey) => void
}

function LiveActivityPanel({ onSelectTab }: PanelProps) {
  const { id: stewardId = '' } = useParams<{ id: string }>()
  return <LiveActivityTab stewardId={stewardId} onViewDna={() => onSelectTab?.('dna')} />
}

function ShellPanel() {
  const { id: stewardId = '' } = useParams<{ id: string }>()
  return <ShellTab stewardId={stewardId} />
}

export const TABS: readonly TabSpec[] = [
  { key: 'dna', label: 'DNA', soon: false, Panel: DnaDrawer },
  { key: 'config', label: 'Config', soon: true },
  { key: 'shell', label: 'Shell', soon: false, Panel: ShellPanel },
  { key: 'logs', label: 'Logs', soon: false, Panel: LogsPanel },
  { key: 'modules', label: 'Modules', soon: false, Panel: ModulesPanel },
  { key: 'live', label: 'Live Activity', soon: false, Panel: LiveActivityPanel },
  { key: 'compliance', label: 'Compliance', soon: false, Panel: ComplianceTab },
]

function SoonPanel({ label }: { label: string }) {
  return (
    <div className="notice">
      <span className="tag">soon</span>
      <p>{label} is not yet available.</p>
    </div>
  )
}

export function PanelContent({ spec, onSelectTab }: { spec: TabSpec } & PanelProps) {
  const Panel = spec.Panel
  return Panel ? <Panel onSelectTab={onSelectTab} /> : <SoonPanel label={spec.label} />
}

/* Status and health reasons from GET /api/v1/stewards/{id}; null until loaded or on failure. */
function useStewardHealth(stewardId: string): { status: string; reasons: HealthReason[] } | null {
  const [state, setState] = useState<{ id: string; status: string; reasons: HealthReason[] } | null>(null)
  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/v1/stewards/${encodeURIComponent(stewardId)}`)
      .then(async (response) => {
        if (!response.ok) return
        const body: unknown = await response.json()
        const data = (body as Record<string, unknown> | null)?.data as Record<string, unknown> | null | undefined
        if (cancelled || typeof data !== 'object' || data === null) return
        setState({
          id: stewardId,
          status: typeof data.status === 'string' ? data.status.trim().toLowerCase() : '',
          reasons: parseHealthReasons(data.health_reasons),
        })
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [stewardId])
  return state?.id === stewardId ? state : null
}

function HealthReasonList({ reasons }: { reasons: HealthReason[] }) {
  return (
    <ul>
      {reasons.map((r, i) => (
        <li key={`${r.component}:${r.code}:${i}`}>
          <span className="mono2">{r.component}</span> <strong>{r.code}</strong>
          {r.message ? <> — {r.message}</> : null}
        </li>
      ))}
    </ul>
  )
}

export default function StewardAssetPage() {
  // useParams returns an already-decoded value from React Router — do not
  // call decodeURIComponent again or bare % chars in IDs throw URIError.
  const { id: stewardId = '' } = useParams<{ id: string }>()
  const health = useStewardHealth(stewardId)
  const tampered = health?.status === 'tampered'
  const [activeTab, setActiveTab] = useState<TabKey>('dna')
  const tabRefs = useRef<Map<TabKey, HTMLButtonElement>>(new Map())

  const activeSpec = (TABS.find((t) => t.key === activeTab) ?? TABS[0])!

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

      {tampered && (
        <div
          role="alert"
          data-testid="tampered-banner"
          style={{
            background: 'var(--state-crit-bg)',
            color: 'var(--state-crit)',
            padding: 'var(--space-3)',
            marginBottom: 'var(--space-3)',
          }}
        >
          <strong>TAMPERED</strong> — this steward reported tampering.
          <HealthReasonList reasons={health.reasons} />
        </div>
      )}
      {health !== null && health.reasons.length > 0 && (
        <section data-testid="health-reasons-block" aria-label="Health reasons">
          <h2>Health reasons</h2>
          <HealthReasonList reasons={health.reasons} />
        </section>
      )}

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
            {tab.soon && <span className="tag asset-tab-soon">soon</span>}
          </button>
        ))}
      </div>

      <div
        id={`asset-panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`asset-tab-${activeTab}`}
      >
        <PanelContent spec={activeSpec} onSelectTab={activateTab} />
      </div>
    </div>
  )
}
