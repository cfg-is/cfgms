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
import { type ComponentType, useCallback, useEffect, useRef, useState } from 'react'
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
import TamperPanel, { type HandsOnTab } from './TamperPanel.tsx'

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

interface StewardHealth {
  status: string
  reasons: HealthReason[]
  /** Stored tamper codes of the last alarm (tampered stewards only). */
  tamperCodes: string[]
  /** Host name the controller has for the steward ('' when none). */
  hostname: string
  connectionState: string
}

type HealthLoad =
  | { phase: 'loading' }
  | { phase: 'error' }
  | { phase: 'ready'; health: StewardHealth }

/*
 * Status and health reasons from GET /api/v1/stewards/{id}. `reload` re-reads without
 * dropping the current value, so the tamper panel does not flash through Loading.
 * NOTE: the REST payload carries no separate host-name field, so the host name is the
 * `dna.hostname` the controller last stored for the steward.
 */
function useStewardHealth(stewardId: string): { load: HealthLoad; reload: () => void } {
  const [state, setState] = useState<{ id: string; load: HealthLoad }>({ id: stewardId, load: { phase: 'loading' } })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let cancelled = false
    apiFetch(`/api/v1/stewards/${encodeURIComponent(stewardId)}`)
      .then(async (response) => {
        if (!response.ok) {
          if (!cancelled) setState((prev) => (prev.id === stewardId && prev.load.phase === 'ready' ? prev : { id: stewardId, load: { phase: 'error' } }))
          return
        }
        const body: unknown = await response.json()
        const data = (body as Record<string, unknown> | null)?.data as Record<string, unknown> | null | undefined
        if (cancelled) return
        if (typeof data !== 'object' || data === null) {
          setState((prev) => (prev.id === stewardId && prev.load.phase === 'ready' ? prev : { id: stewardId, load: { phase: 'error' } }))
          return
        }
        const dna = data.dna as Record<string, unknown> | null | undefined
        setState({
          id: stewardId,
          load: {
            phase: 'ready',
            health: {
              status: typeof data.status === 'string' ? data.status.trim().toLowerCase() : '',
              reasons: parseHealthReasons(data.health_reasons),
              tamperCodes: Array.isArray(data.tamper_codes)
                ? data.tamper_codes.filter((c): c is string => typeof c === 'string')
                : [],
              hostname: typeof dna?.hostname === 'string' ? dna.hostname : '',
              connectionState: typeof data.connection_state === 'string' ? data.connection_state : '',
            },
          },
        })
      })
      .catch(() => {
        if (!cancelled) setState((prev) => (prev.id === stewardId && prev.load.phase === 'ready' ? prev : { id: stewardId, load: { phase: 'error' } }))
      })
    return () => {
      cancelled = true
    }
  }, [stewardId, tick])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { load: state.id === stewardId ? state.load : { phase: 'loading' }, reload }
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
  const { load, reload } = useStewardHealth(stewardId)
  const health = load.phase === 'ready' ? load.health : null
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

      {load.phase === 'loading' && (
        <div className="tp-loading" aria-busy="true" data-testid="tamper-loading">
          Loading steward status…
        </div>
      )}
      {load.phase === 'error' && (
        <div className="tp-error" role="status" data-testid="tamper-error">
          Steward status could not be loaded.{' '}
          <button type="button" className="tp-btn-sec" onClick={reload}>
            Retry
          </button>
        </div>
      )}
      {health !== null && (
        <TamperPanel
          steward={{
            id: stewardId,
            status: health.status,
            hostname: health.hostname,
            connectionState: health.connectionState,
            reasons: health.reasons,
            tamperCodes: health.tamperCodes,
          }}
          onChanged={reload}
          onSelectTab={(tab: HandsOnTab) => activateTab(tab)}
        />
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
