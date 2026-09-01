// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Registration console tab shell (Story #2934, #2935, #2971, #3723).
 * Renders the /registration route with a tab strip:
 *   Pending             — list + deny (Story #2934)
 *   Tokens              — read-only token lifecycle view (Story #2935)
 *   IP Trust            — add/revoke behind step-up (Story #2936 layout, #2971 actions)
 *   Credential Requests — browser-authenticated CLI enrolment approval (Story #3723)
 *
 * Tab pattern mirrors StewardAssetPage.tsx exactly: role="tablist", roving
 * tabindex, ArrowLeft/Right keyboard navigation, implicit aria-labelledby
 * association so inactive panels can be lazily rendered.
 */
import { type ComponentType, useEffect, useRef, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import CredentialRequestsTab from './CredentialRequestsTab.tsx'
import IPTrustTab from './IPTrustTab.tsx'
import PendingQueueTab, { parsePendingRegistrations } from './PendingQueueTab.tsx'
import TokensTab from './TokensTab.tsx'

type TabKey = 'pending' | 'tokens' | 'ip-trust' | 'credential-requests'

interface TabSpec {
  key: TabKey
  label: string
  soon: boolean
  Panel?: ComponentType
}

function SoonPanel({ label }: { label: string }) {
  return (
    <div className="notice">
      <span className="tag">soon</span>
      <p>{label} is not yet available.</p>
    </div>
  )
}

function PanelContent({ spec }: { spec: TabSpec }) {
  const Panel = spec.Panel
  return Panel ? <Panel /> : <SoonPanel label={spec.label} />
}

export const TABS: readonly TabSpec[] = [
  { key: 'pending', label: 'Pending', soon: false, Panel: PendingQueueTab },
  { key: 'tokens', label: 'Tokens', soon: false, Panel: TokensTab },
  { key: 'ip-trust', label: 'IP Trust', soon: false, Panel: IPTrustTab },
  { key: 'credential-requests', label: 'Credential Requests', soon: false, Panel: CredentialRequestsTab },
]

export default function RegistrationConsolePage() {
  const [activeTab, setActiveTab] = useState<TabKey>('pending')
  const [pendingCount, setPendingCount] = useState<number | null>(null)
  const tabRefs = useRef<Map<TabKey, HTMLButtonElement>>(new Map())

  // Independent of tab selection so the badge is visible without navigating
  // into the Pending tab (Issue #3786). Uses the same registration:list-pending
  // -gated endpoint as PendingQueueTab: a principal who cannot see the tab
  // (403) does not see the badge either — failures are silently ignored.
  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/registration/pending')
      .then(async (response) => {
        if (!response.ok) return
        const body: unknown = await response.json()
        const entries = parsePendingRegistrations(body)
        if (!cancelled) setPendingCount(entries.length)
      })
      .catch(() => {
        // Best-effort: no badge on failure, no error surfaced.
      })
    return () => {
      cancelled = true
    }
  }, [])

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
        <h1>Registration</h1>
      </div>

      <div role="tablist" aria-label="Registration sections" onKeyDown={onKeyDown}>
        {TABS.map((tab) => (
          <button
            key={tab.key}
            role="tab"
            id={`reg-tab-${tab.key}`}
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
            {tab.key === 'pending' && pendingCount !== null && pendingCount > 0 && (
              <span className="count-badge" data-testid="pending-count-badge">
                {pendingCount}
              </span>
            )}
          </button>
        ))}
      </div>

      <div
        id={`reg-panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`reg-tab-${activeTab}`}
      >
        <PanelContent spec={activeSpec} />
      </div>
    </div>
  )
}
