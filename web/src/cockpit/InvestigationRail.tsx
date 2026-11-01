// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * InvestigationRail (Story #3608) — the tabbed investigation / chat rail.
 *
 * Two tabs:
 *  - Investigation: renders content entries of kind="finding" from the case.
 *    If no findings are present, shows an empty state prompt.
 *  - Chat: a static placeholder pane — no backend call, no composer wiring.
 *    Chat backend is out of scope for this epic (see Story #3608 Out of Scope).
 *
 * ARIA: roving tabindex tab panel pattern. Tab buttons use role="tab",
 * aria-selected, and aria-controls. Panels use role="tabpanel".
 * ArrowLeft/ArrowRight cycle between tabs (roving tabindex).
 */
import { useEffect, useRef, useState } from 'react'
import type { ContentEntry } from './caseTypes.ts'

type TabKey = 'investigation' | 'chat'

interface InvestigationRailProps {
  content: ContentEntry[]
  isLive?: boolean
  connectedSince?: Date | null
}

// formatElapsed renders mm:ss since the given instant, matching the mockup's
// monospace elapsed form (LIVE · 02:14).
function formatElapsed(since: Date): string {
  const secs = Math.max(0, Math.floor((Date.now() - since.getTime()) / 1000))
  const mm = String(Math.floor(secs / 60)).padStart(2, '0')
  const ss = String(secs % 60).padStart(2, '0')
  return `${mm}:${ss}`
}

export default function InvestigationRail({ content, isLive = false, connectedSince = null }: InvestigationRailProps) {
  const [activeTab, setActiveTab] = useState<TabKey>('investigation')
  const tabRefs = useRef<Map<TabKey, HTMLButtonElement>>(new Map())
  // Elapsed timer: counts from connectedSince, resets on disconnect/reconnect.
  // State holds a tick counter rather than the formatted string — the string is
  // derived at render time, so it resets with connectedSince instead of needing a
  // setState in the effect body (which causes a cascading render), and can never
  // display the previous session's time for a frame after a reconnect.
  const [, setTick] = useState(0)

  useEffect(() => {
    if (!isLive || !connectedSince) return
    const id = setInterval(() => setTick((n) => n + 1), 1000)
    return () => clearInterval(id)
  }, [isLive, connectedSince])

  const elapsed = isLive && connectedSince ? formatElapsed(connectedSince) : '00:00'

  // Pulse animation is suppressed under prefers-reduced-motion: we check via
  // matchMedia and conditionally apply the animate class so the test can
  // assert absence of the class without relying on jsdom CSS cascade.
  const reducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

  const findings = content.filter((e) => e.kind === 'finding')

  const tabs: { key: TabKey; label: string }[] = [
    { key: 'investigation', label: 'Investigation' },
    { key: 'chat', label: 'Chat' },
  ]

  function activateTab(key: TabKey) {
    setActiveTab(key)
    tabRefs.current.get(key)?.focus()
  }

  function onKeyDown(event: React.KeyboardEvent) {
    const keys = tabs.map((t) => t.key)
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
    <aside className="rail">
      <div
        className="tabs"
        role="tablist"
        aria-label="Investigation sections"
        onKeyDown={onKeyDown}
      >
        {tabs.map((tab) => (
          <button
            key={tab.key}
            role="tab"
            id={`cockpit-tab-${tab.key}`}
            type="button"
            className="tabs__btn"
            tabIndex={activeTab === tab.key ? 0 : -1}
            aria-selected={activeTab === tab.key}
            aria-controls={`cockpit-panel-${tab.key}`}
            ref={(el) => {
              if (el) tabRefs.current.set(tab.key, el)
              else tabRefs.current.delete(tab.key)
            }}
            onClick={() => activateTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Context row: LIVE indicator per mockup (.ctx > .ctx-live) */}
      {isLive && (
        <div className="ctx">
          <span className="ctx-live live-ind" aria-live="polite" aria-label="Live connection active">
            <span
              className={reducedMotion ? 'dot' : 'dot dot--pulse'}
              aria-hidden="true"
            />
            {'LIVE'}
            <span aria-hidden="true"> · </span>
            <span className="mono">{elapsed}</span>
          </span>
        </div>
      )}

      <div
        id="cockpit-panel-investigation"
        role="tabpanel"
        aria-labelledby="cockpit-tab-investigation"
        className="tabpane"
        hidden={activeTab !== 'investigation'}
      >
        {findings.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            No investigation findings yet.
          </p>
        ) : (
          <div className="finds">
            {findings.map((entry) => (
              <div key={entry.id} className="find">
                <span className="find__mark" aria-hidden="true" />
                <p>{entry.body}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      <div
        id="cockpit-panel-chat"
        role="tabpanel"
        aria-labelledby="cockpit-tab-chat"
        className="tabpane"
        hidden={activeTab !== 'chat'}
      >
        <p className="chat-placeholder">Chat is not yet available.</p>
      </div>
    </aside>
  )
}
