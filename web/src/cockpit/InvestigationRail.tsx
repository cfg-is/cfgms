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
import { useRef, useState } from 'react'
import type { ContentEntry } from './caseTypes.ts'

type TabKey = 'investigation' | 'chat'

interface InvestigationRailProps {
  content: ContentEntry[]
}

export default function InvestigationRail({ content }: InvestigationRailProps) {
  const [activeTab, setActiveTab] = useState<TabKey>('investigation')
  const tabRefs = useRef<Map<TabKey, HTMLButtonElement>>(new Map())

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
