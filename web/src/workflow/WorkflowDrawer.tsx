// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Overlay drawer shell for the /workflows browse view (Story #3039).
 * Positioned absolute inside .workspace so the list table rows never
 * reflow when the drawer opens or closes.
 *
 * Tab slots: Run (F3), Schedule (#2986), Preview (F4) are placeholder panes;
 * sibling stories mount their content here.
 *
 * Security A9.1: workflow.name and workflow.description originate from
 * user-supplied content and are rendered as JSX text nodes only —
 * never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import type { VersionedWorkflow } from './useWorkflows.ts'

type DrawerTab = 'run' | 'schedule' | 'preview'

interface WorkflowDrawerProps {
  workflow: VersionedWorkflow
  onClose: () => void
}

export default function WorkflowDrawer({ workflow, onClose }: WorkflowDrawerProps) {
  const [activeTab, setActiveTab] = useState<DrawerTab>('run')

  return (
    <aside
      className="drawer"
      data-testid="workflow-drawer"
      aria-label={`${workflow.name} details`}
    >
      <div className="dhead">
        <div className="top">
          <h2 data-testid="drawer-name">{workflow.name}</h2>
          <div className="acts">
            <button
              type="button"
              className="wf-btn-sm"
              data-testid="drawer-open-builder"
            >
              ⤢ Open builder
            </button>
            <button
              type="button"
              className="icobtn"
              aria-label="Close"
              onClick={onClose}
              data-testid="drawer-close"
            >
              ✕
            </button>
          </div>
        </div>
        {workflow.version && (
          <div className="meta" data-testid="drawer-meta">
            v{workflow.version}
          </div>
        )}
      </div>

      <div className="dtabs" role="tablist" aria-label="Workflow details tabs">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'run'}
          className={activeTab === 'run' ? 'on' : ''}
          onClick={() => setActiveTab('run')}
          data-testid="drawer-tab-run"
        >
          Run
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'schedule'}
          className={activeTab === 'schedule' ? 'on' : ''}
          onClick={() => setActiveTab('schedule')}
          data-testid="drawer-tab-schedule"
        >
          Schedule
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'preview'}
          className={activeTab === 'preview' ? 'on' : ''}
          onClick={() => setActiveTab('preview')}
          data-testid="drawer-tab-preview"
        >
          What it does
        </button>
      </div>

      <div className="dbody" role="tabpanel">
        {activeTab === 'run' && (
          <div data-testid="drawer-pane-run">
            <p className="mut">Run and execution history — coming in a later story.</p>
          </div>
        )}
        {activeTab === 'schedule' && (
          <div data-testid="drawer-pane-schedule">
            <p className="mut">Triggers and schedule — coming in a later story.</p>
          </div>
        )}
        {activeTab === 'preview' && (
          <div data-testid="drawer-pane-preview">
            <p className="mut">Workflow preview — coming in a later story.</p>
          </div>
        )}
      </div>
    </aside>
  )
}
