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
 * Last-run status pill: derived from useWorkflowExecutions(workflow.name) —
 * the same fetch the Run tab (F3) will also mount — picking whichever
 * execution has the latest start_time (the endpoint documents no ordering).
 * A workflow with no executions yet renders a neutral "Never run" pill.
 *
 * Security A9.1: workflow.name, workflow.description, and execution status
 * originate from user-supplied / controller content and are rendered as
 * JSX text nodes only — never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import type { VersionedWorkflow, WorkflowExecution } from './useWorkflows.ts'
import { useWorkflowExecutions } from './useWorkflows.ts'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'

type DrawerTab = 'run' | 'schedule' | 'preview'

interface WorkflowDrawerProps {
  workflow: VersionedWorkflow
  onClose: () => void
}

function lastRunTone(status: string): string {
  switch (status) {
    case 'completed':
      return 'ok'
    case 'failed':
    case 'cancelled':
      return 'crit'
    case 'running':
    case 'pending':
    case 'paused':
      return 'warn'
    default:
      return 'neutral'
  }
}

function mostRecentExecution(
  executions: WorkflowExecution[],
): WorkflowExecution | null {
  return executions.reduce<WorkflowExecution | null>((latest, ex) => {
    if (!latest) return ex
    return Date.parse(ex.start_time) > Date.parse(latest.start_time) ? ex : latest
  }, null)
}

export default function WorkflowDrawer({ workflow, onClose }: WorkflowDrawerProps) {
  const [activeTab, setActiveTab] = useState<DrawerTab>('run')
  const { scope } = useTenantScope()
  // Every workflow in a single GET /api/v1/workflows response belongs to the
  // request's scoped tenant (workflowStoreForRequest), so the current scope
  // is the correct tenant path for any workflow in this list.
  const tenantPath = scope || 'root'
  const { executions } = useWorkflowExecutions(workflow.name)
  const lastRun = mostRecentExecution(executions)

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
        <div className="meta" data-testid="drawer-meta">
          {workflow.version && <>v{workflow.version} · </>}
          <span data-testid="drawer-tenant-path">{tenantPath}</span>
          {' · '}
          <span
            className={`pill ${lastRun ? lastRunTone(lastRun.status) : 'neutral'}`}
            data-testid="drawer-last-run-pill"
          >
            <span className="dot" />
            {lastRun ? lastRun.status : 'Never run'}
          </span>
        </div>
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
