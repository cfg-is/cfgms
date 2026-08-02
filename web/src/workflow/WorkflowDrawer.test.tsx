// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowDrawer test suite (Story #3039): drawer renders correctly, tabs
 * switch visible pane, close button fires onClose, the last-run status pill
 * reflects the most recent execution, and user content is rendered as safe
 * text nodes (Security A9.1).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach } from 'vitest'
import WorkflowDrawer from './WorkflowDrawer.tsx'
import type { VersionedWorkflow } from './useWorkflows.ts'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'

const fetchMock = vi.fn<typeof fetch>()

function makeExecutionsResponse(executions: object[], status = 200) {
  return new Response(
    JSON.stringify({ executions, count: executions.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeExecution(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'exec-1',
    workflow_name: 'onboard-user',
    status: 'completed',
    start_time: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  fetchMock.mockResolvedValue(makeExecutionsResponse([]))
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeWorkflow(overrides: Partial<VersionedWorkflow> = {}): VersionedWorkflow {
  return {
    name: 'onboard-user',
    description: 'Create a user on the DC',
    version: '1.5.0',
    steps: [{ id: 'step-1', name: 'step-1', type: 'script', config: {} }],
    semantic_version: { major: 1, minor: 5, patch: 0, pre_release: '', build_meta: '' },
    ...overrides,
  }
}

function renderDrawer(
  workflow = makeWorkflow(),
  onClose = vi.fn(),
  rootPath = 'root/msp-a/client-1',
) {
  return render(
    <TenantScopeProvider rootPath={rootPath}>
      <WorkflowDrawer workflow={workflow} onClose={onClose} />
    </TenantScopeProvider>,
  )
}

describe('WorkflowDrawer — header', () => {
  it('renders the drawer with the workflow name in the header', () => {
    renderDrawer()
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-name')).toHaveTextContent('onboard-user')
  })

  it('shows the version in the meta line', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-meta')).toHaveTextContent('v1.5.0')
  })

  it('shows the current tenant scope path in the meta line', () => {
    renderDrawer(makeWorkflow(), vi.fn(), 'root/msp-a/client-1')
    expect(screen.getByTestId('drawer-tenant-path')).toHaveTextContent(
      'root/msp-a/client-1',
    )
  })

  it('falls back to "root" for an empty (unnarrowed) tenant scope', () => {
    renderDrawer(makeWorkflow(), vi.fn(), '')
    expect(screen.getByTestId('drawer-tenant-path')).toHaveTextContent('root')
  })

  it('renders "Open builder" affordance as a stub button', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-open-builder')).toBeInTheDocument()
  })

  it('close button calls onClose', () => {
    const onClose = vi.fn()
    renderDrawer(makeWorkflow(), onClose)
    fireEvent.click(screen.getByTestId('drawer-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

describe('WorkflowDrawer — tab bar', () => {
  it('renders Run, Schedule, and What-it-does tabs', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-tab-run')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-tab-schedule')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-tab-preview')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-tab-preview')).toHaveTextContent(/what it does/i)
  })

  it('Run tab is active by default', () => {
    renderDrawer()
    expect(screen.getByTestId('drawer-tab-run')).toHaveClass('on')
    expect(screen.getByTestId('drawer-tab-schedule')).not.toHaveClass('on')
    expect(screen.getByTestId('drawer-tab-preview')).not.toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-run')).toBeInTheDocument()
  })

  it('clicking Schedule tab activates it and shows the schedule pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-schedule'))
    expect(screen.getByTestId('drawer-tab-schedule')).toHaveClass('on')
    expect(screen.getByTestId('drawer-tab-run')).not.toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-schedule')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
  })

  it('clicking Preview tab activates it and shows the preview pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-preview'))
    expect(screen.getByTestId('drawer-tab-preview')).toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-preview')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
    expect(screen.queryByTestId('drawer-pane-schedule')).toBeNull()
  })

  it('switching back to Run tab from another tab shows the run pane', () => {
    renderDrawer()
    fireEvent.click(screen.getByTestId('drawer-tab-schedule'))
    fireEvent.click(screen.getByTestId('drawer-tab-run'))
    expect(screen.getByTestId('drawer-tab-run')).toHaveClass('on')
    expect(screen.getByTestId('drawer-pane-run')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-schedule')).toBeNull()
  })
})

describe('WorkflowDrawer — last-run status pill', () => {
  it('shows a neutral "Never run" pill when the workflow has no executions', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    renderDrawer()
    const pill = await screen.findByTestId('drawer-last-run-pill')
    expect(pill).toHaveClass('pill', 'neutral')
    expect(pill).toHaveTextContent('Never run')
  })

  it('shows the most recent execution status, chosen by start_time not array order', async () => {
    fetchMock.mockResolvedValue(
      makeExecutionsResponse([
        makeExecution({
          id: 'exec-newer',
          status: 'completed',
          start_time: '2026-01-03T00:00:00Z',
        }),
        makeExecution({
          id: 'exec-older',
          status: 'failed',
          start_time: '2026-01-01T00:00:00Z',
        }),
      ]),
    )
    renderDrawer()
    const pill = await screen.findByTestId('drawer-last-run-pill')
    expect(pill).toHaveClass('pill', 'ok')
    expect(pill).toHaveTextContent('completed')
  })

  it('maps a failed last run to the crit tone', async () => {
    fetchMock.mockResolvedValue(
      makeExecutionsResponse([
        makeExecution({ status: 'failed', start_time: '2026-01-01T00:00:00Z' }),
      ]),
    )
    renderDrawer()
    const pill = await screen.findByTestId('drawer-last-run-pill')
    expect(pill).toHaveClass('pill', 'crit')
    expect(pill).toHaveTextContent('failed')
  })
})

describe('WorkflowDrawer — security (A9.1)', () => {
  it('renders workflow name as a text node, not HTML', () => {
    const xss = '<img src=x onerror="window.__xss_drawer=1">'
    renderDrawer(makeWorkflow({ name: xss }))
    expect(screen.getByTestId('drawer-name')).toHaveTextContent(xss)
    expect((window as unknown as Record<string, unknown>).__xss_drawer).toBeUndefined()
  })
})
