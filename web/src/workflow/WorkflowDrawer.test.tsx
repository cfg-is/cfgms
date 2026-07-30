// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowDrawer test suite (Story #3039): drawer renders correctly, tabs
 * switch visible pane, close button fires onClose, and user content is
 * rendered as safe text nodes (Security A9.1).
 */
import { describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach } from 'vitest'
import WorkflowDrawer from './WorkflowDrawer.tsx'
import type { VersionedWorkflow } from './useWorkflows.ts'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'

afterEach(cleanup)

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

describe('WorkflowDrawer — security (A9.1)', () => {
  it('renders workflow name as a text node, not HTML', () => {
    const xss = '<img src=x onerror="window.__xss_drawer=1">'
    renderDrawer(makeWorkflow({ name: xss }))
    expect(screen.getByTestId('drawer-name')).toHaveTextContent(xss)
    expect((window as unknown as Record<string, unknown>).__xss_drawer).toBeUndefined()
  })
})
