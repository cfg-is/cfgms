// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowListView test suite (Story #3039): overlay drawer shell behavior —
 * row-select opens the drawer, ✕ closes it, tab switching works, and the
 * list column layout is unchanged between open/closed states.
 *
 * Also covers data states (loading, empty, error, table), the delete confirm
 * dialog, and security (A9.1).
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import WorkflowListView from './WorkflowListView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeWorkflowListResponse(workflows: object[], status = 200) {
  return new Response(
    JSON.stringify({ workflows, count: workflows.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeWorkflow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    name: 'wf-1',
    description: 'Test workflow',
    version: '1.0.0',
    steps: [{ name: 'step-1', type: 'script', config: {} }],
    semantic_version: { major: 1, minor: 0, patch: 0, pre_release: '', build_meta: '' },
    ...overrides,
  }
}

function renderWorkflowListView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <TenantScopeProvider rootPath="root">
          <WorkflowListView />
        </TenantScopeProvider>
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Page structure ────────────────────────────────────────────────────────────

describe('WorkflowListView — heading and page structure', () => {
  it('shows the Workflows heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderWorkflowListView()
    expect(
      screen.getByRole('heading', { name: /workflows/i, level: 1 }),
    ).toBeInTheDocument()
  })
})

// ── Data states ───────────────────────────────────────────────────────────────

describe('WorkflowListView — data states', () => {
  it('shows loading state before the response', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderWorkflowListView()
    expect(screen.getByTestId('workflow-loading')).toBeInTheDocument()
  })

  it('shows empty state when no workflows exist', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
  })

  it('shows error notice when the request fails', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([], 500))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByRole('alert')).toBeInTheDocument(),
    )
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('renders a table with workflow rows', async () => {
    fetchMock.mockResolvedValue(
      makeWorkflowListResponse([makeWorkflow(), makeWorkflow({ name: 'wf-2' })]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    expect(screen.getAllByTestId('workflow-row')).toHaveLength(2)
    expect(screen.getByText('wf-1')).toBeInTheDocument()
    expect(screen.getByText('wf-2')).toBeInTheDocument()
  })

  it('shows the workflow count in the toolbar', async () => {
    fetchMock.mockResolvedValue(
      makeWorkflowListResponse([makeWorkflow(), makeWorkflow({ name: 'wf-2' })]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-count')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('workflow-count')).toHaveTextContent('2 workflows')
  })
})

// ── Overlay drawer (Story #3039) ──────────────────────────────────────────────

describe('WorkflowListView — overlay drawer', () => {
  it('clicking a row opens the overlay drawer', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-name')).toHaveTextContent('wf-1')
    expect(screen.getByTestId('drawer-tenant-path')).toHaveTextContent('root')
  })

  it('clicking ✕ closes the drawer', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('drawer-close'))
    expect(screen.queryByTestId('workflow-drawer')).toBeNull()
  })

  it('clicking the same row a second time closes the drawer', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.queryByTestId('workflow-drawer')).toBeNull()
  })

  it('clicking a different row switches the drawer to that workflow', async () => {
    fetchMock.mockResolvedValue(
      makeWorkflowListResponse([makeWorkflow(), makeWorkflow({ name: 'wf-2', version: '2.0.0' })]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    const rows = screen.getAllByTestId('workflow-row')
    fireEvent.click(rows[0]!)
    expect(screen.getByTestId('drawer-name')).toHaveTextContent('wf-1')
    fireEvent.click(rows[1]!)
    expect(screen.getByTestId('drawer-name')).toHaveTextContent('wf-2')
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()
  })

  it('table column headers are identical whether the drawer is open or closed', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )

    const headersBefore = screen
      .getAllByRole('columnheader')
      .map((h) => h.textContent)

    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.getByTestId('workflow-drawer')).toBeInTheDocument()

    const headersAfter = screen
      .getAllByRole('columnheader')
      .map((h) => h.textContent)

    expect(headersAfter).toEqual(headersBefore)
  })

  it('tab switching: clicking Schedule tab shows schedule pane and hides run pane', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.getByTestId('drawer-pane-run')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('drawer-tab-schedule'))
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
    expect(screen.getByTestId('drawer-pane-schedule')).toBeInTheDocument()
  })

  it('tab switching: clicking Preview tab shows preview pane', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-row'))
    fireEvent.click(screen.getByTestId('drawer-tab-preview'))
    expect(screen.getByTestId('drawer-pane-preview')).toBeInTheDocument()
    expect(screen.queryByTestId('drawer-pane-run')).toBeNull()
  })
})

// ── Delete confirm dialog ─────────────────────────────────────────────────────

describe('WorkflowListView — delete confirm dialog', () => {
  it('shows delete confirm dialog when delete button is clicked', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('delete-confirm-btn')).toBeInTheDocument()
  })

  it('dismisses delete dialog when Cancel is clicked', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('sends DELETE and refreshes list when delete confirmed', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-delete-btn'))

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ deleted: 'wf-1', versions: 1 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))

    fireEvent.click(screen.getByTestId('delete-confirm-btn'))

    await waitFor(() =>
      expect(screen.queryByRole('dialog')).toBeNull(),
    )
    expect(screen.queryByTestId('delete-error')).toBeNull()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
  })

  it('shows delete error notice when DELETE fails', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-delete-btn'))

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'workflow is referenced by a trigger' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('delete-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('delete-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('delete-error')).toHaveTextContent(
      /referenced by a trigger/i,
    )
    expect(screen.getByTestId('workflow-table')).toBeInTheDocument()
  })
})

// ── Error-card classification ─────────────────────────────────────────────────

describe('WorkflowListView — error-card classification', () => {
  it('shows server-error copy (not connectivity) for a 5xx response', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([], 500))
    renderWorkflowListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.queryByText(/check your connection/i)).toBeNull()
    expect(screen.getByText(/server.*error|returned an error/i)).toBeInTheDocument()
  })

  it('shows connectivity copy for a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderWorkflowListView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })
})

// ── Security (A9.1) ───────────────────────────────────────────────────────────

describe('WorkflowListView — security (A9.1)', () => {
  it('renders workflow name and description as plain text, not HTML', async () => {
    const xss = '<img src=x onerror="window.__xss=1">'
    fetchMock.mockResolvedValue(
      makeWorkflowListResponse([makeWorkflow({ name: xss, description: xss })]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    expect(screen.getAllByText(xss).length).toBeGreaterThan(0)
    expect((window as unknown as Record<string, unknown>).__xss).toBeUndefined()
  })

  it('renders workflow name in drawer as plain text, not HTML', async () => {
    const xss = '<img src=x onerror="window.__xss_list=1">'
    fetchMock.mockResolvedValue(
      makeWorkflowListResponse([makeWorkflow({ name: xss })]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.getByTestId('drawer-name')).toHaveTextContent(xss)
    expect((window as unknown as Record<string, unknown>).__xss_list).toBeUndefined()
  })
})
