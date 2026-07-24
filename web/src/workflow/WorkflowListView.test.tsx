// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowListView test suite (Story #2731): list rendering, data states,
 * create panel toggle, trigger panel toggle, and delete confirm.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
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
    steps: [{ name: 'step-1', type: 'script' }],
    semantic_version: { major: 1, minor: 0, patch: 0, pre_release: '', build_meta: '' },
    ...overrides,
  }
}

function makeTriggersResponse(triggers: object[], status = 200) {
  return new Response(
    JSON.stringify({ triggers, count: triggers.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeExecutionsResponse(executions: object[], status = 200) {
  return new Response(
    JSON.stringify({ executions, count: executions.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderWorkflowListView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <WorkflowListView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('WorkflowListView — heading and page structure', () => {
  it('shows the Workflows heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderWorkflowListView()
    expect(
      screen.getByRole('heading', { name: /workflows/i, level: 1 }),
    ).toBeInTheDocument()
  })

  it('shows the New workflow and Triggers buttons', () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
    renderWorkflowListView()
    expect(screen.getByTestId('toggle-create-btn')).toBeInTheDocument()
    expect(screen.getByTestId('toggle-triggers-btn')).toBeInTheDocument()
  })
})

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

describe('WorkflowListView — create panel', () => {
  it('shows create panel when New workflow is clicked', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('workflow-form-panel')).toBeInTheDocument()
    expect(screen.getByTestId('workflow-name-input')).toBeInTheDocument()
  })

  it('hides create panel when toggled off', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.getByTestId('workflow-form-panel')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    expect(screen.queryByTestId('workflow-form-panel')).toBeNull()
  })

  it('submits create form via POST and refreshes list', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-create-btn'))

    // Fill in form
    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'new-workflow' },
    })

    // Mock create response + list refresh
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ name: 'new-workflow', steps: [{ name: 's1', type: 'script' }], semantic_version: {}, version: '1.0.0', description: '' }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    fetchMock.mockResolvedValueOnce(
      makeWorkflowListResponse([makeWorkflow({ name: 'new-workflow' })]),
    )

    fireEvent.click(screen.getByTestId('workflow-save-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('workflow-form-panel')).toBeNull(),
    )
  })

  it('shows validation error when steps JSON is invalid', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'bad-wf' },
    })
    fireEvent.change(screen.getByTestId('workflow-steps-input'), {
      target: { value: 'not-json' },
    })
    fireEvent.click(screen.getByTestId('workflow-save-btn'))
    expect(screen.getByTestId('workflow-save-error')).toBeInTheDocument()
  })

  it('shows server error and keeps panel open when create POST fails', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'dup-workflow' },
    })

    // Server rejects the create with a 409 and an error body.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'workflow already exists' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('workflow-save-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('workflow-save-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('workflow-save-error')).toHaveTextContent(
      /workflow already exists/i,
    )
    // Panel stays open so the user can correct and retry.
    expect(screen.getByTestId('workflow-form-panel')).toBeInTheDocument()
  })

  it('shows server error when edit PUT fails', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow()]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('workflow-edit-btn'))
    expect(screen.getByTestId('workflow-form-panel')).toBeInTheDocument()

    // Server rejects the update with a 500 (no parseable error body → status message).
    fetchMock.mockResolvedValueOnce(
      new Response('internal error', { status: 500 }),
    )

    fireEvent.click(screen.getByTestId('workflow-save-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('workflow-save-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('workflow-save-error')).toHaveTextContent(/500/)
    expect(screen.getByTestId('workflow-form-panel')).toBeInTheDocument()
  })
})

describe('WorkflowListView — row actions', () => {
  it('opens execution view when a row is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow()]))
    // Mock the execution view's fetch
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))

    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('workflow-row'))
    await waitFor(() =>
      expect(screen.getByTestId('workflow-exec-panel')).toBeInTheDocument(),
    )
  })

  it('closes execution view when same row is clicked again', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow()]))
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))

    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('workflow-row'))
    await waitFor(() =>
      expect(screen.getByTestId('workflow-exec-panel')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('workflow-row'))
    expect(screen.queryByTestId('workflow-exec-panel')).toBeNull()
  })

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

    // Queue DELETE + list-refresh responses before confirming (confirm fires fetch immediately)
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
    // The DELETE succeeded, so no error notice surfaces and the refreshed
    // list renders the empty state.
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

    // Server rejects the delete with a 403 and an error body.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'workflow is referenced by a trigger' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('delete-confirm-btn'))

    // Dialog closes optimistically, then the error notice surfaces.
    await waitFor(() =>
      expect(screen.getByTestId('delete-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('delete-error')).toHaveTextContent(
      /referenced by a trigger/i,
    )
    // The workflow row remains since the delete did not take effect.
    expect(screen.getByTestId('workflow-table')).toBeInTheDocument()
  })
})

describe('WorkflowListView — trigger panel', () => {
  it('shows trigger panel when Triggers is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    fetchMock.mockResolvedValue(makeTriggersResponse([]))

    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-triggers-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('trigger-panel')).toBeInTheDocument(),
    )
  })

  it('hides trigger panel when toggled off', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    fetchMock.mockResolvedValue(makeTriggersResponse([]))

    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-triggers-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('trigger-panel')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-triggers-btn'))
    expect(screen.queryByTestId('trigger-panel')).toBeNull()
  })
})

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
})
