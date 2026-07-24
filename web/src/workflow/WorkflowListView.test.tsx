// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowListView test suite (Stories #2731, #2984): list rendering, data
 * states, create panel toggle, trigger panel toggle, delete confirm, and the
 * structured step/variable authoring path (Story #2984).
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
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
    steps: [{ name: 'step-1', type: 'script', config: {} }],
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

  it('shows validation error when a step has an empty name', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-create-btn'))
    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'bad-wf' },
    })
    // Clear the step name to trigger validation
    fireEvent.change(screen.getByTestId('step-name-input'), {
      target: { value: '' },
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

// ── Story #2984: structured step builder ─────────────────────────────────────

async function openCreatePanel() {
  fetchMock.mockResolvedValue(makeWorkflowListResponse([]))
  renderWorkflowListView()
  await waitFor(() =>
    expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
  )
  fireEvent.click(screen.getByTestId('toggle-create-btn'))
  expect(screen.getByTestId('workflow-form-panel')).toBeInTheDocument()
}

describe('WorkflowListView — structured step builder (Story #2984)', () => {
  it('shows one step row with name input and type select by default', async () => {
    await openCreatePanel()
    expect(screen.getAllByTestId('step-row')).toHaveLength(1)
    expect(screen.getByTestId('step-name-input')).toBeInTheDocument()
    expect(screen.getByTestId('step-type-select')).toBeInTheDocument()
  })

  it('default step type is script and shows script body input', async () => {
    await openCreatePanel()
    const typeSelect = screen.getByTestId('step-type-select') as HTMLSelectElement
    expect(typeSelect.value).toBe('script')
    expect(screen.getByTestId('step-script-input')).toBeInTheDocument()
  })

  it('does not show remove button when only one step exists', async () => {
    await openCreatePanel()
    expect(screen.queryByTestId('step-remove-btn')).toBeNull()
  })

  it('Add step button adds a second step row', async () => {
    await openCreatePanel()
    fireEvent.click(screen.getByTestId('add-step-btn'))
    expect(screen.getAllByTestId('step-row')).toHaveLength(2)
    expect(screen.getAllByTestId('step-name-input')).toHaveLength(2)
  })

  it('shows remove button on each row when multiple steps exist', async () => {
    await openCreatePanel()
    fireEvent.click(screen.getByTestId('add-step-btn'))
    expect(screen.getAllByTestId('step-remove-btn')).toHaveLength(2)
  })

  it('Remove step button removes that row', async () => {
    await openCreatePanel()
    fireEvent.click(screen.getByTestId('add-step-btn'))
    expect(screen.getAllByTestId('step-row')).toHaveLength(2)

    const removeBtns = screen.getAllByTestId('step-remove-btn')
    fireEvent.click(removeBtns[0])
    expect(screen.getAllByTestId('step-row')).toHaveLength(1)
  })

  it('editing an existing workflow loads its step rows into the builder', async () => {
    fetchMock.mockResolvedValueOnce(
      makeWorkflowListResponse([
        makeWorkflow({
          name: 'wf-1',
          steps: [
            { name: 'step-a', type: 'script', config: { script: 'echo a' } },
            { name: 'step-b', type: 'script', config: {} },
          ],
        }),
      ]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-edit-btn'))

    const nameInputs = screen.getAllByTestId('step-name-input') as HTMLInputElement[]
    expect(nameInputs).toHaveLength(2)
    expect(nameInputs[0].value).toBe('step-a')
    expect(nameInputs[1].value).toBe('step-b')
  })

  it('script step script-body field is pre-populated from existing config.script', async () => {
    fetchMock.mockResolvedValueOnce(
      makeWorkflowListResponse([
        makeWorkflow({
          steps: [{ name: 'run', type: 'script', config: { script: 'echo hello' } }],
        }),
      ]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-edit-btn'))

    const scriptInput = screen.getByTestId('step-script-input') as HTMLTextAreaElement
    expect(scriptInput.value).toBe('echo hello')
  })

  it('submit sends correct body shape with structured steps — no hand-written JSON', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-create-btn'))

    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'my-wf' },
    })
    fireEvent.change(screen.getByTestId('step-name-input'), {
      target: { value: 'run-task' },
    })
    fireEvent.change(screen.getByTestId('step-script-input'), {
      target: { value: 'echo done' },
    })

    let capturedBody: Record<string, unknown> | null = null
    fetchMock.mockImplementationOnce((_url: RequestInfo | URL, opts?: RequestInit): Promise<Response> => {
      capturedBody = JSON.parse((opts?.body as string) ?? '{}') as Record<string, unknown>
      return Promise.resolve(
        new Response(
          JSON.stringify({ name: 'my-wf', steps: [], semantic_version: {}, version: '1.0.0', description: '' }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    })
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow({ name: 'my-wf' })]))

    fireEvent.click(screen.getByTestId('workflow-save-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('workflow-form-panel')).toBeNull(),
    )
    expect(capturedBody).not.toBeNull()
    expect(capturedBody).toMatchObject({
      name: 'my-wf',
      steps: [{ name: 'run-task', type: 'script', config: { script: 'echo done' } }],
    })
    expect(capturedBody).not.toHaveProperty('steps[0].stepsJson')
  })
})

// ── Story #2984: variables key/value row editor ───────────────────────────────

describe('WorkflowListView — variables editor (Story #2984)', () => {
  it('shows no variable rows by default in create form', async () => {
    await openCreatePanel()
    expect(screen.queryByTestId('var-row')).toBeNull()
  })

  it('Add variable button adds a key/value row', async () => {
    await openCreatePanel()
    fireEvent.click(screen.getByTestId('add-var-btn'))
    expect(screen.getAllByTestId('var-row')).toHaveLength(1)
    expect(screen.getByTestId('var-key-input')).toBeInTheDocument()
    expect(screen.getByTestId('var-value-input')).toBeInTheDocument()
  })

  it('Remove variable button removes that row', async () => {
    await openCreatePanel()
    fireEvent.click(screen.getByTestId('add-var-btn'))
    expect(screen.getAllByTestId('var-row')).toHaveLength(1)
    fireEvent.click(screen.getByTestId('var-remove-btn'))
    expect(screen.queryByTestId('var-row')).toBeNull()
  })

  it('multiple variable rows can be added and individually removed', async () => {
    await openCreatePanel()
    fireEvent.click(screen.getByTestId('add-var-btn'))
    fireEvent.click(screen.getByTestId('add-var-btn'))
    expect(screen.getAllByTestId('var-row')).toHaveLength(2)

    const removeBtns = screen.getAllByTestId('var-remove-btn')
    fireEvent.click(removeBtns[0])
    expect(screen.getAllByTestId('var-row')).toHaveLength(1)
  })

  it('submit with variables sends the correct variables object shape', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-create-btn'))

    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'var-wf' },
    })
    fireEvent.change(screen.getByTestId('step-name-input'), {
      target: { value: 'step-1' },
    })

    fireEvent.click(screen.getByTestId('add-var-btn'))
    fireEvent.click(screen.getByTestId('add-var-btn'))

    const keyInputs = screen.getAllByTestId('var-key-input') as HTMLInputElement[]
    const valInputs = screen.getAllByTestId('var-value-input') as HTMLInputElement[]
    fireEvent.change(keyInputs[0], { target: { value: 'ENV' } })
    fireEvent.change(valInputs[0], { target: { value: 'production' } })
    fireEvent.change(keyInputs[1], { target: { value: 'TIMEOUT' } })
    fireEvent.change(valInputs[1], { target: { value: '30' } })

    let capturedBody: Record<string, unknown> | null = null
    fetchMock.mockImplementationOnce((_url: RequestInfo | URL, opts?: RequestInit): Promise<Response> => {
      capturedBody = JSON.parse((opts?.body as string) ?? '{}') as Record<string, unknown>
      return Promise.resolve(
        new Response(
          JSON.stringify({ name: 'var-wf', steps: [], semantic_version: {}, version: '1.0.0', description: '' }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    })
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow({ name: 'var-wf' })]))

    fireEvent.click(screen.getByTestId('workflow-save-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('workflow-form-panel')).toBeNull(),
    )
    expect(capturedBody).toMatchObject({
      variables: { ENV: 'production', TIMEOUT: '30' },
    })
  })

  it('editing a workflow with variables pre-populates the variable rows', async () => {
    fetchMock.mockResolvedValueOnce(
      makeWorkflowListResponse([
        makeWorkflow({ variables: { FOO: 'bar', BAZ: '42' } }),
      ]),
    )
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-table')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('workflow-edit-btn'))

    const keyInputs = screen.getAllByTestId('var-key-input') as HTMLInputElement[]
    const valInputs = screen.getAllByTestId('var-value-input') as HTMLInputElement[]
    expect(keyInputs).toHaveLength(2)
    // Keys may be in any order depending on Object.entries order
    const pairs = keyInputs.map((k, i) => `${k.value}=${valInputs[i].value}`)
    expect(pairs).toContain('FOO=bar')
    expect(pairs).toContain('BAZ=42')
  })

  it('variables rows omitted from submit body when all keys are empty', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([]))
    renderWorkflowListView()
    await waitFor(() =>
      expect(screen.getByTestId('workflow-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-create-btn'))

    fireEvent.change(screen.getByTestId('workflow-name-input'), {
      target: { value: 'no-vars-wf' },
    })
    fireEvent.change(screen.getByTestId('step-name-input'), {
      target: { value: 'step-1' },
    })

    // Add a var row but leave key empty
    fireEvent.click(screen.getByTestId('add-var-btn'))

    let capturedBody: Record<string, unknown> | null = null
    fetchMock.mockImplementationOnce((_url: RequestInfo | URL, opts?: RequestInit): Promise<Response> => {
      capturedBody = JSON.parse((opts?.body as string) ?? '{}') as Record<string, unknown>
      return Promise.resolve(
        new Response(
          JSON.stringify({ name: 'no-vars-wf', steps: [], semantic_version: {}, version: '1.0.0', description: '' }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    })
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow({ name: 'no-vars-wf' })]))

    fireEvent.click(screen.getByTestId('workflow-save-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('workflow-form-panel')).toBeNull(),
    )
    expect(capturedBody).not.toHaveProperty('variables')
  })
})
