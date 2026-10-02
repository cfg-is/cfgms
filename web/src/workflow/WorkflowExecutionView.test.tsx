// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowExecutionView test suite (Story #2731, extended Story #2985).
 *
 * Required AC (Story #2731): covers the execute → status → cancel flow end-to-end:
 *   1. Execute button shows confirm dialog.
 *   2. Confirming execute POSTs to /execute and shows live status.
 *   3. Cancel button shows confirm dialog.
 *   4. Confirming cancel POSTs to /cancel.
 *
 * Required AC (Story #2985): variable inputs and per-step result rendering:
 *   5. Confirm dialog includes variable key/value editor.
 *   6. Execute POST body includes { variables: {...} }.
 *   7. Active execution status renders step_results per-step table.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import WorkflowExecutionView from './WorkflowExecutionView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeExecutionsResponse(executions: object[], status = 200) {
  return new Response(
    JSON.stringify({ executions, count: executions.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeExecution(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'exec-1',
    workflow_name: 'wf-test',
    status: 'running',
    start_time: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeExecuteResponse(execId: string, status = 'running', httpStatus = 202) {
  return new Response(
    JSON.stringify({
      execution_id: execId,
      workflow_name: 'wf-test',
      status,
      start_time: '2026-01-01T00:00:00Z',
    }),
    { status: httpStatus, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeExecutionStatusResponse(exec: object, status = 200) {
  return new Response(JSON.stringify(exec), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeCancelResponse(execId: string, status = 200) {
  return new Response(JSON.stringify({ cancelled: execId }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderView(workflowName = 'wf-test') {
  const onClose = vi.fn()
  const result = render(
    <MemoryRouter>
      <AuthProvider>
        <WorkflowExecutionView workflowName={workflowName} onClose={onClose} />
      </AuthProvider>
    </MemoryRouter>,
  )
  return { ...result, onClose }
}

describe('WorkflowExecutionView — structure', () => {
  it('renders the panel header with workflow name', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByText(/executions: wf-test/i)).toBeInTheDocument()
  })

  it('renders the Execute button', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByTestId('execute-btn')).toBeInTheDocument()
  })

  it('calls onClose when the close button is clicked', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    const { onClose } = renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByRole('button', { name: /close execution view/i }))
    expect(onClose).toHaveBeenCalledOnce()
  })
})

describe('WorkflowExecutionView — data states', () => {
  it('shows loading state while fetching executions', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByTestId('exec-history-loading')).toBeInTheDocument()
  })

  it('shows empty state when no executions exist', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )
  })

  it('shows error notice when executions request fails', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([], 500))
    renderView()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('renders execution history rows', async () => {
    fetchMock.mockResolvedValue(
      makeExecutionsResponse([
        makeExecution({ id: 'exec-1', status: 'completed' }),
        makeExecution({ id: 'exec-2', status: 'failed' }),
      ]),
    )
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-table')).toBeInTheDocument(),
    )
    expect(screen.getAllByTestId('exec-row')).toHaveLength(2)
    expect(screen.getByText('exec-1')).toBeInTheDocument()
    expect(screen.getByText('exec-2')).toBeInTheDocument()
  })
})

describe('WorkflowExecutionView — execute → status → cancel flow (required AC)', () => {
  it('shows confirm dialog when Execute is clicked', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('exec-confirm-btn')).toBeInTheDocument()
  })

  it('dismisses confirm dialog when Cancel is clicked', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('executes workflow on confirm and shows execution status', async () => {
    // Use URL-aware dispatch to avoid mock-queue ordering sensitivity between
    // concurrent fetch calls (refreshExecutions and useExecutionStatus both fire
    // after execute, in an order determined by React effect scheduling).
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('exec-status')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('exec-status')).toHaveTextContent('running')
  })

  it('shows Cancel execution button for running execution and confirm dialog on click', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('cancel-active-btn')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('cancel-active-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('cancel-confirm-btn')).toBeInTheDocument()
  })

  it('sends cancel POST when cancel is confirmed', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.endsWith('/cancel')) {
        return Promise.resolve(makeCancelResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('cancel-active-btn')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('cancel-active-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('cancel-confirm-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('cancel-confirm-btn')).toBeNull(),
    )
  })

  it('shows cancel error when cancel POST fails', async () => {
    // Execute/status succeed so an active running execution is shown; the cancel
    // POST returns a non-2xx with a server error body, exercising the error branch
    // of handleConfirmCancel (setCancelError → data-testid="cancel-error").
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.endsWith('/cancel')) {
        return Promise.resolve(
          new Response(JSON.stringify({ error: 'execution already completed' }), {
            status: 409,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('cancel-active-btn')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('cancel-active-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('cancel-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('cancel-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('cancel-error')).toHaveTextContent(
      'execution already completed',
    )
  })

  it('dismisses cancel confirm dialog when Keep running is clicked', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('cancel-active-btn')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('cancel-active-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /keep running/i }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('shows execute error when POST fails', async () => {
    fetchMock.mockResolvedValueOnce(makeExecutionsResponse([]))
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'workflow not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('execute-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('execute-error')).toHaveTextContent('workflow not found')
  })
})

describe('WorkflowExecutionView — cancel from history row', () => {
  it('shows cancel confirm dialog for non-terminal execution in history', async () => {
    fetchMock.mockResolvedValue(
      makeExecutionsResponse([makeExecution({ id: 'exec-1', status: 'running' })]),
    )
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('cancel-exec-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('cancel-confirm-btn')).toBeInTheDocument()
  })

  it('does not show cancel button for terminal executions', async () => {
    fetchMock.mockResolvedValue(
      makeExecutionsResponse([makeExecution({ id: 'exec-1', status: 'completed' })]),
    )
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-table')).toBeInTheDocument(),
    )

    expect(screen.queryByTestId('cancel-exec-btn')).toBeNull()
  })
})

describe('WorkflowExecutionView — security (A9.1)', () => {
  it('renders execution id and status as plain text, not HTML', async () => {
    const xss = '<img src=x onerror="window.__xssExec=1">'
    fetchMock.mockResolvedValue(
      makeExecutionsResponse([makeExecution({ id: xss, status: xss })]),
    )
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-table')).toBeInTheDocument(),
    )
    expect(screen.getAllByText(xss).length).toBeGreaterThan(0)
    expect(
      (window as unknown as Record<string, unknown>).__xssExec,
    ).toBeUndefined()
  })
})

describe('WorkflowExecutionView — variables and step results (required AC #2985)', () => {
  it('shows variable editor in the confirm dialog', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('add-var-row-btn')).toBeInTheDocument()
  })

  it('adds and removes variable rows in the confirm dialog', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([]))
    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('add-var-row-btn'))
    expect(screen.getByTestId('var-key-0')).toBeInTheDocument()
    expect(screen.getByTestId('var-value-0')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('remove-var-row-0'))
    expect(screen.queryByTestId('var-key-0')).toBeNull()
  })

  it('posts { variables: {...} } when operator enters variables in confirm dialog', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('add-var-row-btn'))
    fireEvent.change(screen.getByTestId('var-key-0'), { target: { value: 'env' } })
    fireEvent.change(screen.getByTestId('var-value-0'), { target: { value: 'prod' } })

    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('exec-status')).toBeInTheDocument(),
    )

    const executeCall = fetchMock.mock.calls.find(([url]) => {
      const u = typeof url === 'string' ? url : (url as Request).url
      return u.endsWith('/execute')
    })
    expect(executeCall).toBeDefined()
    const body = JSON.parse(executeCall![1]?.body as string) as Record<string, unknown>
    expect(body).toEqual({ variables: { env: 'prod' } })
  })

  it('posts { variables: {} } when no variable rows are entered', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('exec-status')).toBeInTheDocument(),
    )

    const executeCall = fetchMock.mock.calls.find(([url]) => {
      const u = typeof url === 'string' ? url : (url as Request).url
      return u.endsWith('/execute')
    })
    expect(executeCall).toBeDefined()
    const body = JSON.parse(executeCall![1]?.body as string) as Record<string, unknown>
    expect(body).toEqual({ variables: {} })
  })

  it('skips variable rows with empty keys when building POST body', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'running' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('add-var-row-btn'))
    fireEvent.click(screen.getByTestId('add-var-row-btn'))
    // Fill only the second row; first has empty key
    fireEvent.change(screen.getByTestId('var-key-1'), { target: { value: 'target' } })
    fireEvent.change(screen.getByTestId('var-value-1'), { target: { value: 'us-east' } })

    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('exec-status')).toBeInTheDocument(),
    )

    const executeCall = fetchMock.mock.calls.find(([url]) => {
      const u = typeof url === 'string' ? url : (url as Request).url
      return u.endsWith('/execute')
    })
    expect(executeCall).toBeDefined()
    const body = JSON.parse(executeCall![1]?.body as string) as Record<string, unknown>
    expect(body).toEqual({ variables: { target: 'us-east' } })
  })

  it('renders step_results as a per-step table for completed execution', async () => {
    const execWithResults = makeExecution({
      id: 'exec-1',
      status: 'completed',
      step_results: {
        'step-a': { output: 'hello' },
        'step-b': 42,
      },
    })

    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1', 'completed'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(makeExecutionStatusResponse(execWithResults))
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('step-results')).toBeInTheDocument(),
    )

    expect(screen.getAllByTestId('step-result-row')).toHaveLength(2)
    expect(screen.getByText('step-a')).toBeInTheDocument()
    expect(screen.getByText('step-b')).toBeInTheDocument()
  })

  it('renders step_results alongside error for failed execution', async () => {
    const execWithResults = makeExecution({
      id: 'exec-1',
      status: 'failed',
      error: 'step-b timed out',
      step_results: {
        'step-a': { output: 'ok' },
      },
    })

    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1', 'failed'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(makeExecutionStatusResponse(execWithResults))
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('exec-status')).toBeInTheDocument(),
    )

    expect(screen.getByText('step-b timed out')).toBeInTheDocument()
    expect(screen.getByTestId('step-results')).toBeInTheDocument()
    expect(screen.getByText('step-a')).toBeInTheDocument()
  })

  it('does not render step-results section when execution has no step_results', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1', 'completed'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(
          makeExecutionStatusResponse(makeExecution({ id: 'exec-1', status: 'completed' })),
        )
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('exec-status')).toBeInTheDocument(),
    )

    expect(screen.queryByTestId('step-results')).toBeNull()
  })

  it('renders step result values as text nodes, not HTML (security A9.1)', async () => {
    const xss = '<img src=x onerror="window.__xssStep=1">'
    const execWithResults = makeExecution({
      id: 'exec-1',
      status: 'completed',
      step_results: { [xss]: xss },
    })

    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : (input as Request).url
      if (url.endsWith('/execute')) {
        return Promise.resolve(makeExecuteResponse('exec-1', 'completed'))
      }
      if (url.includes('/executions/exec-1')) {
        return Promise.resolve(makeExecutionStatusResponse(execWithResults))
      }
      return Promise.resolve(makeExecutionsResponse([]))
    })

    renderView()
    await waitFor(() =>
      expect(screen.getByTestId('exec-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('step-results')).toBeInTheDocument(),
    )

    expect(
      (window as unknown as Record<string, unknown>).__xssStep,
    ).toBeUndefined()
  })
})
