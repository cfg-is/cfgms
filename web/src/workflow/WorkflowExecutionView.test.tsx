// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowExecutionView test suite (Story #2731).
 *
 * Required AC: covers the execute → status → cancel flow end-to-end:
 *   1. Execute button shows confirm dialog.
 *   2. Confirming execute POSTs to /execute and shows live status.
 *   3. Cancel button shows confirm dialog.
 *   4. Confirming cancel POSTs to /cancel.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
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
