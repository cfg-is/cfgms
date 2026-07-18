// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RollbackPanel test suite (Story #2730, AC: confirm-step gating).
 *
 * Key invariants tested:
 * 1. Execute API is never called without an explicit confirm step.
 * 2. The confirm dialog shows rollback-point details before committing.
 * 3. Cancelling the confirm dialog prevents execution.
 * 4. Confirm fires the execute API.
 * 5. History tab is reachable and shows operations.
 * 6. Preview is reachable and shows results.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RollbackPanel from './RollbackPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makePointsResponse(points: object[]) {
  return new Response(
    JSON.stringify({ rollback_points: points }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeHistoryResponse(ops: object[]) {
  return new Response(
    JSON.stringify({ rollback_operations: ops }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makePoint(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    commit_sha: 'abc123def456',
    timestamp: '2026-01-01T00:00:00Z',
    author: 'admin',
    message: 'Config update',
    configurations: ['sw-1'],
    risk_level: 'low',
    can_rollback: true,
    ...overrides,
  }
}

function makeOperation(id = 'rb-1') {
  return {
    id,
    target_type: 'steward',
    target_id: 'sw-1',
    rollback_type: 'full',
    rollback_to: 'abc123',
    status: 'completed',
    created_at: '2026-01-01T00:00:00Z',
    completed_at: '2026-01-01T00:01:00Z',
    reason: 'test rollback',
  }
}

function makePreviewResponse() {
  return new Response(
    JSON.stringify({ preview: { changes: [], affected_modules: [] } }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeExecuteResponse(id = 'rb-new-1') {
  return new Response(
    JSON.stringify({
      rollback: {
        id,
        status: 'in_progress',
        target_type: 'steward',
        target_id: 'sw-1',
      },
    }),
    { status: 202, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderRollbackPanel(stewardId = 'sw-1') {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RollbackPanel stewardId={stewardId} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('RollbackPanel — rendering', () => {
  it('shows rollback points tab and history tab', async () => {
    fetchMock.mockResolvedValue(makePointsResponse([]))
    renderRollbackPanel()
    expect(screen.getByRole('button', { name: /rollback points/i })).toBeInTheDocument()
    expect(screen.getByTestId('rb-history-tab')).toBeInTheDocument()
  })

  it('shows loading state while points are fetched', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRollbackPanel()
    expect(screen.getByTestId('rb-loading')).toBeInTheDocument()
  })

  it('shows empty state when no rollback points', async () => {
    fetchMock.mockResolvedValue(makePointsResponse([]))
    renderRollbackPanel()
    await waitFor(() => expect(screen.getByTestId('rb-empty-points')).toBeInTheDocument())
  })

  it('renders rollback point rows', async () => {
    fetchMock.mockResolvedValue(makePointsResponse([makePoint(), makePoint({ commit_sha: 'def456abc123' })]))
    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-point-row')).toHaveLength(2))
    expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(2)
    expect(screen.getAllByTestId('rb-preview-btn')).toHaveLength(2)
  })

  it('shows error state when points fetch fails', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderRollbackPanel()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })
})

describe('RollbackPanel — confirm-step gating (AC)', () => {
  it('does NOT fire execute API when Execute is clicked — shows confirm dialog first', async () => {
    fetchMock.mockResolvedValue(makePointsResponse([makePoint()]))
    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-execute-btn'))

    // Confirm dialog must appear
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    // Execute API must NOT have been called yet
    const executeCalls = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/api/v1/rollback/execute'),
    )
    expect(executeCalls).toHaveLength(0)
  })

  it('confirm dialog shows rollback point details', async () => {
    fetchMock.mockResolvedValue(
      makePointsResponse([makePoint({ message: 'Deploy v2.1', configurations: ['sw-1', 'sw-2'] })]),
    )
    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-execute-btn'))

    expect(screen.getByTestId('rb-confirm-point')).toBeInTheDocument()
    expect(screen.getByTestId('rb-confirm-point')).toHaveTextContent('Deploy v2.1')
    expect(screen.getByTestId('rb-confirm-point')).toHaveTextContent('2 configs affected')
  })

  it('cancelling the confirm dialog prevents the execute from firing', async () => {
    fetchMock.mockResolvedValue(makePointsResponse([makePoint()]))
    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-execute-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).toBeNull()

    // Execute API must never have been called
    const executeCalls = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/api/v1/rollback/execute'),
    )
    expect(executeCalls).toHaveLength(0)
  })

  it('fires the execute API only after Confirm rollback is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makePointsResponse([makePoint()]))
    fetchMock.mockResolvedValue(makeExecuteResponse())

    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-execute-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('rb-confirm-execute-btn'))

    await waitFor(() => {
      const executeCalls = fetchMock.mock.calls.filter(
        (c) => typeof c[0] === 'string' && (c[0] as string).includes('/api/v1/rollback/execute'),
      )
      expect(executeCalls).toHaveLength(1)
    })

    // Dialog closes after execution
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('shows execution result after successful execute', async () => {
    // useRollbackHistory fires on mount alongside useRollbackPoints;
    // give each a dedicated response so they don't consume each other.
    fetchMock.mockResolvedValueOnce(makePointsResponse([makePoint()]))
    fetchMock.mockResolvedValueOnce(makeHistoryResponse([]))
    fetchMock.mockResolvedValueOnce(makeExecuteResponse('rb-new-999'))

    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-execute-btn'))
    fireEvent.click(screen.getByTestId('rb-confirm-execute-btn'))

    await waitFor(() => expect(screen.getByTestId('rb-execute-result')).toBeInTheDocument())
  })

  it('shows error when execute API returns non-ok', async () => {
    fetchMock.mockResolvedValueOnce(makePointsResponse([makePoint()]))
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'approval required' }), {
        status: 412,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-execute-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-execute-btn'))
    fireEvent.click(screen.getByTestId('rb-confirm-execute-btn'))

    await waitFor(() => expect(screen.getByTestId('rb-execute-error')).toBeInTheDocument())
    expect(screen.getByTestId('rb-execute-error')).toHaveTextContent('approval required')
  })
})

describe('RollbackPanel — preview', () => {
  it('shows preview result after Preview is clicked', async () => {
    // useRollbackHistory fires on mount; give it a dedicated response.
    fetchMock.mockResolvedValueOnce(makePointsResponse([makePoint()]))
    fetchMock.mockResolvedValueOnce(makeHistoryResponse([]))
    fetchMock.mockResolvedValueOnce(makePreviewResponse())

    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-preview-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-preview-btn'))

    await waitFor(() => expect(screen.getByTestId('rb-preview-result')).toBeInTheDocument())
  })

  it('shows error when preview fails', async () => {
    fetchMock.mockResolvedValueOnce(makePointsResponse([makePoint()]))
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderRollbackPanel()
    await waitFor(() => expect(screen.getAllByTestId('rb-preview-btn')).toHaveLength(1))

    fireEvent.click(screen.getByTestId('rb-preview-btn'))

    await waitFor(() => expect(screen.getByTestId('rb-preview-error')).toBeInTheDocument())
  })
})

describe('RollbackPanel — history tab', () => {
  it('shows history table when History tab is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makePointsResponse([]))
    fetchMock.mockResolvedValue(makeHistoryResponse([makeOperation()]))

    renderRollbackPanel()
    await waitFor(() => expect(screen.getByTestId('rb-empty-points')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('rb-history-tab'))

    await waitFor(() => expect(screen.getByTestId('rb-history-table')).toBeInTheDocument())
    expect(screen.getByTestId('rb-history-row')).toBeInTheDocument()
  })

  it('shows empty state when no history operations', async () => {
    fetchMock.mockResolvedValueOnce(makePointsResponse([]))
    fetchMock.mockResolvedValue(makeHistoryResponse([]))

    renderRollbackPanel()
    await waitFor(() => expect(screen.getByTestId('rb-empty-points')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('rb-history-tab'))

    await waitFor(() => expect(screen.getByTestId('rb-empty-history')).toBeInTheDocument())
  })
})
