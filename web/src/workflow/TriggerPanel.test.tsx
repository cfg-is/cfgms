// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TriggerPanel test suite (Story #2731): trigger list rendering, data states,
 * create form, and delete confirm dialog.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import TriggerPanel from './TriggerPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeTriggersResponse(triggers: object[], status = 200) {
  return new Response(
    JSON.stringify({ triggers, count: triggers.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeTrigger(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'trig-1',
    name: 'Daily sync',
    type: 'schedule',
    status: 'active',
    workflow_name: 'wf-1',
    ...overrides,
  }
}

function renderTriggerPanel() {
  const onClose = vi.fn()
  const result = render(
    <MemoryRouter>
      <AuthProvider>
        <TriggerPanel onClose={onClose} />
      </AuthProvider>
    </MemoryRouter>,
  )
  return { ...result, onClose }
}

describe('TriggerPanel — data states', () => {
  it('shows loading state while fetching triggers', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderTriggerPanel()
    expect(screen.getByTestId('trigger-loading')).toBeInTheDocument()
  })

  it('shows empty state when no triggers exist', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )
  })

  it('shows error notice when request fails', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([], 500))
    renderTriggerPanel()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('renders a table with trigger rows', async () => {
    fetchMock.mockResolvedValue(
      makeTriggersResponse([makeTrigger(), makeTrigger({ id: 'trig-2', name: 'Weekly report' })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )
    expect(screen.getAllByTestId('trigger-row')).toHaveLength(2)
    expect(screen.getByText('Daily sync')).toBeInTheDocument()
    expect(screen.getByText('Weekly report')).toBeInTheDocument()
  })
})

describe('TriggerPanel — create form', () => {
  it('shows create form when New trigger is clicked', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))
    expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument()
    expect(screen.getByTestId('trigger-name-input')).toBeInTheDocument()
  })

  it('hides create form when toggled off', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))
    expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))
    expect(screen.queryByTestId('trigger-create-form')).toBeNull()
  })

  it('shows validation error when name is missing', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))
    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))
    expect(screen.getByTestId('trigger-create-error')).toBeInTheDocument()
    expect(screen.getByTestId('trigger-create-error')).toHaveTextContent(/name is required/i)
  })

  it('submits create form and refreshes list on success', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))

    fireEvent.change(screen.getByTestId('trigger-name-input'), {
      target: { value: 'new-trigger' },
    })
    fireEvent.change(screen.getByTestId('trigger-workflow-input'), {
      target: { value: 'wf-1' },
    })

    // Mock create response + list refresh
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(makeTrigger({ name: 'new-trigger' })), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ name: 'new-trigger' })]),
    )

    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('trigger-create-form')).toBeNull(),
    )
  })
})

describe('TriggerPanel — delete confirm', () => {
  it('shows delete confirm dialog when delete button is clicked', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('trigger-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('trigger-delete-confirm-btn')).toBeInTheDocument()
  })

  it('dismisses delete dialog when Cancel is clicked', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('trigger-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('sends DELETE and refreshes list when confirmed', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('trigger-delete-btn'))

    // Queue DELETE + list-refresh responses before confirming (confirm fires fetch immediately)
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ message: 'Trigger deleted successfully', trigger_id: 'trig-1' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([]))

    fireEvent.click(screen.getByTestId('trigger-delete-confirm-btn'))

    await waitFor(() =>
      expect(screen.queryByRole('dialog')).toBeNull(),
    )
  })

  it('shows delete error notice when DELETE fails', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('trigger-delete-btn'))

    // Server rejects the delete with a 500 and an error body.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'trigger is locked' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-delete-confirm-btn'))

    // Dialog closes optimistically, then the error notice surfaces.
    await waitFor(() =>
      expect(screen.getByTestId('trigger-delete-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-delete-error')).toHaveTextContent(
      /trigger is locked/i,
    )
    // The trigger row remains since the delete did not take effect.
    expect(screen.getByTestId('trigger-table')).toBeInTheDocument()
  })
})

describe('TriggerPanel — close', () => {
  it('calls onClose when close button is clicked', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    const { onClose } = renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByRole('button', { name: /close triggers/i }))
    expect(onClose).toHaveBeenCalledOnce()
  })
})

describe('TriggerPanel — security (A9.1)', () => {
  it('renders trigger name and workflow as plain text, not HTML', async () => {
    const xss = '<img src=x onerror="window.__xssTrigger=1">'
    fetchMock.mockResolvedValue(
      makeTriggersResponse([makeTrigger({ name: xss, workflow_name: xss })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )
    expect(screen.getAllByText(xss).length).toBeGreaterThan(0)
    expect(
      (window as unknown as Record<string, unknown>).__xssTrigger,
    ).toBeUndefined()
  })
})
