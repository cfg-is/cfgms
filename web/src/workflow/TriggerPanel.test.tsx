// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * TriggerPanel test suite (Story #2731, Story #2986): trigger list rendering,
 * data states, create form, delete confirm dialog, schedule/webhook config
 * fields, edit form, and enable/disable toggle.
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

  it('surfaces server error when create POST returns non-ok', async () => {
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

    // Server rejects the create with a 409 and an error body.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'trigger name already exists' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('trigger-create-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-create-error')).toHaveTextContent(
      /trigger name already exists/i,
    )
    // The form stays open so the user can correct and retry.
    expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument()
  })
})

describe('TriggerPanel — schedule/webhook fields', () => {
  it('reveals cron expression input when type is schedule', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))

    // Default type is manual — no schedule input
    expect(screen.queryByTestId('trigger-schedule-expression-input')).toBeNull()

    // Switch to schedule type
    fireEvent.change(screen.getByTestId('trigger-type-select'), {
      target: { value: 'schedule' },
    })

    expect(screen.getByTestId('trigger-schedule-expression-input')).toBeInTheDocument()
  })

  it('reveals webhook path input when type is webhook', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))

    expect(screen.queryByTestId('trigger-webhook-path-input')).toBeNull()

    fireEvent.change(screen.getByTestId('trigger-type-select'), {
      target: { value: 'webhook' },
    })

    expect(screen.getByTestId('trigger-webhook-path-input')).toBeInTheDocument()
  })

  it('includes schedule cron expression in create POST body', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))

    fireEvent.change(screen.getByTestId('trigger-name-input'), {
      target: { value: 'my-schedule' },
    })
    fireEvent.change(screen.getByTestId('trigger-workflow-input'), {
      target: { value: 'wf-1' },
    })
    fireEvent.change(screen.getByTestId('trigger-type-select'), {
      target: { value: 'schedule' },
    })
    fireEvent.change(screen.getByTestId('trigger-schedule-expression-input'), {
      target: { value: '0 * * * *' },
    })

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(makeTrigger({ type: 'schedule' })), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([]))

    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('trigger-create-form')).toBeNull(),
    )

    const postCall = fetchMock.mock.calls.find(
      ([url, opts]) =>
        typeof url === 'string' &&
        url === '/api/v1/triggers' &&
        (opts as RequestInit)?.method === 'POST',
    )
    expect(postCall).toBeDefined()
    const body = JSON.parse((postCall![1] as RequestInit).body as string) as Record<string, unknown>
    expect((body.schedule as Record<string, unknown>)?.cron_expression).toBe('0 * * * *')
  })

  it('includes webhook path in create POST body', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-empty')).toBeInTheDocument(),
    )

    fireEvent.click(screen.getByTestId('toggle-trigger-create-btn'))

    fireEvent.change(screen.getByTestId('trigger-name-input'), {
      target: { value: 'my-webhook' },
    })
    fireEvent.change(screen.getByTestId('trigger-workflow-input'), {
      target: { value: 'wf-1' },
    })
    fireEvent.change(screen.getByTestId('trigger-type-select'), {
      target: { value: 'webhook' },
    })
    fireEvent.change(screen.getByTestId('trigger-webhook-path-input'), {
      target: { value: '/hooks/deploy' },
    })

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(makeTrigger({ type: 'webhook' })), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([]))

    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('trigger-create-form')).toBeNull(),
    )

    const postCall = fetchMock.mock.calls.find(
      ([url, opts]) =>
        typeof url === 'string' &&
        url === '/api/v1/triggers' &&
        (opts as RequestInit)?.method === 'POST',
    )
    expect(postCall).toBeDefined()
    const body = JSON.parse((postCall![1] as RequestInit).body as string) as Record<string, unknown>
    expect((body.webhook as Record<string, unknown>)?.path).toBe('/hooks/deploy')
  })
})

describe('TriggerPanel — edit', () => {
  it('shows edit form pre-filled when edit button is clicked', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([
        makeTrigger({ type: 'schedule', schedule: { cron_expression: '0 * * * *' } }),
      ]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    // GET /triggers/trig-1 response (for edit pre-fill)
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify(
          makeTrigger({ type: 'schedule', schedule: { cron_expression: '0 * * * *' } }),
        ),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    fireEvent.click(screen.getByTestId('trigger-edit-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument(),
    )

    expect((screen.getByTestId('trigger-name-input') as HTMLInputElement).value).toBe(
      'Daily sync',
    )
    expect(screen.getByTestId('trigger-schedule-expression-input')).toBeInTheDocument()
    expect(
      (screen.getByTestId('trigger-schedule-expression-input') as HTMLInputElement).value,
    ).toBe('0 * * * *')
  })

  it('submits PUT and refreshes list when edit form is saved', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    // GET for edit pre-fill
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(makeTrigger()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-edit-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument(),
    )

    // PUT response + list refresh
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(makeTrigger()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))

    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('trigger-create-form')).toBeNull(),
    )

    const putCall = fetchMock.mock.calls.find(
      ([url, opts]) =>
        typeof url === 'string' &&
        url.includes('/api/v1/triggers/') &&
        (opts as RequestInit)?.method === 'PUT',
    )
    expect(putCall).toBeDefined()
  })

  it('surfaces server error when edit PUT returns non-ok', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    // GET for edit pre-fill succeeds.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(makeTrigger()), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-edit-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument(),
    )

    // Server rejects the update with a 422 and an error body.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'invalid schedule expression' }), {
        status: 422,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-create-submit-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('trigger-create-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-create-error')).toHaveTextContent(
      /invalid schedule expression/i,
    )
    // The edit form stays open so the user can correct and retry.
    expect(screen.getByTestId('trigger-create-form')).toBeInTheDocument()
  })

  it('surfaces error when single-trigger GET fails on edit open', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    // GET /triggers/trig-1 (for edit pre-fill) fails with a 404.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-edit-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('trigger-create-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-create-error')).toHaveTextContent(
      /failed to load trigger/i,
    )
  })
})

describe('TriggerPanel — enable/disable toggle', () => {
  it('calls /enable when trigger status is inactive', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'inactive' })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'active', trigger_id: 'trig-1', message: 'Trigger enabled successfully' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'active' })]),
    )

    fireEvent.click(screen.getByTestId('trigger-toggle-btn'))

    await waitFor(() => {
      const enableCall = fetchMock.mock.calls.find(
        ([url, opts]) =>
          typeof url === 'string' &&
          url.includes('/enable') &&
          (opts as RequestInit)?.method === 'POST',
      )
      expect(enableCall).toBeDefined()
    })
  })

  it('calls /disable when trigger status is active', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'active' })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ status: 'inactive', trigger_id: 'trig-1', message: 'Trigger disabled successfully' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'inactive' })]),
    )

    fireEvent.click(screen.getByTestId('trigger-toggle-btn'))

    await waitFor(() => {
      const disableCall = fetchMock.mock.calls.find(
        ([url, opts]) =>
          typeof url === 'string' &&
          url.includes('/disable') &&
          (opts as RequestInit)?.method === 'POST',
      )
      expect(disableCall).toBeDefined()
    })
  })

  it('toggle button is labelled Enable for inactive trigger', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'inactive' })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-toggle-btn')).toHaveTextContent(/enable/i)
  })

  it('toggle button is labelled Disable for active trigger', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'active' })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-toggle-btn')).toHaveTextContent(/disable/i)
  })

  it('surfaces toggle error when enable/disable POST returns non-ok', async () => {
    fetchMock.mockResolvedValueOnce(
      makeTriggersResponse([makeTrigger({ status: 'active' })]),
    )
    renderTriggerPanel()
    await waitFor(() =>
      expect(screen.getByTestId('trigger-table')).toBeInTheDocument(),
    )

    // Server rejects the disable with a 500 and an error body.
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'trigger is busy converging' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    fireEvent.click(screen.getByTestId('trigger-toggle-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('trigger-toggle-error')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('trigger-toggle-error')).toHaveTextContent(
      /trigger is busy converging/i,
    )
    // The trigger row remains since the toggle did not take effect.
    expect(screen.getByTestId('trigger-table')).toBeInTheDocument()
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
