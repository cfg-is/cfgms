// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * PushPanel test suite (Story #2730, AC: confirm-step gating).
 *
 * Key invariants tested:
 * 1. The push API is never called without an explicit confirm step.
 * 2. The confirm dialog shows the resolved target count before committing.
 * 3. Cancelling the confirm dialog prevents the push.
 * 4. The push resolves through the confirm and fires the API.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import PushPanel from './PushPanel.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeStewPage(total: number) {
  return new Response(
    JSON.stringify({
      data: { stewards: [], total, limit: 1, offset: 0 },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makePushResponse(pushId: string) {
  return new Response(
    JSON.stringify({ push_id: pushId, status: 'accepted', queued_at: new Date().toISOString() }),
    { status: 202, headers: { 'Content-Type': 'application/json' } },
  )
}

function makePushStatus(pushId: string, status: string) {
  return new Response(
    JSON.stringify({
      push_id: pushId,
      config_id: 'sw-1',
      tenant_id: 'root',
      version: '1',
      status,
      initiated_by: '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderPushPanel(onClose = vi.fn()) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <PushPanel onClose={onClose} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function fillPushForm(selector = 'name:web*', configId = 'sw-1', tenantId = 'root') {
  fireEvent.change(screen.getByRole('textbox', { name: /selector/i }), {
    target: { value: selector },
  })
  fireEvent.change(screen.getByRole('textbox', { name: /config id/i }), {
    target: { value: configId },
  })
  fireEvent.change(screen.getByRole('textbox', { name: /tenant id/i }), {
    target: { value: tenantId },
  })
}

describe('PushPanel — rendering', () => {
  it('renders form inputs and action buttons', () => {
    renderPushPanel()
    expect(screen.getByRole('textbox', { name: /selector/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /config id/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /version/i })).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /tenant id/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /resolve targets/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /push config/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  it('disables Push config until targets are resolved', () => {
    renderPushPanel()
    expect(screen.getByRole('button', { name: /push config/i })).toBeDisabled()
  })
})

describe('PushPanel — confirm-step gating (AC)', () => {
  it('does NOT fire the push API when Push config is clicked — shows confirm dialog first', async () => {
    fetchMock.mockResolvedValue(makeStewPage(5))
    renderPushPanel()

    fillPushForm()
    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))

    // Confirm dialog appears
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByTestId('push-confirm-count')).toBeInTheDocument()

    // The push API (POST /api/v1/config/push) must NOT have been called yet
    const pushCalls = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/api/v1/config/push') && (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(pushCalls).toHaveLength(0)
  })

  it('confirm dialog shows the resolved target count', async () => {
    fetchMock.mockResolvedValue(makeStewPage(12))
    renderPushPanel()

    fillPushForm('os:linux', 'my-config', 'root')
    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toHaveTextContent('12'))

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))

    expect(screen.getByTestId('push-confirm-count')).toHaveTextContent('12')
  })

  it('cancelling the confirm dialog prevents the push from firing', async () => {
    fetchMock.mockResolvedValue(makeStewPage(3))
    renderPushPanel()

    fillPushForm()
    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    // Cancel the confirm
    const cancelBtns = screen.getAllByRole('button', { name: /cancel/i })
    // The cancel inside the modal
    const modalCancel = cancelBtns.find((btn) => btn.closest('[role="dialog"]'))
    fireEvent.click(modalCancel!)

    expect(screen.queryByRole('dialog')).toBeNull()

    // Push API must never have been called
    const pushCalls = fetchMock.mock.calls.filter(
      (c) => typeof c[0] === 'string' && (c[0] as string).includes('/api/v1/config/push') && (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(pushCalls).toHaveLength(0)
  })

  it('fires the push API only after Confirm push is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(7))
    fetchMock.mockResolvedValue(makePushResponse('push-test-1'))

    renderPushPanel()

    fillPushForm('name:prod*', 'cfg-1', 'root/msp')
    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    // Confirm the push
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() => {
      const pushCalls = fetchMock.mock.calls.filter(
        (c) => typeof c[0] === 'string' && (c[0] as string).includes('/api/v1/config/push'),
      )
      expect(pushCalls.length).toBeGreaterThan(0)
    })

    // Confirm dialog closes after push fires
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})

describe('PushPanel — push status display', () => {
  it('shows push status after a successful push', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(2))
    fetchMock.mockResolvedValueOnce(makePushResponse('push-xyz'))
    fetchMock.mockResolvedValue(makePushStatus('push-xyz', 'completed'))

    renderPushPanel()
    fillPushForm()

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() => expect(screen.getByTestId('push-status')).toBeInTheDocument())
  })

  it('shows an error when the push API returns non-ok', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(1))
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'not the leader' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    renderPushPanel()
    fillPushForm()

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() => expect(screen.getByTestId('push-error')).toBeInTheDocument())
  })

  it('calls onClose when Cancel is clicked', () => {
    const onClose = vi.fn()
    renderPushPanel(onClose)
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(onClose).toHaveBeenCalled()
  })
})

describe('PushPanel — resolve targets', () => {
  it('shows resolved count after clicking Resolve targets', async () => {
    fetchMock.mockResolvedValue(makeStewPage(8))
    renderPushPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /selector/i }), {
      target: { value: 'os:windows' },
    })
    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))

    await waitFor(() =>
      expect(screen.getByTestId('push-target-count')).toHaveTextContent('8'),
    )
  })

  it('shows error when resolve fails', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderPushPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /selector/i }), {
      target: { value: 'bad:selector' },
    })
    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))

    await waitFor(() =>
      expect(screen.getByTestId('push-resolve-error')).toBeInTheDocument(),
    )
  })
})

// ── Per-steward deployment breakdown ─────────────────────────────────────────

function makeDeploymentsEnvelope(configId: string, stewards: object[]) {
  return new Response(
    JSON.stringify({
      data: {
        config_id: configId,
        summary: {
          applied: stewards.length,
          pending: 0,
          failed: 0,
          halted: 0,
          total: stewards.length,
        },
        stewards,
        push_history: [],
      },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('PushPanel — per-steward deployment breakdown', () => {
  it('shows deployment breakdown after push fires and deployments load', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(2))
    fetchMock.mockResolvedValueOnce(makePushResponse('push-xyz'))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          makeDeploymentsEnvelope('sw-1', [
            { steward_id: 'sw-1', status: 'applied', last_updated: '2026-01-01T00:00:00Z' },
            { steward_id: 'sw-2', status: 'failed', last_updated: '2026-01-01T00:00:00Z' },
          ]),
        )
      }
      return Promise.resolve(makePushStatus('push-xyz', 'completed'))
    })

    renderPushPanel()
    fillPushForm('name:web*', 'sw-1', 'root')

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('deployment-breakdown')).toBeInTheDocument(),
    )
    await waitFor(() =>
      expect(screen.getAllByTestId('deployment-steward-row')).toHaveLength(2),
    )
    expect(screen.getByText('sw-1')).toBeInTheDocument()
    expect(screen.getByText('sw-2')).toBeInTheDocument()
  })

  it('renders applied status with ok pill and failed with crit pill', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(1))
    fetchMock.mockResolvedValueOnce(makePushResponse('push-abc'))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          makeDeploymentsEnvelope('cfg-1', [
            { steward_id: 'sw-a', status: 'applied', last_updated: '2026-01-01T00:00:00Z' },
            { steward_id: 'sw-b', status: 'failed', last_updated: '2026-01-01T00:00:00Z' },
          ]),
        )
      }
      return Promise.resolve(makePushStatus('push-abc', 'completed'))
    })

    renderPushPanel()
    fillPushForm('os:linux', 'cfg-1', 'root')

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('deployment-steward-table')).toBeInTheDocument(),
    )

    const pills = screen.getAllByTestId('deployment-steward-row')
    expect(pills[0]!.querySelector('.pill.ok')).not.toBeNull()
    expect(pills[1]!.querySelector('.pill.crit')).not.toBeNull()
  })

  it('shows unavailable message when deployments store returns 503', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(1))
    fetchMock.mockResolvedValueOnce(makePushResponse('push-503'))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          new Response(JSON.stringify({ error: 'store unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          }),
        )
      }
      return Promise.resolve(makePushStatus('push-503', 'completed'))
    })

    renderPushPanel()
    fillPushForm('os:windows', 'cfg-2', 'root')

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('deployment-breakdown')).toBeInTheDocument(),
    )
    await waitFor(() =>
      expect(screen.getByText(/unavailable/i)).toBeInTheDocument(),
    )
  })

  it('shows no-records message when stewards array is empty', async () => {
    fetchMock.mockResolvedValueOnce(makeStewPage(0))
    fetchMock.mockResolvedValueOnce(makePushResponse('push-empty'))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          makeDeploymentsEnvelope('cfg-empty', []),
        )
      }
      return Promise.resolve(makePushStatus('push-empty', 'completed'))
    })

    renderPushPanel()
    fillPushForm('os:linux', 'cfg-empty', 'root')

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('deployment-breakdown')).toBeInTheDocument(),
    )
    await waitFor(() =>
      expect(screen.getByText(/no per-steward records/i)).toBeInTheDocument(),
    )
  })

  it('steward IDs in breakdown render as text, not HTML (security A9.1)', async () => {
    const xssId = '<img src=x onerror="window.__xss=true">'
    fetchMock.mockResolvedValueOnce(makeStewPage(1))
    fetchMock.mockResolvedValueOnce(makePushResponse('push-xss'))
    fetchMock.mockImplementation((url: unknown) => {
      const u = String(url)
      if (u.includes('/deployments')) {
        return Promise.resolve(
          makeDeploymentsEnvelope('cfg-xss', [
            { steward_id: xssId, status: 'applied', last_updated: '2026-01-01T00:00:00Z' },
          ]),
        )
      }
      return Promise.resolve(makePushStatus('push-xss', 'completed'))
    })

    renderPushPanel()
    fillPushForm('os:linux', 'cfg-xss', 'root')

    fireEvent.click(screen.getByRole('button', { name: /resolve targets/i }))
    await waitFor(() => expect(screen.getByTestId('push-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /push config/i }))
    fireEvent.click(screen.getByTestId('push-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('deployment-breakdown')).toBeInTheDocument(),
    )
    await waitFor(() => expect(screen.getByText(xssId)).toBeInTheDocument())
    expect((window as unknown as Record<string, unknown>).__xss).toBeUndefined()
  })
})
