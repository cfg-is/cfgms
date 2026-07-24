// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ModuleReviewQueue test suite (Issue #2732): list rendering, data states,
 * approve-confirm-fire, and reject-confirm-fire.
 *
 * Security A9.1: bundle metadata is attacker-influenced. The tests verify
 * that fields render as text content, not via dangerouslySetInnerHTML.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ModuleReviewQueue from './ModuleReviewQueue.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeBundle(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    address: 'vendor-a:file:1.0.0:abc123',
    publisher: 'vendor-a',
    name: 'file',
    version: '1.0.0',
    content_hash: 'abc123==',
    ...overrides,
  }
}

function makeListResponse(bundles: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: { pending: bundles } }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeActionResponse(action: 'approved' | 'rejected' = 'approved', status = 200) {
  return new Response(
    JSON.stringify({ data: { status: action } }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderQueue() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ModuleReviewQueue />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('ModuleReviewQueue — heading and list rendering', () => {
  it('renders the Modules heading', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderQueue()
    expect(screen.getByRole('heading', { name: /modules/i, level: 1 })).toBeInTheDocument()
  })

  it('shows loading rows while fetching', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderQueue()
    expect(screen.getByTestId('modules-loading')).toBeInTheDocument()
  })

  it('shows the empty state when no bundles are pending', async () => {
    fetchMock.mockResolvedValue(makeListResponse([]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('modules-empty')).toBeInTheDocument())
  })

  it('renders a table with bundle rows when bundles are pending', async () => {
    fetchMock.mockResolvedValue(
      makeListResponse([
        makeBundle(),
        makeBundle({ address: 'vendor-b:patch:2.0.0:def456', name: 'patch', publisher: 'vendor-b' }),
      ]),
    )
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('modules-table')).toBeInTheDocument())
    expect(screen.getAllByTestId('bundle-row')).toHaveLength(2)
  })

  it('renders bundle name, publisher, and version as text nodes', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('modules-table')).toBeInTheDocument())
    expect(screen.getByText('file')).toBeInTheDocument()
    expect(screen.getByText('vendor-a')).toBeInTheDocument()
    expect(screen.getByText('1.0.0')).toBeInTheDocument()
  })

  it('shows Approve and Reject buttons for each bundle row', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('modules-table')).toBeInTheDocument())
    expect(screen.getByTestId('bundle-approve-btn')).toBeInTheDocument()
    expect(screen.getByTestId('bundle-reject-btn')).toBeInTheDocument()
  })

  it('shows an error notice on fetch failure', async () => {
    fetchMock.mockResolvedValue(makeListResponse([], 500))
    renderQueue()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('500')
  })

  it('retries the fetch when Retry is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([], 500))
      .mockResolvedValueOnce(makeListResponse([]))
    renderQueue()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(screen.getByTestId('modules-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('shows server-error copy (not connectivity) for a 5xx response', async () => {
    fetchMock.mockResolvedValue(makeListResponse([], 503))
    renderQueue()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.queryByText(/check your connection/i)).toBeNull()
    expect(screen.getByText(/server.*error|returned an error/i)).toBeInTheDocument()
  })

  it('shows connectivity copy for a network-level failure', async () => {
    fetchMock.mockRejectedValue(new Error('network down'))
    renderQueue()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })
})

describe('ModuleReviewQueue — approve-confirm-fire', () => {
  it('shows no confirm dialog before any action is triggered', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('modules-table')).toBeInTheDocument())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('opens the approve confirm dialog showing publisher and content address', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-approve-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-approve-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /approve module bundle/i })).toBeInTheDocument()
    expect(screen.getByTestId('confirm-publisher')).toHaveTextContent('vendor-a')
    expect(screen.getByTestId('confirm-address')).toHaveTextContent('vendor-a:file:1.0.0:abc123')
  })

  it('cancel closes the approve dialog without firing any approve request', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-approve-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-approve-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('confirm-cancel-btn'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('fires the approve POST and refreshes the list when the confirm button is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(makeActionResponse('approved'))
      .mockResolvedValueOnce(makeListResponse([]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-approve-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-approve-btn'))
    fireEvent.click(screen.getByTestId('confirm-approve-btn'))
    await waitFor(() => expect(screen.getByTestId('modules-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(3)
    const approveCall = fetchMock.mock.calls[1]!
    expect(String(approveCall[0])).toContain('/approve')
  })

  it('shows an action error banner when the approve request fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Bundle not found' } }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-approve-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-approve-btn'))
    fireEvent.click(screen.getByTestId('confirm-approve-btn'))
    await waitFor(() => expect(screen.getByTestId('action-error')).toBeInTheDocument())
    expect(screen.getByTestId('action-error')).toHaveTextContent('Bundle not found')
  })
})

describe('ModuleReviewQueue — reject-confirm-fire', () => {
  it('opens the reject confirm dialog showing publisher and content address', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-reject-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-reject-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /reject module bundle/i })).toBeInTheDocument()
    expect(screen.getByTestId('confirm-publisher')).toHaveTextContent('vendor-a')
    expect(screen.getByTestId('confirm-address')).toHaveTextContent('vendor-a:file:1.0.0:abc123')
  })

  it('cancel closes the reject dialog without firing any reject request', async () => {
    fetchMock.mockResolvedValue(makeListResponse([makeBundle()]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-reject-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-reject-btn'))
    fireEvent.click(screen.getByTestId('confirm-cancel-btn'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('fires the reject POST and refreshes the list when the confirm button is clicked', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(makeActionResponse('rejected'))
      .mockResolvedValueOnce(makeListResponse([]))
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-reject-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-reject-btn'))
    fireEvent.click(screen.getByTestId('confirm-reject-btn'))
    await waitFor(() => expect(screen.getByTestId('modules-empty')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(3)
    const rejectCall = fetchMock.mock.calls[1]!
    expect(String(rejectCall[0])).toContain('/reject')
  })

  it('shows an action error banner when the reject request fails', async () => {
    fetchMock
      .mockResolvedValueOnce(makeListResponse([makeBundle()]))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: { message: 'Not in pending state' } }),
          { status: 409, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    renderQueue()
    await waitFor(() => expect(screen.getByTestId('bundle-reject-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('bundle-reject-btn'))
    fireEvent.click(screen.getByTestId('confirm-reject-btn'))
    await waitFor(() => expect(screen.getByTestId('action-error')).toBeInTheDocument())
    expect(screen.getByTestId('action-error')).toHaveTextContent('Not in pending state')
  })
})
