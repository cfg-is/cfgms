// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ClusterNodesView test suite (Issue #5462, Epic #5300). Real AuthProvider,
 * apiFetch and StepUpModal; only global fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ClusterNodesView from './ClusterNodesView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
  localStorage.clear()
  sessionStorage.clear()
})

function jsonResponse(status: number, body: unknown = {}, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const stepUp401 = () =>
  jsonResponse(
    401,
    { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
    { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"' },
  )

// ha.NodeState / ha.NodeRole serialise as integers: state 1 = healthy, role 2 = leader.
const nodes = [
  { id: 'node-a', address: '10.0.0.1:8443', state: 1, role: 2, version: '1.2.3', last_seen: '2026-11-10T10:00:00Z' },
  { id: 'node-b', address: '10.0.0.2:8443', state: 2, role: 0, version: '1.2.3', last_seen: '2026-11-10T10:00:00Z' },
]

interface Opts {
  localNodeId?: string
  /** Handler for POST requests to /api/v1/cluster/...; defaults to success. */
  onPost?: (url: string, init?: RequestInit) => Response
  nodeList?: unknown
}

function stubApi(opts: Opts = {}) {
  fetchMock.mockImplementation((url, init) => {
    const u = String(url)
    if (init?.method === 'POST') {
      return Promise.resolve(opts.onPost ? opts.onPost(u, init) : jsonResponse(202, { node_id: 'x', state: 'draining' }))
    }
    if (u === '/api/v1/ha/nodes') {
      return Promise.resolve(jsonResponse(200, opts.nodeList ?? { nodes, count: nodes.length }))
    }
    if (u === '/api/v1/ha/status') {
      return Promise.resolve(jsonResponse(200, { node_id: opts.localNodeId ?? 'node-a', is_leader: true }))
    }
    return Promise.resolve(jsonResponse(404))
  })
}

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ClusterNodesView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

/** POSTs to the lifecycle endpoints (the step-up ceremony's own POSTs are excluded). */
function posts() {
  return fetchMock.mock.calls.filter(
    ([u, init]) => init?.method === 'POST' && String(u).startsWith('/api/v1/cluster/'),
  )
}

function stubPresence() {
  const cred = {
    id: 'cred-id-b64u',
    type: 'public-key',
    rawId: new TextEncoder().encode('cred-id-b64u').buffer,
    response: {
      clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
      authenticatorData: new TextEncoder().encode('ad').buffer,
      signature: new TextEncoder().encode('sig').buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({}),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  }
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } })
}

const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

/** POST handler that demands a presence token: 401 step-up without one, success with it. */
function elevationPosts(url: string, init?: RequestInit): Response {
  if (new Headers(init?.headers).get('X-Presence-Token') !== 'tap-token-1') return stepUp401()
  return url.endsWith('/decommission')
    ? jsonResponse(200, { node_id: 'node-b', state: 'decommissioned' })
    : jsonResponse(202, { node_id: 'node-b', state: 'draining' })
}

/** stubApi plus the presence begin/finish endpoints the StepUpModal talks to. */
function stubApiWithPresence(onPost: Opts['onPost']) {
  stubApi({ onPost })
  const base = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation((url, init) => {
    const u = String(url)
    if (u.includes('presence/begin')) {
      return Promise.resolve(
        jsonResponse(
          200,
          envelope({
            publicKey: {
              challenge: 'Y2hhbGxlbmdl',
              timeout: 60000,
              rpId: 'localhost',
              allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
              userVerification: 'required',
            },
          }),
        ),
      )
    }
    if (u.includes('presence/finish')) {
      return Promise.resolve(jsonResponse(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
    }
    return base(url, init)
  })
}

describe('ClusterNodesView', () => {
  it('lists nodes from GET /api/v1/ha/nodes with role, health and status', async () => {
    stubApi()
    renderView()
    const rows = await screen.findAllByTestId('node-row')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]!).getByTestId('node-id')).toHaveTextContent('node-a')
    expect(within(rows[0]!).getByTestId('node-address')).toHaveTextContent('10.0.0.1:8443')
    expect(within(rows[0]!).getByTestId('node-role')).toHaveTextContent(/leader/i)
    expect(within(rows[0]!).getByTestId('node-health')).toHaveTextContent(/healthy/i)
    expect(within(rows[0]!).getByTestId('node-status')).toHaveTextContent(/active/i)
    expect(within(rows[1]!).getByTestId('node-role')).toHaveTextContent(/follower/i)
    expect(within(rows[1]!).getByTestId('node-health')).toHaveTextContent(/degraded/i)
    expect(fetchMock.mock.calls.some(([u]) => String(u) === '/api/v1/ha/nodes')).toBe(true)
  })

  it('shows a loading state, an empty state and a retryable error', async () => {
    stubApi({ nodeList: { nodes: [], count: 0 } })
    renderView()
    expect(screen.getByTestId('nodes-loading')).toBeInTheDocument()
    expect(await screen.findByTestId('nodes-empty')).toBeInTheDocument()
    cleanup()

    fetchMock.mockReset()
    fetchMock.mockResolvedValue(jsonResponse(503, { error: 'HA manager not available' }))
    renderView()
    expect(await screen.findByText(/couldn.t load cluster nodes/i)).toBeInTheDocument()
    expect(screen.getByText(/503/)).toBeInTheDocument()
    stubApi()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(await screen.findAllByTestId('node-row')).toHaveLength(2)
  })

  it('drain posts to the drain endpoint and marks the node draining', async () => {
    stubApi({ localNodeId: 'node-a' })
    renderView()
    fireEvent.click(await screen.findByTestId('node-drain-btn-node-b'))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(String(posts()[0]![0])).toBe('/api/v1/cluster/nodes/node-b/drain')
    await waitFor(() =>
      expect(within(screen.getAllByTestId('node-row')[1]!).getByTestId('node-status')).toHaveTextContent(/draining/i),
    )
    expect(screen.getByTestId('node-drain-btn-node-b')).toBeDisabled()
  })

  it('shows the server reason when a drain fails and keeps the action available', async () => {
    stubApi({ localNodeId: 'node-a', onPost: () => jsonResponse(409, { error: 'node is not active' }) })
    renderView()
    fireEvent.click(await screen.findByTestId('node-drain-btn-node-b'))
    expect(await screen.findByTestId('node-action-error-node-b')).toHaveTextContent('node is not active')
    expect(screen.getByTestId('node-drain-btn-node-b')).toBeEnabled()
  })

  it('decommission needs the typed node id', async () => {
    stubApi({
      localNodeId: 'node-a',
      onPost: () => jsonResponse(200, { node_id: 'node-b', state: 'decommissioned' }),
    })
    renderView()
    fireEvent.click(await screen.findByTestId('node-decommission-btn-node-b'))
    const confirm = screen.getByTestId('decommission-confirm-btn')
    const input = screen.getByTestId('decommission-confirm-input')
    expect(confirm).toBeDisabled()

    // Wrong text, a different node's id and a near miss all keep it disabled.
    for (const wrong of ['decommission', 'node-a', 'node-', 'NODE-B']) {
      fireEvent.change(input, { target: { value: wrong } })
      expect(confirm).toBeDisabled()
    }
    fireEvent.click(confirm)
    expect(posts()).toHaveLength(0)

    fireEvent.change(input, { target: { value: 'node-b' } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(String(posts()[0]![0])).toBe('/api/v1/cluster/nodes/node-b/decommission')
    await waitFor(() => expect(screen.queryByTestId('decommission-overlay')).toBeNull())
    // The list refetches after the action; wait for the table to come back.
    await waitFor(() =>
      expect(within((screen.getAllByTestId('node-row'))[1]!).getByTestId('node-status')).toHaveTextContent(
        /decommissioned/i,
      ),
    )
    expect(screen.getByTestId('node-decommission-btn-node-b')).toBeDisabled()
  })

  it('cancelling the decommission modal sends nothing', async () => {
    stubApi({ localNodeId: 'node-a' })
    renderView()
    fireEvent.click(await screen.findByTestId('node-decommission-btn-node-b'))
    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    expect(screen.queryByTestId('decommission-overlay')).toBeNull()
    expect(posts()).toHaveLength(0)
  })

  it('keeps the modal open with the server reason when decommission is refused', async () => {
    stubApi({
      localNodeId: 'node-a',
      onPost: () => jsonResponse(409, { error: 'node is not in draining state' }),
    })
    renderView()
    fireEvent.click(await screen.findByTestId('node-decommission-btn-node-b'))
    fireEvent.change(screen.getByTestId('decommission-confirm-input'), { target: { value: 'node-b' } })
    fireEvent.click(screen.getByTestId('decommission-confirm-btn'))
    expect(await screen.findByTestId('decommission-error')).toHaveTextContent('node is not in draining state')
    expect(screen.getByTestId('decommission-overlay')).toBeInTheDocument()
  })

  it('drain and decommission handle elevation 401 without a presence token', async () => {
    stubPresence()
    stubApiWithPresence(elevationPosts)
    renderView()

    // Drain: the view's own request carries no presence token; the interceptor
    // runs the tap and retries with the token it obtained.
    fireEvent.click(await screen.findByTestId('node-drain-btn-node-b'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(posts()).toHaveLength(1)
    expect(new Headers(posts()[0]![1]?.headers).has('X-Presence-Token')).toBe(false)
    // Nothing is marked draining until the admin taps.
    expect(within(screen.getAllByTestId('node-row')[1]!).getByTestId('node-status')).toHaveTextContent(/active/i)
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    await waitFor(() =>
      expect(within(screen.getAllByTestId('node-row')[1]!).getByTestId('node-status')).toHaveTextContent(/draining/i),
    )
    expect(posts()).toHaveLength(2)
    expect(String(posts()[1]![0])).toBe('/api/v1/cluster/nodes/node-b/drain')
    expect(new Headers(posts()[1]![1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
    await waitFor(() => expect(screen.queryByTestId('step-up-overlay')).toBeNull())

    // Decommission: same flow, after the typed node id.
    fireEvent.click(screen.getByTestId('node-decommission-btn-node-b'))
    fireEvent.change(screen.getByTestId('decommission-confirm-input'), { target: { value: 'node-b' } })
    fireEvent.click(screen.getByTestId('decommission-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(posts()).toHaveLength(3)
    expect(new Headers(posts()[2]![1]?.headers).has('X-Presence-Token')).toBe(false)
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    await waitFor(() =>
      expect(within(screen.getAllByTestId('node-row')[1]!).getByTestId('node-status')).toHaveTextContent(
        /decommissioned/i,
      ),
    )
    expect(posts()).toHaveLength(4)
    expect(String(posts()[3]![0])).toBe('/api/v1/cluster/nodes/node-b/decommission')
    expect(new Headers(posts()[3]![1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
  })

  it('a cancelled presence tap drains nothing and reports the failure', async () => {
    stubApi({ onPost: () => stepUp401() })
    renderView()
    fireEvent.click(await screen.findByTestId('node-drain-btn-node-b'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-cancel-btn'))
    expect(await screen.findByTestId('node-action-error-node-b')).toBeInTheDocument()
    expect(posts()).toHaveLength(1)
    expect(within(screen.getAllByTestId('node-row')[1]!).getByTestId('node-status')).toHaveTextContent(/active/i)
  })

  it('disables actions on the local node when the server refuses', async () => {
    const reason = 'cluster node lifecycle requires an unscoped principal'
    stubApi({ localNodeId: 'node-a', onPost: () => jsonResponse(403, { error: reason }) })
    renderView()
    const localRow = (await screen.findAllByTestId('node-row'))[0]!
    expect(within(localRow).getByTestId('node-local-tag')).toBeInTheDocument()
    // Other nodes carry no local tag.
    expect(within(screen.getAllByTestId('node-row')[1]!).queryByTestId('node-local-tag')).toBeNull()

    fireEvent.click(screen.getByTestId('node-drain-btn-node-a'))
    await waitFor(() => expect(screen.getByTestId('node-drain-btn-node-a')).toBeDisabled())
    expect(screen.getByTestId('node-decommission-btn-node-a')).toBeDisabled()
    expect(screen.getByTestId('node-refusal-node-a')).toHaveTextContent(reason)
    expect(screen.getByTestId('node-drain-btn-node-a')).toHaveAttribute('title', reason)
    expect(posts()).toHaveLength(1)

    // The refusal is not attributed to other nodes.
    expect(screen.getByTestId('node-drain-btn-node-b')).toBeEnabled()
    expect(screen.getByTestId('node-decommission-btn-node-b')).toBeEnabled()
    expect(screen.queryByTestId('node-refusal-node-b')).toBeNull()
  })

  it('a refusal on a non-local node does not disable its actions', async () => {
    stubApi({ localNodeId: 'node-a', onPost: () => jsonResponse(403, { error: 'nope' }) })
    renderView()
    fireEvent.click(await screen.findByTestId('node-drain-btn-node-b'))
    expect(await screen.findByTestId('node-action-error-node-b')).toHaveTextContent('nope')
    expect(screen.getByTestId('node-drain-btn-node-b')).toBeEnabled()
    expect(screen.queryByTestId('node-refusal-node-b')).toBeNull()
  })

  it('renders hostile node values as text, never markup', async () => {
    stubApi({ nodeList: { nodes: [{ id: '<img src=x onerror=alert(1)>', address: '<b>x</b>', state: 1, role: 0 }] } })
    renderView()
    expect(await screen.findByTestId('node-id')).toHaveTextContent('<img src=x onerror=alert(1)>')
    expect(document.querySelector('img')).toBeNull()
    expect(document.querySelector('td b')).toBeNull()
  })
})
