// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ScriptApprovalPanel test suite (Issue #5856): version states, the exact
 * approve and revoke requests, the presence tap, and diff text rendering.
 * The panel runs against the real useScriptApprovals hook; only the network
 * boundary (fetch) is stubbed.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ScriptApprovalPanel from './ScriptApprovalPanel.tsx'
import { useScriptApprovals } from './useScriptApprovals.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

const LIST = '/api/v1/automation/approvals/scripts'
const PENDING = '/api/v1/automation/approvals/scripts/pending'

const approvedEntry = {
  script_id: 'patch',
  version: '1.0.0',
  content_hash: 'c-approved',
  approval_hash: 'a-approved',
  state: 'approved',
  approval: { approved_by: 'admin-1', approved_at: '2026-01-02T00:00:00Z', method: 'approve_tap' },
}
const pendingEntry = {
  script_id: 'patch',
  version: '1.1.0',
  content_hash: 'c-pending',
  approval_hash: 'a-pending',
  state: 'pending',
}
const newEntry = {
  script_id: 'fresh',
  version: '0.1.0',
  content_hash: 'c-new',
  approval_hash: 'a-new',
  state: 'pending',
}
const deniedEntry = {
  script_id: 'old',
  version: '2.0.0',
  content_hash: 'c-denied',
  approval_hash: 'a-denied',
  state: 'denied',
  reason: 'rejected <i>by policy</i>',
}
const pendingChange = {
  script_id: 'patch',
  version: '1.1.0',
  content_hash: 'c-pending',
  approval_hash: 'a-pending',
  previous_version: '1.0.0',
  previous_approval_hash: 'a-approved',
  first_seen: '2026-01-03T00:00:00Z',
  diff: '--- patch 1.0.0\n+++ patch 1.1.0\n-echo old\n+echo "<img src=x onerror=alert(1)>"\n',
}

interface Routes {
  entries?: object[]
  changes?: object[]
}

function Harness({ scriptId = null }: { scriptId?: string | null }) {
  const approvals = useScriptApprovals()
  return <ScriptApprovalPanel approvals={approvals} scriptId={scriptId} />
}

function renderPanel(scriptId: string | null = null) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Harness scriptId={scriptId} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

/** Serves the list and pending routes; other requests go to `other`. */
function serve(routes: Routes, other?: (url: string, init?: RequestInit) => Response | undefined) {
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (method === 'GET' && url === LIST) {
      return Promise.resolve(json(200, envelope({ mode: 'approve', scripts: routes.entries ?? [] })))
    }
    if (method === 'GET' && url === PENDING) {
      return Promise.resolve(json(200, envelope({ changes: routes.changes ?? [] })))
    }
    const handled = other?.(url, init)
    if (handled) return Promise.resolve(handled)
    return Promise.resolve(json(404, { error: 'unexpected request ' + method + ' ' + url }))
  })
}

function bodyOf(init: RequestInit | undefined): unknown {
  return JSON.parse(String(init?.body))
}

describe('ScriptApprovalPanel states', () => {
  it('shows approved, pending and denied badges with the denial reason as text', async () => {
    serve({ entries: [approvedEntry, newEntry, deniedEntry] })
    renderPanel()

    await waitFor(() => expect(screen.getAllByTestId('approval-version-row')).toHaveLength(3))
    const states = screen.getAllByTestId('approval-state').map((e) => e.textContent)
    expect(states).toEqual(['Approved', 'Pending', 'Denied'])
    expect(screen.getByTestId('approval-reason')).toHaveTextContent('rejected <i>by policy</i>')
    expect(screen.getByTestId('approval-reason').querySelector('i')).toBeNull()
    expect(screen.getByTestId('approval-by')).toHaveTextContent('admin-1')
  })

  it('limits the version list to the selected script', async () => {
    serve({ entries: [approvedEntry, newEntry] })
    renderPanel('fresh')

    await waitFor(() => expect(screen.getAllByTestId('approval-version-row')).toHaveLength(1))
    expect(screen.getByTestId('approval-version-row')).toHaveTextContent('fresh')
  })

  it('offers Approve only on pending versions and Revoke only on approved ones', async () => {
    serve({ entries: [approvedEntry, newEntry, deniedEntry] })
    renderPanel()

    await waitFor(() => expect(screen.getAllByTestId('approval-version-row')).toHaveLength(3))
    const [approved, pending, denied] = screen.getAllByTestId('approval-version-row')
    expect(within(approved!).getByTestId('approval-revoke-btn')).toBeInTheDocument()
    expect(within(approved!).queryByTestId('approval-approve-btn')).toBeNull()
    expect(within(pending!).getByTestId('approval-approve-btn')).toBeInTheDocument()
    expect(within(denied!).queryByTestId('approval-approve-btn')).toBeNull()
    expect(within(denied!).queryByTestId('approval-revoke-btn')).toBeNull()
  })

  it('shows an error card with retry when the list cannot be loaded', async () => {
    fetchMock.mockResolvedValue(json(500, { error: 'boom' }))
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('approvals-load-error')).toBeInTheDocument())
    expect(screen.getByTestId('approvals-load-error')).toHaveTextContent('500')
  })

  it('shows the empty states', async () => {
    serve({})
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('pending-empty')).toBeInTheDocument())
    expect(screen.getByTestId('approval-versions-empty')).toBeInTheDocument()
  })
})

describe('ScriptApprovalPanel pending diff', () => {
  it('renders diff text as text and injects no DOM from a script containing HTML tags', async () => {
    serve({ entries: [approvedEntry, pendingEntry], changes: [pendingChange] })
    renderPanel()

    const diff = await screen.findByTestId('pending-diff')
    expect(diff.textContent).toBe(pendingChange.diff)
    expect(diff.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(diff.querySelector('img')).toBeNull()
    // TextDiff renders one <span> per diff line; no other element is injected.
    expect(Array.from(diff.children).every((c) => c.tagName === 'SPAN')).toBe(true)
    expect(diff.children).toHaveLength(pendingChange.diff.split('\n').length)
    expect(screen.getByTestId('script-approval-panel').querySelector('img')).toBeNull()
  })

  it('shows why a diff is unavailable instead of an empty diff', async () => {
    serve({
      changes: [{ ...pendingChange, diff: '', diff_unavailable: 'the previously approved version is no longer in the library' }],
    })
    renderPanel()

    await waitFor(() =>
      expect(screen.getByTestId('pending-diff-unavailable')).toHaveTextContent(
        'no longer in the library',
      ),
    )
    expect(screen.queryByTestId('pending-diff')).toBeNull()
  })

  it('puts the Approve button of a pending change beside its diff and not in the version row', async () => {
    serve({ entries: [approvedEntry, pendingEntry], changes: [pendingChange] })
    renderPanel()

    const card = await screen.findByTestId('pending-change')
    expect(within(card).getByTestId('pending-diff')).toBeInTheDocument()
    expect(within(card).getByTestId('pending-approve-btn')).toBeInTheDocument()

    const rows = screen.getAllByTestId('approval-version-row')
    const pendingRow = rows.find((r) => r.textContent?.includes('1.1.0'))!
    expect(within(pendingRow).queryByTestId('approval-approve-btn')).toBeNull()
  })
})

describe('ScriptApprovalPanel approve', () => {
  const credential = {
    id: 'cred-id',
    type: 'public-key',
    rawId: new TextEncoder().encode('cred-id').buffer,
    response: {
      clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
      authenticatorData: new TextEncoder().encode('authenticator-data').buffer,
      signature: new TextEncoder().encode('signature').buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({}),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  }

  let posts: { token: string | null; body: unknown }[]

  /** The approve route demands a presence tap: 401 step-up until the token is sent. */
  function serveApprove(routes: Routes) {
    posts = []
    serve(routes, (url, init) => {
      if (url.includes('presence/begin')) {
        return json(
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
        )
      }
      if (url.includes('presence/finish')) {
        return json(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 }))
      }
      if (url === LIST && init?.method === 'POST') {
        const token = new Headers(init.headers).get('X-Presence-Token')
        posts.push({ token, body: bodyOf(init) })
        if (['tap-token-1'].includes(token ?? '')) return json(201, envelope({ state: 'approved' }))
        return json(
          401,
          { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
          {
            'WWW-Authenticate':
              'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="content-approval:approve"',
          },
        )
      }
      return undefined
    })
  }

  it('sends the server-provided hashes after the presence tap and refreshes the list', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    serveApprove({ entries: [newEntry] })
    renderPanel()

    fireEvent.click(await screen.findByTestId('approval-approve-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(posts).toHaveLength(1)
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    await waitFor(() => expect(posts).toHaveLength(2))
    expect(posts[1]!.token).toBe('tap-token-1')
    const expected = {
      script_id: 'fresh',
      version: '0.1.0',
      approval_hash: 'a-new',
      content_hash: 'c-new',
    }
    expect(posts[0]!.body).toEqual(expected)
    expect(posts[1]!.body).toEqual(expected)
    await waitFor(() => expect(screen.getByTestId('approval-notice')).toHaveTextContent('Approval recorded'))
    const listCalls = fetchMock.mock.calls.filter(
      ([u, i]) => String(u) === LIST && (i?.method ?? 'GET') === 'GET',
    )
    expect(listCalls.length).toBeGreaterThanOrEqual(2)
  })

  it('approves a pending change with the hash of its pending record', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    serveApprove({ entries: [approvedEntry, pendingEntry], changes: [pendingChange] })
    renderPanel()

    fireEvent.click(await screen.findByTestId('pending-approve-btn'))
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    await waitFor(() => expect(posts).toHaveLength(2))
    expect(posts[1]!.body).toEqual({
      script_id: 'patch',
      version: '1.1.0',
      approval_hash: 'a-pending',
      content_hash: 'c-pending',
    })
  })

  it('sends nothing more and approves nothing when the tap is cancelled', async () => {
    serveApprove({ entries: [newEntry] })
    renderPanel()

    fireEvent.click(await screen.findByTestId('approval-approve-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('approval-error')).toHaveTextContent(/nothing was approved/i),
    )
    expect(posts).toHaveLength(1)
    expect(screen.queryByTestId('approval-notice')).toBeNull()
  })

  it('shows the server refusal verbatim, such as a hash mismatch', async () => {
    serve({ entries: [newEntry] }, (url, init) =>
      url === LIST && init?.method === 'POST'
        ? json(409, { error: { code: 'HASH_MISMATCH', message: 'Hash does not match the stored script version' } })
        : undefined,
    )
    renderPanel()

    fireEvent.click(await screen.findByTestId('approval-approve-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('approval-error')).toHaveTextContent(
        'Hash does not match the stored script version',
      ),
    )
  })
})

describe('ScriptApprovalPanel revoke', () => {
  it('calls the revoke route with the id, version and approval hash and refreshes', async () => {
    let deleted: string | null = null
    serve({ entries: [approvedEntry] }, (url, init) => {
      if (init?.method === 'DELETE') {
        deleted = url
        return new Response(null, { status: 204 })
      }
      return undefined
    })
    renderPanel()

    fireEvent.click(await screen.findByTestId('approval-revoke-btn'))

    await waitFor(() => expect(screen.getByTestId('approval-notice')).toHaveTextContent('Approval revoked'))
    expect(deleted).toBe(`${LIST}/patch/1.0.0/a-approved`)
  })

  it('percent-encodes path segments so a hostile id cannot add a path', async () => {
    let deleted: string | null = null
    serve({ entries: [{ ...approvedEntry, script_id: '../x/y', version: '1.0.0?z' }] }, (url, init) => {
      if (init?.method === 'DELETE') {
        deleted = url
        return new Response(null, { status: 204 })
      }
      return undefined
    })
    renderPanel()

    fireEvent.click(await screen.findByTestId('approval-revoke-btn'))

    await waitFor(() => expect(deleted).not.toBeNull())
    expect(deleted).toBe(`${LIST}/..%2Fx%2Fy/1.0.0%3Fz/a-approved`)
  })

  it('shows the server message when revoke is refused', async () => {
    serve({ entries: [approvedEntry] }, (_url, init) =>
      init?.method === 'DELETE'
        ? json(404, { error: { code: 'NOT_FOUND', message: 'Approval not found' } })
        : undefined,
    )
    renderPanel()

    fireEvent.click(await screen.findByTestId('approval-revoke-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('approval-error')).toHaveTextContent('Approval not found'),
    )
  })
})
