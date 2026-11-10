// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * WorkflowApprovalPanel test suite (Issue #5861): version states, the exact approve
 * and revoke requests, the presence tap, definition text rendering, and the library
 * mode change for kind workflow as mounted in WorkflowListView. The panel runs against
 * the real useWorkflowApprovals hook; only the network boundary (fetch) is stubbed.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import WorkflowApprovalPanel from './WorkflowApprovalPanel.tsx'
import WorkflowListView from './WorkflowListView.tsx'
import { useWorkflowApprovals } from './useWorkflowApprovals.ts'
import { parseWorkflowList, type VersionedWorkflow } from './useWorkflows.ts'

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

const LIST = '/api/v1/automation/approvals/workflows'

const approvedEntry = {
  workflow_id: 'deploy',
  version: '1.0.0',
  content_hash: 'c-approved',
  approval_hash: 'a-approved',
  state: 'approved',
  reason: 'an approval is recorded for this exact version and content',
  approval: { approved_by: 'admin-1', approved_at: '2026-01-02T00:00:00Z', method: 'approve_tap' },
}
const pendingEntry = {
  workflow_id: 'deploy',
  version: '1.1.0',
  content_hash: 'c-pending',
  approval_hash: 'a-pending',
  state: 'pending',
  reason: 'no approval exists for this exact version and content',
}
const otherEntry = {
  workflow_id: 'cleanup',
  version: '0.1.0',
  content_hash: 'c-other',
  approval_hash: 'a-other',
  state: 'pending',
  reason: 'no approval exists for this exact version and content',
}

const HOSTILE = '<img src=x onerror=alert(1)>'

function makeWorkflows(): VersionedWorkflow[] {
  return parseWorkflowList([
    {
      name: 'deploy',
      description: HOSTILE,
      version: '1.1.0',
      steps: [{ id: 's1', name: HOSTILE, type: 'script', config: { run: '<b>bold</b>' } }],
      semantic_version: { major: 1, minor: 1, patch: 0, pre_release: '', build_meta: '' },
      trigger_count: 3,
      enabled_trigger_count: 1,
      last_execution: null,
    },
    {
      name: 'cleanup',
      description: 'tidy',
      version: '0.1.0',
      steps: [],
      semantic_version: { major: 0, minor: 1, patch: 0, pre_release: '', build_meta: '' },
    },
  ])
}

/** Serves the list route; other requests go to `other`. */
function serve(entries: object[], other?: (url: string, init?: RequestInit) => Response | undefined) {
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (method === 'GET' && url === LIST) {
      return Promise.resolve(json(200, envelope({ mode: 'approve', workflows: entries })))
    }
    const handled = other?.(url, init)
    if (handled) return Promise.resolve(handled)
    return Promise.resolve(json(404, { error: 'unexpected request ' + method + ' ' + url }))
  })
}

function bodyOf(init: RequestInit | undefined): unknown {
  return JSON.parse(String(init?.body))
}

function Harness({
  workflows,
  workflowId = null,
}: {
  workflows: VersionedWorkflow[]
  workflowId?: string | null
}) {
  const approvals = useWorkflowApprovals()
  return <WorkflowApprovalPanel approvals={approvals} workflows={workflows} workflowId={workflowId} />
}

function renderPanel(workflows = makeWorkflows(), workflowId: string | null = null) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Harness workflows={workflows} workflowId={workflowId} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

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

function presenceRoutes(url: string): Response | undefined {
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
  return undefined
}

function stepUpRequired(permission: string): Response {
  return json(
    401,
    { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
    {
      'WWW-Authenticate': `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="${permission}"`,
    },
  )
}

describe('WorkflowApprovalPanel states', () => {
  it('shows the evaluator state and reason of each version', async () => {
    serve([approvedEntry, pendingEntry])
    renderPanel()

    await waitFor(() => expect(screen.getAllByTestId('workflow-approval-version')).toHaveLength(2))
    expect(screen.getAllByTestId('workflow-approval-state').map((e) => e.textContent)).toEqual([
      'Approved',
      'Pending',
    ])
    expect(screen.getAllByTestId('workflow-approval-reason')[1]).toHaveTextContent(
      'no approval exists for this exact version and content',
    )
    expect(screen.getByTestId('workflow-approval-by')).toHaveTextContent('admin-1')
  })

  it('renders a reason containing HTML as text', async () => {
    serve([{ ...pendingEntry, reason: 'bad <i>reason</i>' }])
    renderPanel()

    const reason = await screen.findByTestId('workflow-approval-reason')
    expect(reason).toHaveTextContent('bad <i>reason</i>')
    expect(reason.querySelector('i')).toBeNull()
  })

  it('limits the version list to the selected workflow', async () => {
    serve([pendingEntry, otherEntry])
    renderPanel(makeWorkflows(), 'cleanup')

    await waitFor(() => expect(screen.getAllByTestId('workflow-approval-version')).toHaveLength(1))
    expect(screen.getByTestId('workflow-approval-version')).toHaveTextContent('cleanup')
  })

  it('offers Approve only on pending versions and Revoke only on approved ones', async () => {
    serve([approvedEntry, pendingEntry])
    renderPanel()

    await waitFor(() => expect(screen.getAllByTestId('workflow-approval-version')).toHaveLength(2))
    const [approved, pending] = screen.getAllByTestId('workflow-approval-version')
    expect(within(approved!).getByTestId('workflow-revoke-btn')).toBeInTheDocument()
    expect(within(approved!).queryByTestId('workflow-approve-btn')).toBeNull()
    expect(within(pending!).getByTestId('workflow-approve-btn')).toBeInTheDocument()
    expect(within(pending!).queryByTestId('workflow-revoke-btn')).toBeNull()
  })

  it('shows an error with retry when the list cannot be loaded', async () => {
    fetchMock.mockResolvedValue(json(500, { error: 'boom' }))
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('workflow-approvals-load-error')).toBeInTheDocument())
    expect(screen.getByTestId('workflow-approvals-load-error')).toHaveTextContent('500')
  })

  it('refuses a list whose mode is not one of the three', async () => {
    fetchMock.mockResolvedValue(json(200, envelope({ mode: 'bypass', workflows: [] })))
    renderPanel()

    await waitFor(() =>
      expect(screen.getByTestId('workflow-approvals-load-error')).toHaveTextContent(
        'unexpected response shape',
      ),
    )
  })

  it('shows the empty state', async () => {
    serve([])
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('workflow-approvals-empty')).toBeInTheDocument())
  })
})

describe('WorkflowApprovalPanel definition', () => {
  it('renders the definition as text and injects no DOM from a definition containing HTML', async () => {
    serve([pendingEntry])
    renderPanel()

    const def = await screen.findByTestId('workflow-approval-definition')
    expect(def.textContent).toContain(HOSTILE)
    expect(def.textContent).toContain('<b>bold</b>')
    expect(def.querySelector('img')).toBeNull()
    expect(def.querySelector('b')).toBeNull()
    expect(def.children).toHaveLength(0)
    expect(screen.getByTestId('workflow-approval-panel').querySelector('img')).toBeNull()
  })

  it('leaves the list summary fields out of the definition', async () => {
    serve([pendingEntry])
    renderPanel()

    const def = await screen.findByTestId('workflow-approval-definition')
    expect(def.textContent).not.toContain('trigger_count')
    expect(def.textContent).not.toContain('last_execution')
  })

  it('puts the Approve button beside the definition of the same version', async () => {
    serve([pendingEntry])
    renderPanel()

    const card = await screen.findByTestId('workflow-approval-version')
    expect(within(card).getByTestId('workflow-approval-definition')).toBeInTheDocument()
    expect(within(card).getByTestId('workflow-approve-btn')).toBeEnabled()
  })

  it('will not offer Approve for a version whose definition is not loaded', async () => {
    serve([{ ...pendingEntry, version: '0.9.0' }])
    renderPanel()

    expect(await screen.findByTestId('workflow-approval-definition-unavailable')).toBeInTheDocument()
    expect(screen.queryByTestId('workflow-approval-definition')).toBeNull()
    expect(screen.getByTestId('workflow-approve-btn')).toBeDisabled()
  })
})

describe('WorkflowApprovalPanel approve', () => {
  let posts: { token: string | null; body: unknown }[]

  /** The approve route demands a presence tap: 401 step-up until the token is sent. */
  function serveApprove(entries: object[]) {
    posts = []
    serve(entries, (url, init) => {
      const presence = presenceRoutes(url)
      if (presence) return presence
      if (url === LIST && init?.method === 'POST') {
        const token = new Headers(init.headers).get('X-Presence-Token')
        posts.push({ token, body: bodyOf(init) })
        if (['tap-token-1'].includes(token ?? '')) return json(201, envelope({ state: 'approved' }))
        return stepUpRequired('content-approval:approve')
      }
      return undefined
    })
  }

  it('sends the server-provided hashes after the presence tap and refreshes the list', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    serveApprove([pendingEntry])
    renderPanel()

    fireEvent.click(await screen.findByTestId('workflow-approve-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(posts).toHaveLength(1)
    expect(posts[0]!.token).toBeNull()
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    await waitFor(() => expect(posts).toHaveLength(2))
    expect(posts[1]!.token).toBe('tap-token-1')
    const expected = {
      workflow_id: 'deploy',
      version: '1.1.0',
      approval_hash: 'a-pending',
      content_hash: 'c-pending',
    }
    expect(posts[0]!.body).toEqual(expected)
    expect(posts[1]!.body).toEqual(expected)
    await waitFor(() =>
      expect(screen.getByTestId('workflow-approval-notice')).toHaveTextContent('Approval recorded'),
    )
    const listCalls = fetchMock.mock.calls.filter(
      ([u, i]) => String(u) === LIST && (i?.method ?? 'GET') === 'GET',
    )
    expect(listCalls.length).toBeGreaterThanOrEqual(2)
  })

  it('sends nothing more and approves nothing when the tap is cancelled', async () => {
    serveApprove([pendingEntry])
    renderPanel()

    fireEvent.click(await screen.findByTestId('workflow-approve-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('workflow-approval-error')).toHaveTextContent(/nothing was approved/i),
    )
    expect(posts).toHaveLength(1)
    expect(screen.queryByTestId('workflow-approval-notice')).toBeNull()
  })

  it('shows the server refusal, such as a hash mismatch', async () => {
    serve([pendingEntry], (url, init) =>
      url === LIST && init?.method === 'POST'
        ? json(409, { error: { code: 'HASH_MISMATCH', message: 'Hash does not match the stored workflow version' } })
        : undefined,
    )
    renderPanel()

    fireEvent.click(await screen.findByTestId('workflow-approve-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('workflow-approval-error')).toHaveTextContent(
        'Hash does not match the stored workflow version',
      ),
    )
  })
})

describe('WorkflowApprovalPanel revoke', () => {
  it('calls the revoke route with the id, version and approval hash and refreshes', async () => {
    let deleted: string | null = null
    serve([approvedEntry], (url, init) => {
      if (init?.method === 'DELETE') {
        deleted = url
        return new Response(null, { status: 204 })
      }
      return undefined
    })
    renderPanel()

    fireEvent.click(await screen.findByTestId('workflow-revoke-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('workflow-approval-notice')).toHaveTextContent('Approval revoked'),
    )
    expect(deleted).toBe(`${LIST}/deploy/1.0.0/a-approved`)
  })

  it('percent-encodes path segments so a hostile id cannot add a path', async () => {
    let deleted: string | null = null
    serve([{ ...approvedEntry, workflow_id: '../x/y', version: '1.0.0?z' }], (url, init) => {
      if (init?.method === 'DELETE') {
        deleted = url
        return new Response(null, { status: 204 })
      }
      return undefined
    })
    renderPanel()

    fireEvent.click(await screen.findByTestId('workflow-revoke-btn'))

    await waitFor(() => expect(deleted).not.toBeNull())
    expect(deleted).toBe(`${LIST}/..%2Fx%2Fy/1.0.0%3Fz/a-approved`)
  })

  it('shows the server message when revoke is refused', async () => {
    serve([approvedEntry], (_url, init) =>
      init?.method === 'DELETE'
        ? json(404, { error: { code: 'NOT_FOUND', message: 'Approval not found' } })
        : undefined,
    )
    renderPanel()

    fireEvent.click(await screen.findByTestId('workflow-revoke-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('workflow-approval-error')).toHaveTextContent('Approval not found'),
    )
  })
})

describe('Workflow library mode in WorkflowListView', () => {
  let mode: string
  let puts: { url: string; token: string | null; body: unknown }[]

  function serveLibrary() {
    puts = []
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      const presence = presenceRoutes(url)
      if (presence) return Promise.resolve(presence)
      if (url === '/api/v1/workflows' && method === 'GET') {
        return Promise.resolve(json(200, { workflows: [], count: 0 }))
      }
      if (url === LIST && method === 'GET') {
        return Promise.resolve(json(200, envelope({ mode, workflows: [] })))
      }
      if (url.endsWith('/libraries/workflow/mode') && method === 'GET') {
        return Promise.resolve(json(200, envelope({ kind: 'workflow', mode })))
      }
      if (url.endsWith('/libraries/workflow/mode') && method === 'PUT') {
        const token = new Headers(init?.headers).get('X-Presence-Token')
        const body = JSON.parse(String(init?.body)) as { mode: string }
        puts.push({ url, token, body })
        if (['tap-token-1'].includes(token ?? '')) {
          mode = body.mode
          return Promise.resolve(json(200, envelope({ kind: 'workflow', mode })))
        }
        return Promise.resolve(stepUpRequired('content-library:set-mode'))
      }
      return Promise.resolve(json(404, { error: 'unexpected request ' + method + ' ' + url }))
    })
  }

  function renderList() {
    return render(
      <MemoryRouter>
        <AuthProvider>
          <TenantScopeProvider rootPath="root">
            <WorkflowListView />
          </TenantScopeProvider>
        </AuthProvider>
      </MemoryRouter>,
    )
  }

  it('changes the mode of the workflow library only through the presence flow', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    mode = 'signed'
    serveLibrary()
    renderList()

    fireEvent.click(await screen.findByTestId('toggle-workflow-approvals-btn'))
    await waitFor(() => expect(screen.getByTestId('library-mode-signed')).toBeChecked())
    fireEvent.click(screen.getByTestId('library-mode-approve'))
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))
    expect(puts).toHaveLength(0)
    fireEvent.click(screen.getByTestId('library-mode-confirm-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(puts).toHaveLength(1)
    expect(puts[0]!.token).toBeNull()
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    await waitFor(() => expect(puts).toHaveLength(2))
    expect(puts[1]!.token).toBe('tap-token-1')
    expect(puts[1]!.url).toBe('/api/v1/automation/libraries/workflow/mode')
    expect(puts[1]!.body).toEqual({ mode: 'approve' })
    await waitFor(() => expect(screen.getByTestId('library-mode-approve')).toBeChecked())
  })

  it('leaves the mode unchanged when the tap is cancelled', async () => {
    mode = 'signed'
    serveLibrary()
    renderList()

    fireEvent.click(await screen.findByTestId('toggle-workflow-approvals-btn'))
    await waitFor(() => expect(screen.getByTestId('library-mode-signed')).toBeChecked())
    fireEvent.click(screen.getByTestId('library-mode-approve'))
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))
    fireEvent.click(screen.getByTestId('library-mode-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('library-mode-error')).toHaveTextContent(/mode was not changed/i),
    )
    expect(puts).toHaveLength(1)
    expect(mode).toBe('signed')
  })
})
