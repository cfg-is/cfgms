// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RowActionMenu suite (Story #2938): per-row action popover, stop-propagation
 * guard, and fully functional tag editor (add / remove via the tag endpoints,
 * state reflected immediately in the editor on each successful response).
 *
 * Security A10.2: parseTags validates the untrusted wire envelope; non-string
 * values in the tags array are dropped before any render.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RowActionMenu, { parseTags, parseQueuedCopies } from './RowActionMenu.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function mockTagsOk(tags: string[]) {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({ data: { tags }, timestamp: '' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  )
}

function mockTagsSeq(...responses: Array<{ status: number; tags?: string[] }>) {
  for (const r of responses) {
    fetchMock.mockResolvedValueOnce(
      new Response(
        r.tags !== undefined
          ? JSON.stringify({ data: { tags: r.tags }, timestamp: '' })
          : JSON.stringify({ error: 'fail' }),
        { status: r.status, headers: { 'Content-Type': 'application/json' } },
      ),
    )
  }
}

// ---------------------------------------------------------------------------
// parseTags unit tests
// ---------------------------------------------------------------------------

describe('parseTags (untrusted wire data)', () => {
  it('returns empty array for non-object data', () => {
    expect(parseTags(null)).toEqual([])
    expect(parseTags('string')).toEqual([])
    expect(parseTags(42)).toEqual([])
  })

  it('returns empty array when tags field is absent or not an array', () => {
    expect(parseTags({})).toEqual([])
    expect(parseTags({ tags: 'not-array' })).toEqual([])
    expect(parseTags({ tags: null })).toEqual([])
  })

  it('drops non-string values from the tags array', () => {
    expect(parseTags({ tags: ['prod', 42, null, 'dev', { obj: true }] })).toEqual([
      'prod',
      'dev',
    ])
  })

  it('returns a valid string array unchanged', () => {
    expect(parseTags({ tags: ['prod', 'dev', 'infra'] })).toEqual([
      'prod',
      'dev',
      'infra',
    ])
  })
})

// ---------------------------------------------------------------------------
// Kebab button behaviour
// ---------------------------------------------------------------------------

describe('kebab button', () => {
  it('renders a button with aria-label "Actions"', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    expect(screen.getByRole('button', { name: 'Actions' })).toBeInTheDocument()
  })

  it('click opens the action menu', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
  })

  it('second click closes the menu', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    const btn = screen.getByRole('button', { name: 'Actions' })
    fireEvent.click(btn)
    fireEvent.click(btn)
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('Escape closes the menu', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('click outside closes the menu', () => {
    render(
      <div>
        <div data-testid="outside">outside</div>
        <RowActionMenu stewardId="stw-1" />
      </div>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByTestId('outside'))
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('click stops propagation — does not reach parent onClick', () => {
    const parentClick = vi.fn()
    render(
      <div onClick={parentClick}>
        <RowActionMenu stewardId="stw-1" />
      </div>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(parentClick).not.toHaveBeenCalled()
  })

  it('menu shows "Edit tags" item', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menuitem', { name: 'Edit tags' })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Tag editor
// ---------------------------------------------------------------------------

describe('tag editor', () => {
  it('clicking "Edit tags" shows the tag editor with a text input', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))
    expect(screen.getByRole('textbox', { name: 'New tag' })).toBeInTheDocument()
  })

  it('fetches current tags from GET /stewards/:id/tags when the editor opens', async () => {
    mockTagsOk(['prod'])
    render(<RowActionMenu stewardId="stw-42" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    expect(await screen.findByText('prod')).toBeInTheDocument()

    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw-42/tags')
    expect((fetchMock.mock.calls[0]?.[1]?.method ?? 'GET').toUpperCase()).toBe('GET')
  })

  it('encodes special characters in the steward ID', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw/sp ec" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw%2Fsp%20ec/tags')
  })

  it('renders existing tags as removable chips', async () => {
    mockTagsOk(['prod', 'dev'])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    expect(await screen.findByText('prod')).toBeInTheDocument()
    expect(screen.getByText('dev')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove tag prod' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove tag dev' })).toBeInTheDocument()
  })

  it('shows "No tags" when the list is empty', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    expect(await screen.findByText('No tags')).toBeInTheDocument()
  })

  it('removing a tag calls DELETE and reflects the updated list', async () => {
    mockTagsSeq({ status: 200, tags: ['prod'] }, { status: 200, tags: [] })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag prod' }))

    await waitFor(() => expect(screen.getByText('No tags')).toBeInTheDocument())

    const delCall = fetchMock.mock.calls.find(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'DELETE',
    )
    expect(delCall).toBeDefined()
    const body = JSON.parse(String(delCall?.[1]?.body)) as { tags: string[] }
    expect(body.tags).toContain('prod')
  })

  it('shows an error alert when remove fails with non-200 status', async () => {
    mockTagsSeq({ status: 200, tags: ['prod'] }, { status: 422 })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag prod' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('422')
    // Tag still shown — the list was not updated after the failed remove.
    expect(screen.getByText('prod')).toBeInTheDocument()
  })

  it('shows an error alert when remove fails with a network error', async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { tags: ['prod'] }, timestamp: '' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockRejectedValueOnce(new Error('network down'))

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag prod' }))

    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })

  it('adding a tag calls POST and reflects the updated list', async () => {
    mockTagsSeq({ status: 200, tags: [] }, { status: 200, tags: ['dev'] })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByText('No tags')

    fireEvent.change(screen.getByRole('textbox', { name: 'New tag' }), {
      target: { value: 'dev' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(screen.getByText('dev')).toBeInTheDocument())

    const postCall = fetchMock.mock.calls.find(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'POST',
    )
    expect(postCall).toBeDefined()
    const body = JSON.parse(String(postCall?.[1]?.body)) as { tags: string[] }
    expect(body.tags).toContain('dev')
  })

  it('pressing Enter in the input adds a tag', async () => {
    mockTagsSeq({ status: 200, tags: [] }, { status: 200, tags: ['qa'] })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByText('No tags')

    const input = screen.getByRole('textbox', { name: 'New tag' })
    fireEvent.change(input, { target: { value: 'qa' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    await waitFor(() => expect(screen.getByText('qa')).toBeInTheDocument())
  })

  it('shows an error alert when the tag fetch fails (non-200 status)', async () => {
    mockTagsSeq({ status: 503 })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('503')
  })

  it('shows an error alert when add fails (non-200 status)', async () => {
    mockTagsSeq({ status: 200, tags: [] }, { status: 400 })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByText('No tags')
    fireEvent.change(screen.getByRole('textbox', { name: 'New tag' }), {
      target: { value: 'INVALID' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('400')
  })

  it('back button returns to the menu from the tag editor', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByRole('textbox', { name: 'New tag' })

    fireEvent.click(screen.getByRole('button', { name: 'Back to menu' }))

    expect(screen.getByRole('menuitem', { name: 'Edit tags' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Move to tenant (Story #2972)
// ---------------------------------------------------------------------------

describe('move to tenant', () => {
  it('menu shows "Move to tenant" item', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menuitem', { name: 'Move to tenant' })).toBeInTheDocument()
  })

  it('clicking "Move to tenant" shows the panel with a tenant ID input', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))
    expect(screen.getByRole('textbox', { name: 'New tenant ID' })).toBeInTheDocument()
  })

  it('move calls POST /stewards/:id/move with the new tenant ID', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { steward_id: 'stw-1', tenant_id: 'tenant-b', status: 'moved' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))

    fireEvent.change(screen.getByRole('textbox', { name: 'New tenant ID' }), {
      target: { value: 'tenant-b' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/stewards/stw-1/move')
    expect((init?.method ?? '').toUpperCase()).toBe('POST')
    const body = JSON.parse(String(init?.body)) as { new_tenant_id: string }
    expect(body.new_tenant_id).toBe('tenant-b')
  })

  it('move encodes special characters in the steward ID', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(<RowActionMenu stewardId="stw/sp ec" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))

    fireEvent.change(screen.getByRole('textbox', { name: 'New tenant ID' }), {
      target: { value: 'tid' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/stewards/stw%2Fsp%20ec/move')
  })

  it('move success shows a status message', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { steward_id: 'stw-1', tenant_id: 'tenant-b', status: 'moved' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))

    fireEvent.change(screen.getByRole('textbox', { name: 'New tenant ID' }), {
      target: { value: 'tenant-b' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))

    expect(await screen.findByRole('status')).toBeInTheDocument()
  })

  it('move error shows an alert with the status code', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))

    fireEvent.change(screen.getByRole('textbox', { name: 'New tenant ID' }), {
      target: { value: 'nonexistent' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('404')
  })

  it('"Move" is disabled when the tenant input is empty', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))
    expect(screen.getByRole('button', { name: 'Move' })).toBeDisabled()
  })

  it('back button returns to the menu from the move panel', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Move to tenant' }))

    expect(screen.getByRole('textbox', { name: 'New tenant ID' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Back to menu' }))

    expect(screen.getByRole('menuitem', { name: 'Move to tenant' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Decommission (Story #2972)
// ---------------------------------------------------------------------------

describe('decommission', () => {
  it('menu shows "Decommission" item', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menuitem', { name: 'Decommission' })).toBeInTheDocument()
  })

  it('clicking "Decommission" shows the confirmation panel', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Decommission' }))
    expect(screen.getByRole('button', { name: 'Confirm decommission' })).toBeInTheDocument()
  })

  it('confirming decommission calls DELETE /stewards/:id', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { id: 'stw-1', status: 'deregistered' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Decommission' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/stewards/stw-1')
    expect((init?.method ?? '').toUpperCase()).toBe('DELETE')
  })

  it('decommission encodes special characters in the steward ID', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    render(<RowActionMenu stewardId="stw/sp ec" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Decommission' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/stewards/stw%2Fsp%20ec')
  })

  it('decommission success shows a status message', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { id: 'stw-1', status: 'deregistered' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Decommission' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    expect(await screen.findByRole('status')).toBeInTheDocument()
  })

  it('decommission error shows an alert with the status code', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'unauthorized' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Decommission' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm decommission' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('403')
  })

  it('back button returns to the menu from the decommission panel', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Decommission' }))

    expect(screen.getByRole('button', { name: 'Confirm decommission' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Back to menu' }))

    expect(screen.getByRole('menuitem', { name: 'Decommission' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Confirm decommission' })).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Steward identity row actions (Story #5443)
// ---------------------------------------------------------------------------

function jsonRes(status: number, body: unknown = {}, headers: Record<string, string> = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const ELEVATION_CHALLENGE = { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong"' }

const CLONES = {
  data: [
    {
      steward_id: 'other',
      tenant_id: 't',
      detection_count: 1,
      queued_copies: [{ pending_id: 'p-other', hostname: 'other-host', source_ip: '1.1.1.1', registered_at: 'x' }],
    },
    {
      steward_id: 'stw-1',
      tenant_id: 't',
      detection_count: 2,
      queued_copies: [
        { pending_id: 'p-1', hostname: 'host-a', source_ip: '10.0.0.1', registered_at: '2026-10-01T00:00:00Z' },
        { pending_id: 'p-2', hostname: '<b>host-b</b>', source_ip: '10.0.0.2', registered_at: '2026-10-02T00:00:00Z' },
      ],
    },
  ],
}

function renderMenu(stewardId = 'stw-1') {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RowActionMenu stewardId={stewardId} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function openItem(name: string) {
  fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
  fireEvent.click(screen.getByRole('menuitem', { name }))
}

function stubElevation(target: (u: string, m: string) => Response | null) {
  vi.stubGlobal('navigator', {
    credentials: {
      get: vi.fn().mockResolvedValue({
        id: 'c',
        type: 'public-key',
        rawId: new ArrayBuffer(1),
        response: {
          clientDataJSON: new ArrayBuffer(1),
          authenticatorData: new ArrayBuffer(1),
          signature: new ArrayBuffer(1),
          userHandle: null,
        },
        getClientExtensionResults: () => ({}),
        authenticatorAttachment: null,
      }),
    },
  })
  let elevated = false
  fetchMock.mockImplementation((input, init) => {
    const u = String(input)
    const m = (init?.method ?? 'GET').toUpperCase()
    if (u.includes('elevate/begin')) {
      return Promise.resolve(
        jsonRes(200, {
          data: {
            publicKey: { challenge: 'Y2g', timeout: 60000, rpId: 'localhost', allowCredentials: [], userVerification: 'required' },
          },
        }),
      )
    }
    if (u.includes('elevate/finish')) {
      elevated = true
      return Promise.resolve(jsonRes(200, { assurance: 'strong' }))
    }
    const r = target(u, m)
    if (r !== null && !elevated && m === 'POST') return Promise.resolve(jsonRes(401, {}, ELEVATION_CHALLENGE))
    return Promise.resolve(r ?? jsonRes(404))
  })
}

describe('parseQueuedCopies (untrusted wire data)', () => {
  it('returns copies only of the matching steward and drops malformed ones', () => {
    const data = [
      { steward_id: 'a', queued_copies: [{ pending_id: 'x' }] },
      { steward_id: 'b', queued_copies: [{ pending_id: 'p', hostname: 'h' }, { pending_id: 3 }, null, { pending_id: '' }] },
    ]
    expect(parseQueuedCopies(data, 'b')).toEqual([
      { pendingId: 'p', hostname: 'h', sourceIp: '', registeredAt: '' },
    ])
    expect(parseQueuedCopies('nope', 'b')).toEqual([])
    expect(parseQueuedCopies(data, 'missing')).toEqual([])
  })
})

describe('RowActionMenu rotate and move-identity handle elevation 401 without a presence token', () => {
  it('rotate: confirm names the steward, sends nothing until Confirm, retries without X-Presence-Token', async () => {
    stubElevation((u, m) => (m === 'POST' && u.endsWith('/credentials/rotate') ? jsonRes(200, { data: { status: 'archived' } }) : null))
    renderMenu()
    openItem('Rotate credentials')
    fireEvent.click(screen.getByRole('button', { name: 'Rotate credentials' }))
    expect(screen.getByText(/stw-1/)).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Credentials rotated'))
    const posts = fetchMock.mock.calls.filter(([u]) => String(u).endsWith('/stewards/stw-1/credentials/rotate'))
    expect(posts).toHaveLength(2)
    expect(new Headers(posts[1]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('presence/begin'))).toBe(false)
  })

  it('move identity: retries after elevation without X-Presence-Token', async () => {
    stubElevation((u, m) => {
      if (m === 'GET' && u.endsWith('/stewards/identity-clones')) return jsonRes(200, CLONES)
      if (m === 'POST' && u.endsWith('/identity/move')) return jsonRes(200, { data: { status: 'moved' } })
      return null
    })
    renderMenu()
    openItem('Move identity')
    fireEvent.click(await screen.findByRole('radio', { name: /host-a/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))
    expect(screen.getByText(/stw-1/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Identity moved'))
    const posts = fetchMock.mock.calls.filter(([u]) => String(u).endsWith('/identity/move'))
    expect(posts).toHaveLength(2)
    expect(new Headers(posts[1]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
  })
})

describe('RowActionMenu move-identity', () => {
  it('sends the selected pending_id', async () => {
    fetchMock.mockImplementation((input, init) => {
      const u = String(input)
      if (u.endsWith('/stewards/identity-clones')) return Promise.resolve(jsonRes(200, CLONES))
      if ((init?.method ?? 'GET') === 'POST') return Promise.resolve(jsonRes(200, { data: { status: 'moved' } }))
      return Promise.resolve(jsonRes(404))
    })
    renderMenu()
    openItem('Move identity')
    await screen.findByText('host-a')
    expect(screen.getByText('<b>host-b</b>')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument()
    expect(screen.queryByText('other-host')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Move' })).toBeDisabled()
    fireEvent.click(screen.getByRole('radio', { name: /host-b/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Identity moved'))
    const post = fetchMock.mock.calls.find(([, i]) => (i?.method ?? 'GET') === 'POST')
    expect(String(post?.[0])).toBe('/api/v1/stewards/stw-1/identity/move')
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ pending_id: 'p-2' })
  })

  it('Cancel returns without sending', async () => {
    fetchMock.mockResolvedValue(jsonRes(200, CLONES))
    renderMenu()
    openItem('Move identity')
    fireEvent.click(await screen.findByRole('radio', { name: /host-a/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Move' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Move' })).toBeInTheDocument()
  })

  it('shows an empty state and no Move button when the steward has no queued copy', async () => {
    fetchMock.mockResolvedValue(jsonRes(200, { data: [] }))
    renderMenu()
    openItem('Move identity')
    expect(await screen.findByText(/No queued copies/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Move' })).not.toBeInTheDocument()
  })

  it('shows an alert when the list fails to load', async () => {
    fetchMock.mockResolvedValue(jsonRes(500, {}))
    renderMenu()
    openItem('Move identity')
    expect(await screen.findByRole('alert')).toHaveTextContent('500')
  })
})

describe('RowActionMenu auth refresh', () => {
  it('auth refresh posts with no step-up and no presence request, and reports refresh_requested', async () => {
    fetchMock.mockResolvedValue(jsonRes(200, { data: { steward_id: 'stw-1', status: 'refresh_requested' } }))
    renderMenu()
    openItem('Refresh auth')
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Auth refresh requested'))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/stewards/stw-1/auth/refresh')
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('POST')
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('/webauthn/presence/begin'))).toBe(false)
  })

  it('shows an alert on failure', async () => {
    fetchMock.mockResolvedValue(jsonRes(404, {}))
    renderMenu()
    openItem('Refresh auth')
    expect(await screen.findByRole('alert')).toHaveTextContent('404')
  })
})
