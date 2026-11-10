// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tests for AssertEdgeForm (Story #5464, Epic #5300).
 *
 * The form is exercised against a stubbed fetch that answers the two routes it
 * uses: GET /api/v1/entities (the To picker; Go struct field names as
 * serialised by writeEntityJSON) and POST /api/v1/entities/edges (201, no body).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import AssertEdgeForm from './AssertEdgeForm.tsx'
import { onStepUpRequired } from '../api/client.ts'

const FROM = 'eid:host:7f3a21c4'
const SQL02 = 'eid:cluster:hv-clu-01/vm/sql-02'

function entityPage(...rows: Array<[string, string]>) {
  return {
    Entities: rows.map(([EID, Kind]) => ({ Entity: { EID, Kind, Attributes: {}, OwningTenant: 't' } })),
    NextToken: '',
  }
}

interface Routes {
  entities?: () => Response
  edges?: () => Response
}

function stubFetch(routes: Routes = {}) {
  const stub = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.startsWith('/api/v1/entities/edges')) {
      return Promise.resolve(routes.edges ? routes.edges() : new Response(null, { status: 201 }))
    }
    if (url.startsWith('/api/v1/entities?')) {
      return Promise.resolve(
        routes.entities
          ? routes.entities()
          : new Response(JSON.stringify(entityPage([SQL02, 'vm'], ['eid:host:b19e0d72', 'host'])), {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            }),
      )
    }
    return Promise.reject(new Error(`unexpected ${init?.method ?? 'GET'} ${url}`))
  })
  vi.stubGlobal('fetch', stub)
  return stub
}

function posts(stub: ReturnType<typeof stubFetch>) {
  return (stub.mock.calls as unknown as Array<[string, RequestInit | undefined]>).filter(
    ([url]) => url === '/api/v1/entities/edges',
  )
}

function mount(props: Partial<React.ComponentProps<typeof AssertEdgeForm>> = {}) {
  const onClose = vi.fn()
  const onAsserted = vi.fn()
  render(
    <AssertEdgeForm
      fromEid={FROM}
      fromKind="host"
      onClose={onClose}
      onAsserted={onAsserted}
      {...props}
    />,
  )
  return { onClose, onAsserted }
}

async function pickTo(query = 'sql') {
  fireEvent.change(screen.getByLabelText('Search entities'), { target: { value: query } })
  const option = await screen.findByRole('option', { name: /sql-02/ })
  fireEvent.click(option)
}

function chooseType(value: string) {
  fireEvent.change(screen.getByLabelText(/^Relationship/), { target: { value } })
}

const submit = () => screen.getByRole('button', { name: 'Assert relationship' })

afterEach(() => {
  vi.unstubAllGlobals()
  onStepUpRequired(null)
})

describe('AssertEdgeForm', () => {
  it('pre-fills the pinned entity as From and starts with submit disabled', () => {
    stubFetch()
    mount()
    const dialog = screen.getByRole('dialog', { name: 'Assert relationship' })
    expect(within(dialog).getByText(FROM)).toBeInTheDocument()
    expect(within(dialog).getByText('From')).toBeInTheDocument()
    expect(within(dialog).getByText('Type to search the knowledge graph.')).toBeInTheDocument()
    expect(submit()).toBeDisabled()
  })

  it('offers the 12 standard edge types plus a custom related:<name>', () => {
    stubFetch()
    mount()
    const select = screen.getByLabelText(/^Relationship/) as HTMLSelectElement
    const values = Array.from(select.options).map((o) => o.value)
    expect(values).toEqual([
      '',
      'contains',
      'runs-on',
      'member-of',
      'depends-on',
      'serves',
      'connects-to',
      'manages',
      'managed-by',
      'assigned-to',
      'delegated-access',
      'reports-to',
      'same-as',
      'related',
    ])
  })

  it('searches the To picker with text_query, kind and page_size', async () => {
    const stub = stubFetch()
    mount()
    fireEvent.change(screen.getByLabelText('Kind'), { target: { value: 'vm' } })
    fireEvent.change(screen.getByLabelText('Search entities'), { target: { value: 'sql 02' } })
    await screen.findByRole('option', { name: /sql-02/ })
    const url = String(stub.mock.calls.find(([u]) => String(u).startsWith('/api/v1/entities?'))![0])
    const params = new URL(url, 'http://x').searchParams
    expect(params.get('text_query')).toBe('sql 02')
    expect(params.get('kind')).toBe('vm')
    expect(params.get('page_size')).toBe('20')
  })

  it('excludes the pinned entity from the results and shows a no-match message', async () => {
    stubFetch({
      entities: () => new Response(JSON.stringify(entityPage([FROM, 'host'])), { status: 200 }),
    })
    mount()
    fireEvent.change(screen.getByLabelText('Search entities'), { target: { value: 'web' } })
    expect(await screen.findByText('No matching entities.')).toBeInTheDocument()
  })

  it('shows a search failure without losing the form', async () => {
    stubFetch({ entities: () => new Response('query failed', { status: 500 }) })
    mount()
    fireEvent.change(screen.getByLabelText('Search entities'), { target: { value: 'sql' } })
    expect(await screen.findByText(/Search failed/)).toBeInTheDocument()
    expect(submit()).toBeDisabled()
  })

  // ── REQUIRED TEST ─────────────────────────────────────────────────────────
  it('AssertEdgeForm submit sends no step-up and no presence request', async () => {
    const stub = stubFetch()
    const stepUp = vi.fn(() => Promise.resolve(null))
    onStepUpRequired(stepUp)
    const { onAsserted } = mount()

    chooseType('depends-on')
    await pickTo()
    fireEvent.click(screen.getByRole('button', { name: /Add attribute/ }))
    fireEvent.change(screen.getByLabelText('Attribute key'), { target: { value: 'ticket' } })
    fireEvent.change(screen.getByLabelText('Attribute value'), { target: { value: 'INC-1042' } })
    fireEvent.click(submit())

    await waitFor(() => expect(onAsserted).toHaveBeenCalledTimes(1))

    // Exactly one request left the form for the assertion: a plain JSON POST.
    const sent = posts(stub)
    expect(sent).toHaveLength(1)
    const init = sent[0]![1]!
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({
      edge_type: 'depends-on',
      from_eid: FROM,
      to_eid: SQL02,
      attributes: { ticket: 'INC-1042' },
    })
    const names = Array.from(new Headers(init.headers).keys()).map((k) => k.toLowerCase())
    expect(names.filter((n) => n !== 'content-type' && n !== 'x-csrf-token')).toEqual([])
    // No step-up was requested and the drawer shows the no-passkey note.
    expect(stepUp).not.toHaveBeenCalled()
    expect(screen.getByText('Relationship recorded')).toBeInTheDocument()
    // Nothing but the picker search and the one POST was requested.
    const urls = (stub.mock.calls as unknown as string[][]).map((c) => c[0]!)
    expect(urls.filter((u) => !u.startsWith('/api/v1/entities'))).toEqual([])
  })

  it('shows the no-passkey note', () => {
    stubFetch()
    mount()
    expect(screen.getByText(/No passkey needed/)).toBeInTheDocument()
  })

  // ── REQUIRED TEST ─────────────────────────────────────────────────────────
  it('AssertEdgeForm rejects the pipe delimiter', async () => {
    const stub = stubFetch()
    mount()
    chooseType('related')
    await pickTo()

    const custom = screen.getByLabelText('Custom relationship name')
    fireEvent.change(custom, { target: { value: 'replica|primary' } })

    expect(custom).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByRole('alert')).toHaveTextContent(/Remove the \| character/)
    expect(submit()).toBeDisabled()
    fireEvent.click(submit())
    expect(posts(stub)).toHaveLength(0)

    // Fixing the name clears the error and enables submit.
    fireEvent.change(custom, { target: { value: 'backs-up' } })
    expect(custom).not.toHaveAttribute('aria-invalid')
    expect(submit()).toBeEnabled()
  })

  it('refuses a picked entity whose ID contains the pipe delimiter', async () => {
    const stub = stubFetch({
      entities: () => new Response(JSON.stringify(entityPage(['eid:host:a|b', 'host'])), { status: 200 }),
    })
    mount()
    chooseType('serves')
    fireEvent.change(screen.getByLabelText('Search entities'), { target: { value: 'a' } })
    fireEvent.click(await screen.findByRole('option', { name: /a\|b/ }))
    expect(screen.getByRole('alert')).toHaveTextContent(/Remove the \| character|can.t be used/)
    expect(submit()).toBeDisabled()
    expect(posts(stub)).toHaveLength(0)
  })

  it('uses related:<name> as the edge type and trims the name', async () => {
    const stub = stubFetch()
    mount()
    chooseType('related')
    fireEvent.change(screen.getByLabelText('Custom relationship name'), { target: { value: ' backs-up ' } })
    await pickTo()
    fireEvent.click(submit())
    await screen.findByText('Relationship recorded')
    expect(JSON.parse(posts(stub)[0]![1]!.body as string).edge_type).toBe('related:backs-up')
  })

  it('keeps submit disabled for related: with an empty name', async () => {
    stubFetch()
    mount()
    chooseType('related')
    await pickTo()
    expect(submit()).toBeDisabled()
  })

  it('swaps direction so the pinned entity becomes the edge target', async () => {
    const stub = stubFetch()
    mount()
    chooseType('serves')
    await pickTo()
    fireEvent.click(screen.getByRole('button', { name: /Swap direction/ }))
    fireEvent.click(submit())
    await screen.findByText('Relationship recorded')
    const body = JSON.parse(posts(stub)[0]![1]!.body as string)
    expect(body.from_eid).toBe(SQL02)
    expect(body.to_eid).toBe(FROM)
  })

  it('previews the relationship that will be recorded', async () => {
    stubFetch()
    mount()
    chooseType('depends-on')
    await pickTo()
    const preview = screen.getByTestId('assert-preview')
    expect(preview).toHaveTextContent('7f3a21c4')
    expect(preview).toHaveTextContent('depends-on')
    expect(preview).toHaveTextContent('sql-02')
  })

  it('removes an attribute row and omits blank keys from the request', async () => {
    const stub = stubFetch()
    mount()
    chooseType('contains')
    await pickTo()
    fireEvent.click(screen.getByRole('button', { name: /Add attribute/ }))
    fireEvent.click(screen.getByRole('button', { name: /Add attribute/ }))
    const keys = screen.getAllByLabelText('Attribute key')
    fireEvent.change(keys[0]!, { target: { value: 'reason' } })
    fireEvent.change(screen.getAllByLabelText('Attribute value')[0]!, { target: { value: 'because' } })
    fireEvent.click(screen.getAllByRole('button', { name: 'Remove attribute' })[1]!)
    expect(screen.getAllByLabelText('Attribute key')).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: /Add attribute/ }))
    fireEvent.click(submit())
    await screen.findByText('Relationship recorded')
    expect(JSON.parse(posts(stub)[0]![1]!.body as string).attributes).toEqual({ reason: 'because' })
  })

  it('disables the inputs and shows Asserting… while the request is in flight', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => {
      release = r
    })
    const stub = stubFetch()
    const inner = stub.getMockImplementation()!
    stub.mockImplementation(async (input, init) => {
      if (String(input).startsWith('/api/v1/entities/edges')) await gate
      return inner(input, init)
    })
    mount()
    chooseType('depends-on')
    await pickTo()
    fireEvent.click(submit())
    expect(await screen.findByRole('button', { name: /Asserting/ })).toBeDisabled()
    expect(screen.getByLabelText(/^Relationship/)).toBeDisabled()
    release()
    await screen.findByText('Relationship recorded')
  })

  it('shows a cross-tenant 404 without naming an endpoint and lets the operator choose again', async () => {
    stubFetch({ edges: () => new Response('not found\n', { status: 404 }) })
    const { onAsserted } = mount()
    chooseType('depends-on')
    await pickTo()
    fireEvent.click(submit())
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/isn.t in a tenant you can reach/)
    expect(alert).toHaveTextContent('404')
    expect(alert).not.toHaveTextContent(SQL02)
    expect(submit()).toBeDisabled()
    expect(onAsserted).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Choose another entity' }))
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByLabelText('Search entities')).toBeInTheDocument()
  })

  it('shows the crossing-required state and retries through Request access', async () => {
    let calls = 0
    const stub = stubFetch({
      edges: () => {
        calls += 1
        return calls === 1
          ? new Response(
              JSON.stringify({ break_glass_endpoint: '/api/v1/tenants/msp-b/break-glass' }),
              { status: 401, headers: { 'WWW-Authenticate': 'CFGMS-StepUp required="tenant-crossing"' } },
            )
          : new Response(null, { status: 201 })
      },
    })
    mount()
    chooseType('depends-on')
    await pickTo()
    fireEvent.click(submit())
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('msp-b')
    expect(alert).toHaveTextContent('tenant_crossing_required')
    fireEvent.click(screen.getByRole('button', { name: 'Request access…' }))
    await screen.findByText('Relationship recorded')
    expect(posts(stub)).toHaveLength(2)
  })

  it('keeps the entries and offers Try again after a server error', async () => {
    let calls = 0
    stubFetch({
      edges: () => {
        calls += 1
        return calls === 1 ? new Response('assertion failed\n', { status: 500 }) : new Response(null, { status: 201 })
      },
    })
    mount()
    chooseType('depends-on')
    await pickTo()
    fireEvent.click(submit())
    expect(await screen.findByRole('alert')).toHaveTextContent('500 · assertion failed')
    expect(screen.getByLabelText(/^Relationship/)).toHaveValue('depends-on')
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    await screen.findByText('Relationship recorded')
  })

  it('shows controller validation text from a 400', async () => {
    stubFetch({ edges: () => new Response('attribute key is too long\n', { status: 400 }) })
    mount()
    chooseType('depends-on')
    await pickTo()
    fireEvent.click(submit())
    expect(await screen.findByRole('alert')).toHaveTextContent('attribute key is too long')
  })

  it('Assert another resets the form and Done closes the drawer', async () => {
    stubFetch()
    const { onClose } = mount()
    chooseType('depends-on')
    await pickTo()
    fireEvent.click(submit())
    await screen.findByText('Relationship recorded')
    fireEvent.click(screen.getByRole('button', { name: 'Assert another' }))
    expect(screen.getByLabelText(/^Relationship/)).toHaveValue('')
    expect(submit()).toBeDisabled()

    chooseType('serves')
    await pickTo()
    fireEvent.click(submit())
    await screen.findByText('Relationship recorded')
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes on Escape, Cancel, the scrim and the close button', async () => {
    stubFetch()
    const { onClose } = mount()
    fireEvent.keyDown(document, { key: 'Escape' })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByTestId('assert-scrim'))
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalledTimes(4)
  })
})
