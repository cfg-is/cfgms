// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * OsqueryView test suite (Issue #5460, Epic #5300). Real AuthProvider, apiFetch
 * and StepUpModal; only global fetch is stubbed at the network edge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import OsqueryView from './OsqueryView.tsx'

const fetchMock = vi.fn<typeof fetch>()
const catalogUrl = '/api/v1/osquery/catalog'
const queryUrl = '/api/v1/osquery/query'

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
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

const catalog = [
  { id: 'file_info', params: [{ name: 'path', type: 'charset' }] },
  { id: 'host_info', params: [] },
  {
    id: 'process_list',
    params: [{ name: 'name_prefix', type: 'enum', allowed_values: ['cfgms', 'osquery', 'steward'] }],
  },
]

type QueryHandler = (init: RequestInit | undefined) => Response | Promise<Response>

function serve(query: QueryHandler, catalogResponse: () => Response = () => jsonResponse(200, envelope(catalog))) {
  fetchMock.mockImplementation((url, init) => {
    const u = String(url)
    if (u === catalogUrl) return Promise.resolve(catalogResponse())
    if (u === queryUrl) return Promise.resolve(query(init))
    return Promise.resolve(jsonResponse(404))
  })
}

function queryCalls() {
  return fetchMock.mock.calls.filter(([u]) => String(u) === queryUrl)
}

function renderView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <OsqueryView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

async function ready() {
  const select = (await screen.findByTestId('osq-catalog')) as HTMLSelectElement
  await waitFor(() => expect(select.options.length).toBe(catalog.length))
  return select
}

async function run(selector = 'tag:edge') {
  await ready()
  fireEvent.change(screen.getByLabelText('Stewards'), { target: { value: selector } })
  fireEvent.click(screen.getByTestId('osq-run-btn'))
}

const rowsFor = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ name: `proc-${i}`, pid: String(1000 + i) }))

describe('OsqueryView catalog picker', () => {
  it('builds the picker and the parameter inputs from the catalog schema', async () => {
    serve(() => jsonResponse(200, envelope({ results: [] })))
    renderView()
    const select = await ready()
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['file_info', 'host_info', 'process_list'])
    // The catalog is a closed list: there is no free-text catalog id or SQL input.
    expect(screen.queryByLabelText(/catalog id/i)).toBeNull()
    expect(screen.getAllByRole('textbox')).toHaveLength(2) // the charset param + the selector

    // charset → text field
    const path = screen.getByTestId('osq-param-path')
    expect(path.tagName).toBe('INPUT')

    // enum → select with exactly the allowed values, first one preselected
    fireEvent.change(select, { target: { value: 'process_list' } })
    const prefix = screen.getByTestId('osq-param-name_prefix') as HTMLSelectElement
    expect(prefix.tagName).toBe('SELECT')
    expect(Array.from(prefix.options).map((o) => o.value)).toEqual(['cfgms', 'osquery', 'steward'])
    expect(prefix.value).toBe('cfgms')
    expect(screen.queryByTestId('osq-param-path')).toBeNull()

    // no params → an explicit note
    fireEvent.change(select, { target: { value: 'host_info' } })
    expect(screen.getByTestId('osq-no-params')).toBeInTheDocument()
  })

  it('shows a loading state and then the catalog error with a working retry', async () => {
    let attempts = 0
    serve(
      () => jsonResponse(200, envelope({ results: [] })),
      () => (++attempts === 1 ? jsonResponse(500) : jsonResponse(200, envelope(catalog))),
    )
    renderView()
    expect(screen.getByTestId('osq-catalog-loading')).toBeInTheDocument()
    expect(await screen.findByTestId('osq-catalog-error')).toBeInTheDocument()
    expect(screen.getByTestId('osq-run-btn')).toBeDisabled()
    fireEvent.click(screen.getByTestId('osq-catalog-retry'))
    await ready()
    expect(screen.getByTestId('osq-run-btn')).toBeEnabled()
  })
})

describe('OsqueryView query request', () => {
  it('posts catalog_id, params and selector', async () => {
    serve(() => jsonResponse(200, envelope({ results: [{ steward_id: 's1', rows: rowsFor(1) }] })))
    renderView()
    const select = await ready()
    fireEvent.change(select, { target: { value: 'process_list' } })
    fireEvent.change(screen.getByTestId('osq-param-name_prefix'), { target: { value: 'osquery' } })
    fireEvent.change(screen.getByLabelText('Stewards'), { target: { value: 'acme-corp/tag:edge' } })
    fireEvent.click(screen.getByTestId('osq-run-btn'))
    await screen.findByTestId('osq-card')
    expect(JSON.parse(String(queryCalls()[0]?.[1]?.body))).toEqual({
      catalog_id: 'process_list',
      params: { name_prefix: 'osquery' },
      selector: 'acme-corp/tag:edge',
    })
  })

  it('does not send a request for an empty selector', async () => {
    serve(() => jsonResponse(200, envelope({ results: [] })))
    renderView()
    await ready()
    fireEvent.click(screen.getByTestId('osq-run-btn'))
    expect(await screen.findByTestId('osq-selector-error')).toHaveTextContent(/selector is required/i)
    expect(queryCalls()).toHaveLength(0)
  })

  it('OsqueryView query sends X-Presence-Token after the tap', async () => {
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
    fetchMock.mockImplementation((url, init) => {
      const u = String(url)
      if (u === catalogUrl) return Promise.resolve(jsonResponse(200, envelope(catalog)))
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
      if (u === queryUrl) {
        if (new Headers(init?.headers).get('X-Presence-Token') !== 'tap-token-1') {
          return Promise.resolve(
            jsonResponse(
              401,
              { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
              {
                'WWW-Authenticate':
                  'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="osquery:execute"',
              },
            ),
          )
        }
        return Promise.resolve(
          jsonResponse(200, envelope({ results: [{ steward_id: 'steward-1', rows: rowsFor(1) }] })),
        )
      }
      return Promise.resolve(jsonResponse(404))
    })

    renderView()
    await run()
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    // Nothing has run until the admin taps.
    expect(queryCalls()).toHaveLength(1)
    expect(screen.queryByTestId('osq-card')).toBeNull()
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    expect(await screen.findByTestId('osq-card')).toBeInTheDocument()
    const posts = queryCalls()
    expect(posts).toHaveLength(2)
    expect(new Headers(posts[0]?.[1]?.headers).get('X-Presence-Token')).toBeNull()
    expect(new Headers(posts[1]?.[1]?.headers).get('X-Presence-Token')).toBe('tap-token-1')
  })

  it('a cancelled presence tap shows "Not run" and no results', async () => {
    serve(() =>
      jsonResponse(
        401,
        { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
        { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms", required="strong", presence="required"' },
      ),
    )
    renderView()
    await run()
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(await screen.findByTestId('step-up-cancel-btn'))
    expect(await screen.findByTestId('osq-state-cancelled')).toHaveTextContent(/nothing was sent/i)
    expect(queryCalls()).toHaveLength(1)
    expect(screen.queryByTestId('osq-card')).toBeNull()
    expect(screen.getByTestId('osq-results-idle')).toBeInTheDocument()
  })
})

describe('OsqueryView results', () => {
  it('OsqueryView renders cell values as text', async () => {
    const hostile = '<img src=x onerror=alert(1)>'
    serve(() =>
      jsonResponse(
        200,
        envelope({
          results: [
            { steward_id: 'steward-<b>1</b>', rows: [{ cmdline: 'cfgms --label "<b>edge-a</b>"', name: hostile }] },
            { steward_id: 'steward-2', error: '<script>alert(2)</script>' },
          ],
        }),
      ),
    )
    const { container } = renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    const cells = screen.getAllByTestId('osq-cell').map((c) => c.textContent)
    expect(cells).toContain(hostile)
    expect(cells).toContain('cfgms --label "<b>edge-a</b>"')
    expect(screen.getByText('steward-<b>1</b>')).toBeInTheDocument()
    expect(screen.getByTestId('osq-error-text')).toHaveTextContent('<script>alert(2)</script>')
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
    expect(container.querySelector('script')).toBeNull()
  })

  it('renders one card per steward, identified by steward_id, with error and no-rows cards distinct', async () => {
    serve(() =>
      jsonResponse(
        200,
        envelope({
          results: [
            { steward_id: 'steward-a', rows: rowsFor(2) },
            { steward_id: 'steward-b', error: 'steward did not respond: deadline exceeded' },
            { steward_id: 'steward-c' },
            { steward_id: 'steward-d', rows: rowsFor(1) },
          ],
        }),
      ),
    )
    renderView()
    await run()
    const cards = await screen.findAllByTestId('osq-card')
    // Answered cards keep server order; failed cards follow them.
    expect(cards.map((c) => c.getAttribute('data-kind'))).toEqual(['rows', 'none', 'rows', 'err'])
    expect(cards.map((c) => within(c).getByTestId('osq-steward-id').textContent)).toEqual([
      'steward-a',
      'steward-c',
      'steward-d',
      'steward-b',
    ])
    expect(within(cards[3]!).getByTestId('osq-error-text')).toHaveTextContent('steward did not respond')
    expect(within(cards[3]!).queryByRole('table')).toBeNull()
    expect(within(cards[1]!).getByTestId('osq-none-text')).toHaveTextContent(/returned nothing/i)
    expect(within(cards[1]!).queryByRole('table')).toBeNull()
    expect(within(cards[0]!).getByRole('table')).toBeInTheDocument()
    // The API returns no hostname; the view never shows one.
    expect(screen.queryByText(/hostname/i)).toBeNull()
  })

  it('derives the tally and the filters from the response', async () => {
    serve(() =>
      jsonResponse(
        200,
        envelope({
          results: [
            { steward_id: 'steward-a', rows: rowsFor(2) },
            { steward_id: 'steward-b', error: 'boom' },
            { steward_id: 'steward-c' },
            { steward_id: 'steward-d' },
          ],
        }),
      ),
    )
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    const tally = screen.getByTestId('osq-tally')
    expect(tally).toHaveTextContent('4 stewards')
    expect(tally).toHaveTextContent('1 with rows')
    expect(tally).toHaveTextContent('2 no rows')
    expect(tally).toHaveTextContent('1 failed')

    const ids = () => screen.getAllByTestId('osq-steward-id').map((n) => n.textContent)
    fireEvent.click(screen.getByTestId('osq-filter-rows'))
    expect(ids()).toEqual(['steward-a'])
    fireEvent.click(screen.getByTestId('osq-filter-none'))
    expect(ids()).toEqual(['steward-c', 'steward-d'])
    fireEvent.click(screen.getByTestId('osq-filter-err'))
    expect(ids()).toEqual(['steward-b'])
    expect(screen.getByTestId('osq-filter-err')).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getByTestId('osq-filter-all'))
    expect(ids()).toHaveLength(4)
  })

  it('previews five rows and expands with Show all', async () => {
    serve(() => jsonResponse(200, envelope({ results: [{ steward_id: 'steward-a', rows: rowsFor(8) }] })))
    renderView()
    await run()
    await screen.findByTestId('osq-card')
    const body = () => within(screen.getByRole('table')).getAllByRole('row').length - 1
    expect(body()).toBe(5)
    expect(screen.getByTestId('osq-more')).toHaveTextContent('Showing 5 of 8 rows')
    fireEvent.click(screen.getByTestId('osq-show-all'))
    expect(body()).toBe(8)
    expect(screen.getByTestId('osq-more')).toHaveTextContent('Showing all 8 rows')
    fireEvent.click(screen.getByTestId('osq-show-all'))
    expect(body()).toBe(5)
  })

  it('shows no Show all control for five rows or fewer, and an em dash for empty values', async () => {
    serve(() =>
      jsonResponse(200, envelope({ results: [{ steward_id: 'steward-a', rows: [{ name: 'x', cmdline: '' }] }] })),
    )
    renderView()
    await run()
    await screen.findByTestId('osq-card')
    expect(screen.queryByTestId('osq-show-all')).toBeNull()
    expect(screen.getByTestId('osq-cell-empty')).toHaveTextContent('—')
  })

  it('collapses and expands a result card', async () => {
    serve(() => jsonResponse(200, envelope({ results: [{ steward_id: 'steward-a', rows: rowsFor(2) }] })))
    renderView()
    await run()
    await screen.findByTestId('osq-card')
    fireEvent.click(screen.getByTestId('osq-collapse'))
    expect(screen.queryByRole('table')).toBeNull()
    expect(screen.getByTestId('osq-collapse')).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(screen.getByTestId('osq-collapse'))
    expect(screen.getByRole('table')).toBeInTheDocument()
  })
})

describe('OsqueryView outcomes and summary', () => {
  // A server time three hours back, so its hour:minute differs from the test clock.
  const queriedAtMs = Math.floor((Date.now() - 3 * 3_600_000) / 1000) * 1000
  const queriedAt = new Date(queriedAtMs).toISOString()
  const seen23mBefore = new Date(queriedAtMs - 23 * 60_000).toISOString()
  const notConnectedError = 'osquery: steward not connected to osquery stream'

  const mixed = () => ({
    summary: { matched: 5, answered: 2, not_connected: 2, failed: 1, queried_at: queriedAt },
    results: [
      { steward_id: 'steward-off-1', error: notConnectedError, outcome: 'not_connected', last_seen: seen23mBefore },
      { steward_id: 'steward-rows', rows: rowsFor(2), outcome: 'answered' },
      { steward_id: 'steward-failed', error: 'osquery execution failed', outcome: 'failed' },
      { steward_id: 'steward-off-2', error: notConnectedError, outcome: 'not_connected' },
      { steward_id: 'steward-empty', outcome: 'answered' },
    ],
  })

  it('the tally shows the summary the API returned', async () => {
    serve(() => jsonResponse(200, envelope(mixed())))
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    expect(screen.getByTestId('osq-tally-matched')).toHaveTextContent('5 stewards matched ·')
    expect(screen.getByTestId('osq-tally-answered')).toHaveTextContent('2 answered')
    expect(screen.getByTestId('osq-tally-unreached')).toHaveTextContent('2 not reached')
    expect(screen.getByTestId('osq-tally-failed')).toHaveTextContent('1 failed')
    expect(screen.getByTestId('osq-tally-breakdown')).toHaveTextContent('1 with rows · 1 no rows')
  })

  it('the tally numbers are the API numbers, not a recount of the results', async () => {
    const body = mixed()
    body.summary = { matched: 9, answered: 4, not_connected: 3, failed: 2, queried_at: queriedAt }
    serve(() => jsonResponse(200, envelope(body)))
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    expect(screen.getByTestId('osq-tally-matched')).toHaveTextContent('9 stewards matched ·')
    expect(screen.getByTestId('osq-tally-answered')).toHaveTextContent('4 answered')
    expect(screen.getByTestId('osq-tally-unreached')).toHaveTextContent('3 not reached')
    expect(screen.getByTestId('osq-tally-failed')).toHaveTextContent('2 failed')
  })

  it('lists not-reached stewards as one group, apart from the failed card', async () => {
    serve(() => jsonResponse(200, envelope(mixed())))
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')

    const groups = screen.getAllByTestId('osq-unreached-group')
    expect(groups).toHaveLength(1)
    const group = groups[0]!
    expect(group).toHaveAttribute('data-kind', 'unreached')
    expect(group).toHaveTextContent(
      '2 stewards had no connection to the controller node that ran the query. Nothing was sent to them.',
    )
    expect(screen.getByRole('region', { name: 'Not reached' })).toBe(group)
    const items = within(group).getAllByTestId('osq-unreached-item')
    expect(items.map((li) => within(li).getByTestId('osq-steward-id').textContent)).toEqual([
      'steward-off-1',
      'steward-off-2',
    ])
    const first = within(items[0]!).getByTestId('osq-last-seen')
    expect(first).toHaveTextContent('last seen 23m ago')
    expect(first.querySelector('time')).toHaveAttribute('dateTime', new Date(seen23mBefore).toISOString())
    expect(within(items[1]!).getByTestId('osq-last-seen')).toHaveTextContent('no check-in recorded')
    expect(items[1]!.querySelector('time')).toBeNull()

    // The failed steward keeps the Error card and is not in the group.
    expect(within(group).queryByText('steward-failed')).toBeNull()
    const cards = screen.getAllByTestId('osq-card')
    expect(cards.map((c) => c.getAttribute('data-kind'))).toEqual(['rows', 'none', 'err'])
    expect(within(cards[2]!).getByTestId('osq-steward-id')).toHaveTextContent('steward-failed')
    expect(within(cards[2]!).getByTestId('osq-error-text')).toHaveTextContent('osquery execution failed')
    // The not-reached stewards' error text is not shown.
    expect(screen.queryByText(notConnectedError, { exact: false })).toBeNull()

    // Answered cards, then the group, then the failed card.
    const follows = (a: Element, b: Element) =>
      (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
    expect(follows(cards[0]!, cards[1]!)).toBe(true)
    expect(follows(cards[1]!, group)).toBe(true)
    expect(follows(group, cards[2]!)).toBe(true)
  })

  it('the Not reached filter shows only the group and Failed only the failed card', async () => {
    serve(() => jsonResponse(200, envelope(mixed())))
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    expect(screen.getByTestId('osq-filter-unreached')).toHaveTextContent('Not reached')
    expect(screen.getByTestId('osq-filter-err')).toHaveTextContent('Failed')

    fireEvent.click(screen.getByTestId('osq-filter-unreached'))
    expect(screen.getByTestId('osq-unreached-group')).toBeInTheDocument()
    expect(screen.queryAllByTestId('osq-card')).toHaveLength(0)
    expect(screen.getAllByTestId('osq-steward-id').map((n) => n.textContent)).toEqual([
      'steward-off-1',
      'steward-off-2',
    ])

    fireEvent.click(screen.getByTestId('osq-filter-err'))
    expect(screen.queryByTestId('osq-unreached-group')).toBeNull()
    const cards = screen.getAllByTestId('osq-card')
    expect(cards).toHaveLength(1)
    expect(cards[0]).toHaveAttribute('data-kind', 'err')
    expect(within(cards[0]!).getByTestId('osq-steward-id')).toHaveTextContent('steward-failed')
  })

  it('the header shows the server queried_at as the ran time', async () => {
    serve(() => jsonResponse(200, envelope(mixed())))
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    const expected = new Date(queriedAtMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    expect(screen.getByTestId('osq-ran-time')).toHaveTextContent(`· ran ${expected}`)
  })

  it('an older response without summary or outcome derives the tally and shows no group', async () => {
    serve(() =>
      jsonResponse(
        200,
        envelope({
          results: [
            { steward_id: 'steward-a', rows: rowsFor(1) },
            { steward_id: 'steward-b', error: 'boom' },
            { steward_id: 'steward-c' },
          ],
        }),
      ),
    )
    renderView()
    await run()
    await screen.findAllByTestId('osq-card')
    expect(screen.getByTestId('osq-tally-matched')).toHaveTextContent('3 stewards matched ·')
    expect(screen.getByTestId('osq-tally-answered')).toHaveTextContent('2 answered')
    expect(screen.getByTestId('osq-tally-unreached')).toHaveTextContent('0 not reached')
    expect(screen.getByTestId('osq-tally-failed')).toHaveTextContent('1 failed')
    expect(screen.queryByTestId('osq-unreached-group')).toBeNull()
    expect(screen.getAllByTestId('osq-card').map((c) => c.getAttribute('data-kind'))).toEqual([
      'rows',
      'none',
      'err',
    ])
  })

  it('renders a hostile not-reached steward id as text', async () => {
    const hostile = '<img src=x onerror=alert(1)>'
    serve(() =>
      jsonResponse(
        200,
        envelope({
          summary: { matched: 1, answered: 0, not_connected: 1, failed: 0, queried_at: queriedAt },
          results: [{ steward_id: hostile, error: notConnectedError, outcome: 'not_connected', last_seen: seen23mBefore }],
        }),
      ),
    )
    const { container } = renderView()
    await run()
    const group = await screen.findByTestId('osq-unreached-group')
    expect(within(group).getByTestId('osq-steward-id').textContent).toBe(hostile)
    expect(group.querySelector('img')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
  })

  it('the time dateTime is the normalised ISO form, not the wire string', async () => {
    serve(() =>
      jsonResponse(
        200,
        envelope({
          summary: { matched: 1, answered: 0, not_connected: 1, failed: 0, queried_at: queriedAt },
          results: [
            { steward_id: 'steward-off', error: notConnectedError, outcome: 'not_connected', last_seen: '2026-11-22T13:40:00Z' },
          ],
        }),
      ),
    )
    renderView()
    await run()
    const group = await screen.findByTestId('osq-unreached-group')
    expect(group).toHaveTextContent(
      '1 steward had no connection to the controller node that ran the query. Nothing was sent to them.',
    )
    expect(group.querySelector('time')).toHaveAttribute('dateTime', '2026-11-22T13:40:00.000Z')
  })

  it('a leniently parsed hostile last_seen never reaches an attribute or text verbatim', async () => {
    const hostileSeen = '2026-01-01 (<b>x</b>)'
    serve(() =>
      jsonResponse(
        200,
        envelope({
          summary: { matched: 1, answered: 0, not_connected: 1, failed: 0, queried_at: queriedAt },
          results: [{ steward_id: 'steward-off', error: notConnectedError, outcome: 'not_connected', last_seen: hostileSeen }],
        }),
      ),
    )
    const { container } = renderView()
    await run()
    const group = await screen.findByTestId('osq-unreached-group')
    expect(group.textContent).not.toContain(hostileSeen)
    expect(group.textContent).not.toContain('<b>')
    for (const el of [group, ...Array.from(group.querySelectorAll('*'))]) {
      for (const attr of Array.from(el.attributes)) {
        expect(attr.value).not.toContain(hostileSeen)
        expect(attr.value).not.toContain('<b>')
      }
    }
    expect(container.querySelector('b')).toBeNull()
    const seen = within(group).getByTestId('osq-last-seen')
    const time = seen.querySelector('time')
    if (time === null) {
      expect(seen).toHaveTextContent('no check-in recorded')
    } else {
      const dt = time.getAttribute('dateTime') ?? ''
      expect(dt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
      expect(new Date(dt).toISOString()).toBe(dt)
      expect(seen.textContent).toMatch(/^last seen \d+[smhd] ago$/)
    }
  })

  it('an answered result that carries an error renders as an Error card with its error text', async () => {
    serve(() =>
      jsonResponse(
        200,
        envelope({
          summary: { matched: 2, answered: 1, not_connected: 0, failed: 1, queried_at: queriedAt },
          results: [
            { steward_id: 'steward-ok', rows: rowsFor(1), outcome: 'answered' },
            { steward_id: 'steward-bad', rows: rowsFor(1), error: 'osquery returned an error', outcome: 'answered' },
          ],
        }),
      ),
    )
    renderView()
    await run()
    const cards = await screen.findAllByTestId('osq-card')
    expect(cards.map((c) => c.getAttribute('data-kind'))).toEqual(['rows', 'err'])
    expect(within(cards[1]!).getByTestId('osq-steward-id')).toHaveTextContent('steward-bad')
    expect(within(cards[1]!).getByText('Error')).toBeInTheDocument()
    expect(within(cards[1]!).getByTestId('osq-error-text')).toHaveTextContent('osquery returned an error')
    expect(within(cards[1]!).queryByRole('table')).toBeNull()
  })

  it('a zero-match response shows the zero tally, the ran time and the No stewards matched notice', async () => {
    serve(() =>
      jsonResponse(
        200,
        envelope({
          summary: { matched: 0, answered: 0, not_connected: 0, failed: 0, queried_at: queriedAt },
          results: [],
        }),
      ),
    )
    renderView()
    await run('acme-corp/tag:edge')
    const empty = await screen.findByTestId('osq-state-empty')
    expect(empty).toHaveTextContent(/no stewards matched/i)
    expect(within(empty).getByTestId('osq-open-fleet')).toBeInTheDocument()
    expect(screen.getByTestId('osq-tally-matched')).toHaveTextContent('0 stewards matched ·')
    expect(screen.getByTestId('osq-tally-answered')).toHaveTextContent('0 answered')
    expect(screen.getByTestId('osq-tally-unreached')).toHaveTextContent('0 not reached')
    expect(screen.getByTestId('osq-tally-failed')).toHaveTextContent('0 failed')
    expect(screen.getByTestId('osq-tally-breakdown')).toHaveTextContent('0 with rows · 0 no rows')
    // The tally sits above the notice and there are no filter buttons.
    expect(
      (screen.getByTestId('osq-tally').compareDocumentPosition(empty) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0,
    ).toBe(true)
    expect(screen.queryByTestId('osq-filter-all')).toBeNull()
    const expected = new Date(queriedAtMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    expect(screen.getByTestId('osq-ran-time')).toHaveTextContent(`· ran ${expected}`)
  })
})

describe('OsqueryView request states', () => {
  it('shows the running state while the query is in flight', async () => {
    let release: (r: Response) => void = () => {}
    serve(() => new Promise<Response>((resolve) => (release = resolve)))
    renderView()
    await run()
    expect(await screen.findByTestId('osq-running')).toBeInTheDocument()
    expect(screen.getByTestId('osq-run-btn')).toBeDisabled()
    release(jsonResponse(200, envelope({ results: [{ steward_id: 's1' }] })))
    expect(await screen.findByTestId('osq-card')).toBeInTheDocument()
    expect(screen.queryByTestId('osq-running')).toBeNull()
  })

  it('400 shows the rejected selector message on the form', async () => {
    serve(() => jsonResponse(400, { error: { message: 'Invalid selector' } }))
    renderView()
    await run('acme-corp/tag:edge os:')
    expect(await screen.findByTestId('osq-state-rejected')).toHaveTextContent(/rejected/i)
    expect(screen.queryByTestId('osq-card')).toBeNull()
  })

  it('403 shows the tenant-outside-yours message', async () => {
    serve(() => jsonResponse(403, { error: { message: 'cross tenant' } }))
    renderView()
    await run('vendor-a/tag:edge')
    expect(await screen.findByTestId('osq-state-forbidden')).toHaveTextContent(/outside your authorized tenants/i)
    expect(screen.queryByTestId('osq-card')).toBeNull()
  })

  it('503 shows that fleet query is unavailable', async () => {
    serve(() => jsonResponse(503, { error: { message: 'Fleet query not available' } }))
    renderView()
    await run()
    expect(await screen.findByTestId('osq-state-unavailable')).toHaveTextContent(/not available/i)
  })

  it('500 shows the error card and Try again re-runs the query', async () => {
    let calls = 0
    serve(() => (++calls === 1 ? jsonResponse(500) : jsonResponse(200, envelope({ results: [{ steward_id: 's1' }] }))))
    renderView()
    await run()
    expect(await screen.findByTestId('osq-state-error')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('osq-retry'))
    expect(await screen.findByTestId('osq-card')).toBeInTheDocument()
    expect(queryCalls()).toHaveLength(2)
  })

  it('an empty results array is "No stewards matched" and not an error', async () => {
    serve(() => jsonResponse(200, envelope({ results: [] })))
    renderView()
    await run('acme-corp/tag:edge')
    const empty = await screen.findByTestId('osq-state-empty')
    expect(empty).toHaveTextContent(/no stewards matched/i)
    expect(empty).toHaveTextContent('acme-corp/tag:edge')
    expect(screen.queryByTestId('osq-card')).toBeNull()
    expect(screen.queryByTestId('osq-state-error')).toBeNull()
  })

  it('shows "No results yet" before the first run', async () => {
    serve(() => jsonResponse(200, envelope({ results: [] })))
    renderView()
    await ready()
    expect(screen.getByTestId('osq-results-idle')).toHaveTextContent(/no results yet/i)
  })
})
