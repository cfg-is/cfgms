// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * DnaDrawer suite (Story #2498): fetch/render/error, redacted-attribute
 * tolerance, hostile attribute KEY and VALUE text-node guarantee (A10.1,
 * A9.1), and Escape/scrim close.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import DnaDrawer from './DnaDrawer.tsx'
import type { Steward } from './columns.ts'

const fetchMock = vi.fn<typeof fetch>()

const NOW_MS = 1_700_000_000_000

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeSteward(overrides: Partial<Steward> = {}): Steward {
  return {
    id: 'steward-01',
    status: 'active',
    last_seen: new Date(NOW_MS - 30_000).toISOString(),
    version: 'v0.42',
    dna: { hostname: 'web-ingest-04', os: 'linux', architecture: 'amd64', attributes: {} },
    ...overrides,
  }
}

function makeDNAResponse(attrs: Record<string, string> = {}, topLevel: Record<string, string> = {}) {
  return {
    data: {
      hostname: topLevel.hostname ?? 'web-ingest-04',
      os: topLevel.os ?? 'linux',
      architecture: topLevel.architecture ?? 'amd64',
      attributes: attrs,
      collected_at: new Date(NOW_MS).toISOString(),
    },
    timestamp: new Date(NOW_MS).toISOString(),
  }
}

function mockDNAFetch(attrs: Record<string, string> = {}, topLevel: Record<string, string> = {}) {
  fetchMock.mockResolvedValueOnce(
    new Response(JSON.stringify(makeDNAResponse(attrs, topLevel)), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
}

function renderDrawer(steward: Steward | null, onClose = vi.fn()) {
  return render(<DnaDrawer steward={steward} onClose={onClose} nowMs={NOW_MS} />)
}

describe('drawer closed', () => {
  it('renders nothing when steward is null', () => {
    renderDrawer(null)
    expect(screen.queryByTestId('dna-drawer')).not.toBeInTheDocument()
    expect(screen.queryByTestId('dna-scrim')).not.toBeInTheDocument()
  })
})

describe('drawer open / loading', () => {
  it('shows loading state immediately after a steward is set', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderDrawer(makeSteward())
    expect(screen.getByTestId('dna-drawer')).toBeInTheDocument()
    expect(screen.getByTestId('dna-loading')).toBeInTheDocument()
    expect(screen.queryByTestId('dna-error')).not.toBeInTheDocument()
  })

  it('displays the steward name and health pill in the header immediately', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderDrawer(makeSteward({ dna: { hostname: 'my-host' } }))
    expect(screen.getByText('my-host')).toBeInTheDocument()
    expect(screen.getByText('Healthy')).toBeInTheDocument()
  })

  it('shows the scrim while the drawer is open', () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    renderDrawer(makeSteward())
    expect(screen.getByTestId('dna-scrim')).toBeInTheDocument()
  })
})

describe('DNA fetch success', () => {
  it('renders all group headings from fixed constants — not from data', async () => {
    mockDNAFetch({
      tenant: 'root/msp-a',
      deployment_ring: 'broad',
      fqdn: 'web-ingest-04.acme.internal',
      primary_ip: '10.20.4.14',
      primary_mac: 'a4:bb:6d:2f:19:07',
      os_pretty_name: 'Ubuntu 24.04',
      current_user: 'svc_deploy',
    })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    // These headings are defined as client-side constants — they must be in the DOM.
    expect(screen.getByText('Identity')).toBeInTheDocument()
    expect(screen.getByText('Network')).toBeInTheDocument()
    expect(screen.getByText('System')).toBeInTheDocument()
    expect(screen.getByText('Session & agent')).toBeInTheDocument()
  })

  it('renders Identity group attributes in the correct group', async () => {
    mockDNAFetch({
      tenant: 'root/msp-a',
      deployment_ring: 'broad',
      fqdn: 'web-ingest-04.acme.internal',
    })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    expect(screen.getByText('root/msp-a')).toBeInTheDocument()
    expect(screen.getByText('broad')).toBeInTheDocument()
    expect(screen.getByText('web-ingest-04.acme.internal')).toBeInTheDocument()
  })

  it('renders Network group attributes', async () => {
    mockDNAFetch({ primary_ip: '10.20.4.14', primary_mac: 'a4:bb:6d:2f:19:07' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    expect(screen.getByText('10.20.4.14')).toBeInTheDocument()
    expect(screen.getByText('a4:bb:6d:2f:19:07')).toBeInTheDocument()
  })

  it('renders System group attributes', async () => {
    mockDNAFetch({
      os_pretty_name: 'Ubuntu 24.04',
      system_model: 'PowerEdge R650',
      system_serial_number: '5CD82',
      cpu_count: '16',
      total_memory: '64 GB',
    })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    expect(screen.getByText('Ubuntu 24.04')).toBeInTheDocument()
    expect(screen.getByText('PowerEdge R650')).toBeInTheDocument()
    expect(screen.getByText('5CD82')).toBeInTheDocument()
  })

  it('renders Session & agent group including last_seen from steward and version', async () => {
    mockDNAFetch({ current_user: 'svc_deploy', module_trust_mode: 'controller' })
    const steward = makeSteward({
      last_seen: new Date(NOW_MS - 12_000).toISOString(),
      version: 'v0.42',
    })
    renderDrawer(steward)
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    expect(screen.getByText('svc_deploy')).toBeInTheDocument()
    expect(screen.getByText('controller')).toBeInTheDocument()
    // Agent version comes from steward object, not DNA endpoint
    expect(screen.getByText('v0.42')).toBeInTheDocument()
    // Last check-in is formatted from steward.last_seen
    expect(screen.getByText('12s ago')).toBeInTheDocument()
  })

  it('uses model fallback (hardware_model) when system_model absent', async () => {
    mockDNAFetch({ hardware_model: 'Mac mini M2' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    expect(screen.getByText('Mac mini M2')).toBeInTheDocument()
  })

  it('uses serial fallback (motherboard_serial) when system_serial_number absent', async () => {
    mockDNAFetch({ motherboard_serial: 'MB-X01' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    expect(screen.getByText('MB-X01')).toBeInTheDocument()
  })

  it('renders em-dash for missing values in named groups', async () => {
    mockDNAFetch({}) // empty attributes
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    // Many values will be "—" for empty attributes
    const body = screen.getByTestId('dna-body')
    expect(within(body).getAllByText('—').length).toBeGreaterThanOrEqual(4)
  })
})

describe('Other attributes group', () => {
  it('puts unknown keys in Other attributes, not in the named groups', async () => {
    mockDNAFetch({ custom_sensor: 'temp-42c', unknown_field: 'value-xyz' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    expect(screen.getByText('Other attributes')).toBeInTheDocument()
    expect(screen.getByText('custom_sensor')).toBeInTheDocument()
    expect(screen.getByText('temp-42c')).toBeInTheDocument()
    expect(screen.getByText('unknown_field')).toBeInTheDocument()
    expect(screen.getByText('value-xyz')).toBeInTheDocument()
  })

  it('hostile attribute KEY renders as inert text, never as markup (security A10.1)', async () => {
    const hostileKey = '<img src=x onerror="document.title=\'pwned\'">'
    const attrs: Record<string, string> = { [hostileKey]: 'some-value' }
    mockDNAFetch(attrs)
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    // The raw string must be visible as text
    expect(screen.getByText(hostileKey)).toBeInTheDocument()
    // No real <img> or <script> must have been created
    expect(document.querySelector('img')).toBeNull()
    expect(document.title).not.toBe('pwned')
  })

  it('hostile attribute VALUE renders as inert text, never as markup (security A9.1)', async () => {
    const hostileValue = '<script>document.title="pwned"</script>'
    mockDNAFetch({ hostile_val: hostileValue })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    expect(screen.getByText(hostileValue)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(document.title).not.toBe('pwned')
  })

  it('group headings are client-side constants, not derived from data', async () => {
    // Even if the server returns a key that looks like a group heading, it does not
    // create a new heading — it appears only as a value in Other attributes.
    mockDNAFetch({ Identity: 'injected', Network: 'injected' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())

    // The fixed group headings are in .grp .lbl elements — query only those.
    const body = screen.getByTestId('dna-body')
    const groupHeadings = within(body).getAllByText('Identity')
    // Exactly one should be a group heading (.lbl inside .grp); the other is
    // a data key in the "Other attributes" overflow (.kv .k).
    const headingNodes = groupHeadings.filter((el) =>
      el.classList.contains('lbl') && el.closest('.grp') !== null,
    )
    expect(headingNodes).toHaveLength(1)

    // The injected keys appear in Other attributes, not as group headings.
    expect(screen.getByText('Other attributes')).toBeInTheDocument()
    const overflowKeys = within(body).getAllByText('injected')
    expect(overflowKeys.length).toBeGreaterThanOrEqual(2)
  })

  it('shows no Other attributes section when all keys are consumed by named groups', async () => {
    mockDNAFetch({ tenant: 'root/msp-a', primary_ip: '10.0.0.1' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    expect(screen.queryByText('Other attributes')).not.toBeInTheDocument()
  })
})

describe('redacted attribute tolerance', () => {
  it('a response with no attributes renders known groups with em-dash placeholders', async () => {
    mockDNAFetch({}) // fully redacted / empty
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    expect(screen.queryByTestId('dna-error')).not.toBeInTheDocument()
    // Named groups still show
    expect(screen.getByText('Identity')).toBeInTheDocument()
  })

  it('attributes missing from a partial response render as em-dash without crashing', async () => {
    // Partial: some known keys present, some absent
    mockDNAFetch({ tenant: 'root/msp-a' })
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    expect(screen.getByText('root/msp-a')).toBeInTheDocument()
    // ip address absent → em-dash
    const ipRow = screen.getByText('IP address').closest('.kv')
    expect(within(ipRow as HTMLElement).getByText('—')).toBeInTheDocument()
  })
})

describe('fetch errors', () => {
  it('shows error state on 404 (steward not found or cross-tenant)', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response('{"error":"not found"}', { status: 404, headers: { 'Content-Type': 'application/json' } }),
    )
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.getByTestId('dna-error')).toBeInTheDocument())
    expect(screen.getByText(/404/)).toBeInTheDocument()
    expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument()
  })

  it('shows error state on 403 permission denied', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response('{}', { status: 403, headers: { 'Content-Type': 'application/json' } }),
    )
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.getByTestId('dna-error')).toBeInTheDocument())
    expect(screen.getByText(/403/)).toBeInTheDocument()
  })

  it('shows error state on network failure', async () => {
    fetchMock.mockRejectedValueOnce(new Error('network failure'))
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.getByTestId('dna-error')).toBeInTheDocument())
    expect(screen.getByText(/network failure/)).toBeInTheDocument()
  })

  it('shows error state when response shape is not a DNA object', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ data: { wrong: true } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderDrawer(makeSteward())
    await waitFor(() => expect(screen.getByTestId('dna-error')).toBeInTheDocument())
    expect(screen.getByText(/unexpected/)).toBeInTheDocument()
  })
})

describe('close behavior', () => {
  it('Escape key calls onClose', async () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    const onClose = vi.fn()
    renderDrawer(makeSteward(), onClose)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('scrim click calls onClose', async () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    const onClose = vi.fn()
    renderDrawer(makeSteward(), onClose)
    fireEvent.click(screen.getByTestId('dna-scrim'))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('X button calls onClose', async () => {
    fetchMock.mockImplementation(() => new Promise<Response>(() => {}))
    const onClose = vi.fn()
    renderDrawer(makeSteward(), onClose)
    fireEvent.click(screen.getByRole('button', { name: /close dna detail/i }))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('re-fetches when steward ID changes', async () => {
    const s1 = makeSteward({ id: 'steward-01' })
    const s2 = makeSteward({ id: 'steward-02', dna: { hostname: 'other-host' } })

    mockDNAFetch({ tenant: 'root/msp-a' })
    const { rerender } = renderDrawer(s1)
    await waitFor(() => expect(screen.queryByTestId('dna-loading')).not.toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(1)

    mockDNAFetch({ tenant: 'root/msp-b' })
    rerender(<DnaDrawer steward={s2} onClose={vi.fn()} nowMs={NOW_MS} />)
    await waitFor(() => expect(screen.getByText('root/msp-b')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
