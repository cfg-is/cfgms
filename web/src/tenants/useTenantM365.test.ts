// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  deleteM365Connection,
  getM365Connection,
  linkGdapCustomers,
  listGdapCustomers,
  parseGdapCustomers,
  parseGdapLinked,
  parseM365Connection,
  putM365Connection,
} from './useTenantM365.ts'
import { PolicyApiError, PolicyStepUpError } from './useTenantPolicies.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const conn = {
  tenant_id: 'root/msp-a/client-1',
  mode: 'direct',
  app_id: 'app-1',
  m365_tenant_id: 'dir-1',
  has_client_secret: true,
}
const customer = {
  customer_tenant_id: 'c-1',
  name: 'Acme',
  status: 'active',
  expires_at: '2027-01-01T00:00:00Z',
  roles: ['Helpdesk Administrator'],
  link_state: 'unlinked',
}

describe('useTenantM365', () => {
  it('parses connection and GDAP payloads', () => {
    expect(parseM365Connection(conn)).toEqual(conn)
    expect(parseM365Connection({ ...conn, mode: 'partner', partner_tenant_id: 'p', gdap_roles: ['r'] }))
      .toMatchObject({ partner_tenant_id: 'p', gdap_roles: ['r'] })
    expect(parseM365Connection({ ...conn, has_client_secret: 'yes' })).toBeNull()
    expect(parseM365Connection({ ...conn, gdap_roles: [1] })).toBeNull()
    expect(parseM365Connection(null)).toBeNull()

    expect(parseGdapCustomers({ customers: [customer, { ...customer, link_state: 'linked', linked_to: 'root/msp-a/client-1' }] }))
      .toHaveLength(2)
    expect(parseGdapCustomers({ customers: null })).toEqual([])
    expect(parseGdapCustomers({ customers: [{ ...customer, roles: null }] })).toEqual([{ ...customer, roles: [] }])
    expect(parseGdapCustomers({ customers: [{ ...customer, name: 3 }] })).toBeNull()
    expect(parseGdapCustomers({ customers: 'x' })).toBeNull()

    expect(parseGdapLinked({ linked: [{ customer_tenant_id: 'c-1', tenant_id: 't' }] })).toHaveLength(1)
    expect(parseGdapLinked({ linked: [{ customer_tenant_id: 'c-1' }] })).toBeNull()
  })

  it('returns null for a tenant with no connection and parses a present one', async () => {
    fetchMock.mockResolvedValueOnce(json(404, { error: { message: 'none' } }))
    await expect(getM365Connection('root/msp-a/client-1')).resolves.toBeNull()
    fetchMock.mockResolvedValueOnce(json(200, { data: conn }))
    await expect(getM365Connection('root/msp-a/client-1')).resolves.toEqual(conn)
    expect(String(fetchMock.mock.calls[0]![0])).toBe('/api/v1/tenants/root/msp-a/client-1/m365-connection')
    fetchMock.mockResolvedValueOnce(json(200, { data: { nope: 1 } }))
    await expect(getM365Connection('t')).rejects.toThrow(/malformed/)
  })

  it('PUTs the direct body and surfaces a 409 with its status', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: conn }))
    const input = { app_id: 'app-1', m365_tenant_id: 'dir-1', client_secret: 's', replace: false }
    await putM365Connection('root/msp-a/client-1', input)
    const [, init] = fetchMock.mock.calls[0]!
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual(input)

    fetchMock.mockResolvedValueOnce(json(409, { error: { message: 'tenant already has an M365 connection' } }))
    const err = await putM365Connection('t', input).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(PolicyApiError)
    expect((err as PolicyApiError).status).toBe(409)
  })

  it('DELETEs and requires the deleted acknowledgement', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { tenant_id: 't', deleted: true } }))
    await deleteM365Connection('root/msp-a/client-1')
    expect(fetchMock.mock.calls[0]![1]?.method).toBe('DELETE')
    fetchMock.mockResolvedValueOnce(json(200, { data: {} }))
    await expect(deleteM365Connection('t')).rejects.toThrow(/malformed/)
  })

  it('POSTs discovery and link bodies and reports an unresolved 401', async () => {
    const partner = { partner_tenant_id: 'p', app_id: 'a', client_secret: 's' }
    fetchMock.mockResolvedValueOnce(json(200, { data: { msp_tenant_id: 'root/msp-a', customers: [customer] } }))
    await expect(listGdapCustomers('root/msp-a', partner)).resolves.toEqual([customer])
    expect(String(fetchMock.mock.calls[0]![0])).toBe('/api/v1/tenants/root/msp-a/m365-gdap-customers')
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body))).toEqual(partner)

    const links = { ...partner, links: [{ customer_tenant_id: 'c-1', tenant_id: 'root/msp-a/client-1' }], gdap_roles: [], replace: true }
    fetchMock.mockResolvedValueOnce(json(200, { data: { msp_tenant_id: 'root/msp-a', linked: links.links } }))
    await expect(linkGdapCustomers('root/msp-a', links)).resolves.toEqual(links.links)
    expect(JSON.parse(String(fetchMock.mock.calls[1]![1]?.body))).toEqual(links)

    fetchMock.mockResolvedValue(json(401, { error: 'x' }))
    await expect(listGdapCustomers('t', partner)).rejects.toBeInstanceOf(PolicyStepUpError)
  })
})
