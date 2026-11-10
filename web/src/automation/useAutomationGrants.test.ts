// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createAutomationGrant,
  expiryFromDate,
  grantStatus,
  latestExpiryDate,
  parseAutomationGrant,
  parseAutomationGrantCreateResult,
  parseAutomationGrantList,
  revokeAutomationGrant,
  type AutomationGrant,
} from './useAutomationGrants.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function grant(over: Partial<AutomationGrant> = {}): AutomationGrant {
  return {
    id: 'g1',
    tenant_id: 't1',
    name: 'n',
    created_by: 'u',
    created_at: '2026-10-01T00:00:00Z',
    expires_at: '2026-12-01T00:00:00Z',
    revoked_at: null,
    revoked_by: '',
    ...over,
  }
}

describe('parsers', () => {
  it('rejects entries without an id and coerces bad fields', () => {
    expect(parseAutomationGrant(null)).toBeNull()
    expect(parseAutomationGrant({ name: 'x' })).toBeNull()
    expect(parseAutomationGrant({ id: 'g', name: 5, revoked_at: 7, expires_at: '2027-01-01T00:00:00Z' })).toEqual({
      id: 'g',
      tenant_id: '',
      name: '',
      created_by: '',
      created_at: '',
      expires_at: '2027-01-01T00:00:00Z',
      revoked_at: null,
      revoked_by: '',
    })
  })

  it('parseAutomationGrantList accepts null, skips bad items, throws on other shapes', () => {
    expect(parseAutomationGrantList(null)).toEqual([])
    expect(parseAutomationGrantList({ grants: null })).toEqual([])
    expect(parseAutomationGrantList({ grants: [{ id: 'a' }, 'junk'], count: 2 })).toHaveLength(1)
    expect(() => parseAutomationGrantList([])).toThrow()
    expect(() => parseAutomationGrantList({ grants: {} })).toThrow()
    expect(() => parseAutomationGrantList('x')).toThrow()
  })

  it('parseAutomationGrantCreateResult requires a grant and a credential', () => {
    expect(parseAutomationGrantCreateResult(null)).toBeNull()
    expect(parseAutomationGrantCreateResult({ grant: { id: 'a' } })).toBeNull()
    expect(parseAutomationGrantCreateResult({ credential: 's' })).toBeNull()
    expect(parseAutomationGrantCreateResult({ grant: { id: 'a' }, credential: 's' })?.credential).toBe('s')
  })
})

describe('grantStatus', () => {
  const now = Date.parse('2026-11-09T00:00:00Z')
  it('reports active, expired and revoked from the server fields', () => {
    expect(grantStatus(grant(), now)).toBe('active')
    expect(grantStatus(grant({ expires_at: '2026-11-01T00:00:00Z' }), now)).toBe('expired')
    expect(grantStatus(grant({ expires_at: '2026-11-09T00:00:00Z' }), now)).toBe('expired')
    expect(grantStatus(grant({ revoked_at: '2026-10-02T00:00:00Z' }), now)).toBe('revoked')
  })

  it('revocation wins over expiry and an unreadable expiry is not active', () => {
    expect(grantStatus(grant({ revoked_at: 'x', expires_at: '2026-01-01T00:00:00Z' }), now)).toBe('revoked')
    expect(grantStatus(grant({ expires_at: '' }), now)).toBe('expired')
  })
})

describe('expiry helpers', () => {
  it('expiryFromDate yields 00:00 UTC and rejects other input', () => {
    expect(expiryFromDate('2026-12-31')).toBe('2026-12-31T00:00:00.000Z')
    expect(expiryFromDate('')).toBe('')
    expect(expiryFromDate('12/31/2026')).toBe('')
    expect(expiryFromDate('2026-13-45')).toBe('')
  })

  it('latestExpiryDate is the controller cap (90 days) from now', () => {
    expect(latestExpiryDate(Date.parse('2026-01-01T12:00:00Z'))).toBe('2026-04-01')
  })
})

describe('createAutomationGrant / revokeAutomationGrant', () => {
  it('createAutomationGrant omits an empty tenant and returns the credential', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: { grant: { id: 'g' }, credential: 'CRED' } }))
    const result = await createAutomationGrant({ name: 'n', tenantId: '', expiresAt: '2026-12-01T00:00:00.000Z' })
    expect(result.credential).toBe('CRED')
    const init = fetchMock.mock.calls[0]?.[1]
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({ name: 'n', expires_at: '2026-12-01T00:00:00.000Z' })
  })

  it('createAutomationGrant sends a named tenant', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: { grant: { id: 'g' }, credential: 'CRED' } }))
    await createAutomationGrant({ name: 'n', tenantId: 'msp-a', expiresAt: '2026-12-01T00:00:00.000Z' })
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)).tenant_id).toBe('msp-a')
  })

  it('createAutomationGrant surfaces string and object server errors verbatim', async () => {
    const input = { name: 'n', tenantId: '', expiresAt: 'x' }
    fetchMock.mockResolvedValueOnce(json(400, { error: 'bad expiry' }))
    await expect(createAutomationGrant(input)).rejects.toThrow('bad expiry')
    fetchMock.mockResolvedValueOnce(json(400, { error: { message: 'expiry exceeds the maximum lifetime' } }))
    await expect(createAutomationGrant(input)).rejects.toThrow('expiry exceeds the maximum lifetime')
    fetchMock.mockResolvedValueOnce(new Response('', { status: 500 }))
    await expect(createAutomationGrant(input)).rejects.toThrow('Create failed — 500')
  })

  it('createAutomationGrant rejects a response without a credential', async () => {
    fetchMock.mockResolvedValueOnce(json(201, { data: { grant: { id: 'g' } } }))
    await expect(createAutomationGrant({ name: 'n', tenantId: '', expiresAt: 'x' })).rejects.toThrow(
      /unexpected response/i,
    )
  })

  it('revokeAutomationGrant encodes the id and reports failure', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { grant: { id: 'a/b' }, runs_ended: 0 } }))
    await revokeAutomationGrant('a/b')
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/automation/grants/a%2Fb')
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('DELETE')
    fetchMock.mockResolvedValueOnce(new Response('', { status: 404 }))
    await expect(revokeAutomationGrant('x')).rejects.toThrow('Revoke failed — 404')
  })
})
