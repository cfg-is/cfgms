// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { bindCert, fetchCertBindings, parseCertBinding, revokeCert, rotateCert } from './useCertBindings.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

function ok(body: unknown = {}) {
  return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }))
}

describe('useCertBindings', () => {
  it('[REQUIRED TEST] useCertBindings builds the serial into the path with encodeURIComponent', async () => {
    fetchMock.mockImplementation(() => ok())
    await revokeCert('alice', '3a:2f/../x?y')
    await rotateCert('alice', '3a:2f/../x?y', { serial: 'new' })
    const urls = fetchMock.mock.calls.map(([u]) => String(u))
    expect(urls[0]).toBe('/api/v1/accounts/alice/certs/revoke/3a%3A2f%2F..%2Fx%3Fy')
    expect(urls[1]).toBe('/api/v1/accounts/alice/certs/rotate/3a%3A2f%2F..%2Fx%3Fy')
  })

  it('encodes the username in the path', async () => {
    fetchMock.mockImplementation(() => ok({ data: [] }))
    await fetchCertBindings('a/b')
    expect(String(fetchMock.mock.calls[0]![0])).toBe('/api/v1/accounts/a%2Fb/certs')
  })

  it('bind sends serial, fingerprint and label only when set', async () => {
    fetchMock.mockImplementation(() => ok())
    await bindCert('alice', { serial: 's1', fingerprint: 'f1', label: 'laptop' })
    await bindCert('alice', { serial: 's2', fingerprint: 'f2', label: '' })
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]!.body))).toEqual({ serial: 's1', fingerprint: 'f1', label: 'laptop' })
    expect(JSON.parse(String(fetchMock.mock.calls[1]![1]!.body))).toEqual({ serial: 's2', fingerprint: 'f2' })
  })

  it('rotate sends the new certificate in the body', async () => {
    fetchMock.mockImplementation(() => ok())
    await rotateCert('alice', 'old', { serial: 'new', fingerprint: 'nf' })
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]!.body))).toEqual({ serial: 'new', fingerprint: 'nf' })
  })

  it('surfaces the server error message on failure', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify({ error: { message: 'Certificate not found' } }), { status: 404 })),
    )
    await expect(revokeCert('alice', 's')).rejects.toThrow('Certificate not found')
  })

  it('parseCertBinding validates the wire shape', () => {
    expect(parseCertBinding(null)).toBeNull()
    expect(parseCertBinding({ serial: 's' })).toBeNull()
    expect(parseCertBinding({ serial: 's', fingerprint: 'f', bound_at: 't', label: 5 })?.label).toBe('')
    expect(
      parseCertBinding({ serial: 's', fingerprint: 'f', bound_at: 't', last_used_at: 'u', human_approved_at: 'h' }),
    ).toMatchObject({ lastUsedAt: 'u', humanApprovedAt: 'h' })
  })
})
