// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  encodeTenantPath,
  getAssurancePolicy,
  getRefreshPolicy,
  parseAssurancePolicy,
  parseRefreshPolicy,
  putAssurancePolicy,
  putRefreshPolicy,
  PolicyApiError,
  PolicyStepUpError,
} from './useTenantPolicies.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('useTenantPolicies parses and rejects malformed policy payloads [REQUIRED]', () => {
  it('parses a valid refresh policy', () => {
    expect(parseRefreshPolicy({ mode: 'require_approval', max_dormancy_days: 30 })).toEqual({
      mode: 'require_approval',
      max_dormancy_days: 30,
    })
    expect(parseRefreshPolicy({ mode: 'reject' })).toEqual({ mode: 'reject' })
  })

  it.each([
    null,
    'x',
    {},
    { mode: 'allow_all' },
    { mode: 7 },
    { mode: 'reject', max_dormancy_days: -1 },
    { mode: 'reject', max_dormancy_days: 1.5 },
    { mode: 'reject', max_dormancy_days: '30' },
  ])('rejects malformed refresh policy %j', (raw) => {
    expect(parseRefreshPolicy(raw)).toBeNull()
  })

  it('parses a valid assurance policy, treating a null list as empty', () => {
    expect(
      parseAssurancePolicy({
        overrides: [{ permission_id: 'refresh:set-policy', min_override: 'strong', require_user_presence: true }],
      }),
    ).toEqual({
      overrides: [{ permission_id: 'refresh:set-policy', min_override: 'strong', require_user_presence: true }],
    })
    expect(parseAssurancePolicy({ overrides: null })).toEqual({ overrides: [] })
  })

  it.each([
    null,
    'x',
    { overrides: 'nope' },
    { overrides: [null] },
    { overrides: [{ permission_id: '', require_user_presence: false }] },
    { overrides: [{ permission_id: 'a', require_user_presence: 'yes' }] },
    { overrides: [{ permission_id: 'a', min_override: 'weak', require_user_presence: false }] },
    { overrides: [{ permission_id: 'a', require_user_presence: false }, { bad: true }] },
  ])('rejects malformed assurance policy %j', (raw) => {
    expect(parseAssurancePolicy(raw)).toBeNull()
  })

  it('getRefreshPolicy rejects a malformed server payload', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { mode: 'bogus' } }))
    await expect(getRefreshPolicy('msp-a')).rejects.toThrow(/malformed/)
  })

  it('getAssurancePolicy rejects a malformed server payload', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { overrides: [{ permission_id: 5 }] } }))
    await expect(getAssurancePolicy('msp-a')).rejects.toThrow(/malformed/)
  })
})

describe('transport', () => {
  it('encodes each path segment but keeps the separators', () => {
    expect(encodeTenantPath('root/msp a/client#1')).toBe('root/msp%20a/client%231')
  })

  it('GETs and PUTs the refresh policy at the encoded path', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { tenant_id: 'root/msp-a', mode: 'auto_accept' } }))
    expect(await getRefreshPolicy('root/msp-a')).toEqual({ mode: 'auto_accept' })
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/tenants/root/msp-a/refresh-policy')

    fetchMock.mockResolvedValueOnce(json(200, { data: { mode: 'reject', max_dormancy_days: 9 } }))
    await putRefreshPolicy('root/msp-a', { mode: 'reject', max_dormancy_days: 9 })
    const [url, init] = fetchMock.mock.calls[1] ?? []
    expect(String(url)).toBe('/api/v1/tenants/root/msp-a/refresh-policy')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual({ mode: 'reject', max_dormancy_days: 9 })
  })

  it('PUTs the assurance policy body', async () => {
    const policy = { overrides: [{ permission_id: 'x:y', require_user_presence: true }] }
    fetchMock.mockResolvedValueOnce(json(200, { data: policy }))
    await putAssurancePolicy('msp-a', policy)
    const [url, init] = fetchMock.mock.calls[0] ?? []
    expect(String(url)).toBe('/api/v1/tenants/msp-a/assurance-policy')
    expect(JSON.parse(String(init?.body))).toEqual(policy)
  })

  it('surfaces the server message verbatim on a rejected save', async () => {
    fetchMock.mockResolvedValue(json(400, { error: { code: 'bad', message: 'unknown permission "zz"' } }))
    const err = await putAssurancePolicy('msp-a', { overrides: [] }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(PolicyApiError)
    expect((err as PolicyApiError).message).toBe('unknown permission "zz"')
  })

  it('reports an unresolved step-up 401 as PolicyStepUpError', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 401, headers: { 'WWW-Authenticate': 'CFGMS-StepUp realm="cfgms"' } }),
    )
    await expect(putRefreshPolicy('msp-a', { mode: 'reject' })).rejects.toBeInstanceOf(PolicyStepUpError)
  })
})
