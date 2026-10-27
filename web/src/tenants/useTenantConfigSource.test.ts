// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  parseCredentialResult,
  parseTestResult,
  putConfigSourceCredential,
  testConfigSource,
} from './useTenantConfigSource.ts'
import { PolicyApiError, PolicyStepUpError } from './useTenantPolicies.ts'

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

describe('useTenantConfigSource', () => {
  it('surfaces the server error text', async () => {
    fetchMock.mockResolvedValue(json(400, { error: { code: 'INVALID', message: 'url host is not allowed' } }))
    await expect(putConfigSourceCredential('root/msp-a', 'http://x', 't')).rejects.toThrow('url host is not allowed')
    fetchMock.mockResolvedValue(json(429, { error: 'rate limit exceeded' }))
    const err = await testConfigSource('root/msp-a').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(PolicyApiError)
    expect((err as Error).message).toBe('rate limit exceeded')
  })

  it('reports an unresolved 401 as a step-up failure', async () => {
    fetchMock.mockResolvedValue(json(401, { error: 'x' }))
    await expect(testConfigSource('root/msp-a')).rejects.toBeInstanceOf(PolicyStepUpError)
  })

  it('PUTs {url, token} to the encoded tenant path and parses the result', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { credential_ref: 'root/msp-a/config-source-git', bound_repository_url: 'https://g/r.git' } }))
    const res = await putConfigSourceCredential('root/msp-a', 'https://g/r.git', 'tok')
    expect(res.credential_ref).toBe('root/msp-a/config-source-git')
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/tenants/root/msp-a/config-source/credential')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual({ url: 'https://g/r.git', token: 'tok' })
  })

  it('POSTs the test with no body and rejects a malformed result', async () => {
    fetchMock.mockResolvedValue(json(200, { reachable: 'yes' }))
    await expect(testConfigSource('root/msp-a')).rejects.toThrow(/malformed/)
    expect(fetchMock.mock.calls[0]![1]?.body).toBeUndefined()
  })

  it('validates payload shapes', () => {
    expect(parseTestResult({ reachable: false, error: 'dns' })).toEqual({ reachable: false, error: 'dns' })
    expect(parseTestResult({ reachable: true, error: 3 })).toBeNull()
    expect(parseCredentialResult({ credential_ref: 'a' })).toBeNull()
  })
})
