// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, renderHook, waitFor } from '@testing-library/react'
import { fetchAdminContacts, parseAdminContacts, saveAdminContacts, useAdminContacts } from './useSupportAccess.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('parseAdminContacts', () => {
  it('keeps strings and coerces everything else away', () => {
    expect(parseAdminContacts({ contacts: ['a@acme-corp.example', 7, null, '', { x: 1 }] })).toEqual(['a@acme-corp.example'])
  })

  it('returns an empty list for a malformed payload', () => {
    expect(parseAdminContacts(null)).toEqual([])
    expect(parseAdminContacts({ contacts: 'a@b.c' })).toEqual([])
    expect(parseAdminContacts('x')).toEqual([])
  })
})

describe('admin contacts requests', () => {
  it('fetch issues a GET on the encoded tenant path and unwraps data', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { contacts: ['a@acme-corp.example'] } }))
    await expect(fetchAdminContacts('msp a')).resolves.toEqual(['a@acme-corp.example'])
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/v1/tenants/msp%20a/admin-contacts')
  })

  it('save PUTs the full list and returns the stored list', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { contacts: ['a@acme-corp.example', 'b@acme-corp.example'] } }))
    const saved = await saveAdminContacts('msp-a', ['a@acme-corp.example', 'b@acme-corp.example'])
    expect(saved).toEqual(['a@acme-corp.example', 'b@acme-corp.example'])
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/admin-contacts')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual({ contacts: ['a@acme-corp.example', 'b@acme-corp.example'] })
  })

  it('maps a validation rejection to a coded error with the server message', async () => {
    fetchMock.mockResolvedValueOnce(json(400, { error: { code: 'INVALID_CONTACTS', message: 'ops@acme-corp is not a valid address' } }))
    await expect(saveAdminContacts('msp-a', ['ops@acme-corp'])).rejects.toMatchObject({
      status: 400,
      code: 'INVALID_CONTACTS',
      message: 'ops@acme-corp is not a valid address',
    })
  })

  it('falls back to a status message when the error body is empty', async () => {
    fetchMock.mockResolvedValueOnce(json(500, {}))
    await expect(fetchAdminContacts('msp-a')).rejects.toMatchObject({ status: 500, message: 'Load contacts failed — 500' })
  })
})

describe('useAdminContacts', () => {
  it('loads, and reports an error then retries', async () => {
    fetchMock.mockResolvedValueOnce(json(500, {}))
    const { result } = renderHook(() => useAdminContacts('msp-a'))
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.error).not.toBeNull())
    fetchMock.mockResolvedValueOnce(json(200, { data: { contacts: ['a@acme-corp.example'] } }))
    result.current.refetch()
    await waitFor(() => expect(result.current.contacts).toEqual(['a@acme-corp.example']))
    expect(result.current.error).toBeNull()
  })

  it('makes no request for a null tenant', () => {
    const { result } = renderHook(() => useAdminContacts(null))
    expect(result.current.loading).toBe(false)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
