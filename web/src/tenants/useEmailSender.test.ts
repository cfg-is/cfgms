// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, renderHook, waitFor } from '@testing-library/react'
import {
  classifyFailure,
  defaultPortFor,
  fetchEmailSender,
  parseEmailSender,
  parseEmailTestResult,
  removeEmailSender,
  saveEmailSender,
  testEmailSender,
  useEmailSender,
  type EmailSenderInput,
} from './useEmailSender.ts'
import { TenantApiError } from './useTenants.ts'

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

const stored = {
  configured: true,
  password_present: true,
  host: 'smtp.vendor-a.example',
  port: 587,
  tls_mode: 'starttls',
  from: 'ops@acme-corp.example',
  username: 'mailer',
}

const input: EmailSenderInput = {
  host: 'smtp.vendor-a.example',
  port: 587,
  tlsMode: 'starttls',
  from: 'ops@acme-corp.example',
  username: 'mailer',
  password: '',
}

describe('parsers', () => {
  it('parses a sender and coerces wrong types away', () => {
    expect(parseEmailSender(stored)).toEqual({
      configured: true,
      passwordPresent: true,
      host: 'smtp.vendor-a.example',
      port: 587,
      tlsMode: 'starttls',
      from: 'ops@acme-corp.example',
      username: 'mailer',
    })
    expect(parseEmailSender({ configured: 'yes', port: '587', host: 7 })).toMatchObject({
      configured: false,
      port: 0,
      host: '',
    })
  })

  it('treats a malformed sender payload as no sender', () => {
    expect(parseEmailSender(null).configured).toBe(false)
    expect(parseEmailSender('x').configured).toBe(false)
  })

  it('parses recipients and drops malformed entries', () => {
    const r = parseEmailTestResult({
      delivered: false,
      recipients: [{ address: 'a@acme-corp.example', accepted: false, reason: '<script>x</script>' }, null, 4],
      failure_reason: 'recipient not accepted',
    })
    expect(r.delivered).toBe(false)
    expect(r.recipients).toEqual([{ address: 'a@acme-corp.example', accepted: false, reason: '<script>x</script>' }])
    expect(r.failureReason).toBe('recipient not accepted')
  })

  it('treats a malformed test payload as undelivered with no recipients', () => {
    expect(parseEmailTestResult(null)).toEqual({ delivered: false, recipients: [], failureReason: '' })
  })

  it('maps a TLS mode to its default port', () => {
    expect(defaultPortFor('starttls')).toBe(587)
    expect(defaultPortFor('implicit_tls')).toBe(465)
  })
})

describe('email sender requests', () => {
  it('fetch GETs the encoded tenant path and unwraps data', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: stored }))
    const sender = await fetchEmailSender('msp a')
    expect(sender.host).toBe('smtp.vendor-a.example')
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/v1/tenants/msp%20a/email-sender')
  })

  it('save PUTs every setting and omits the password when it is empty', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: stored }))
    await saveEmailSender('msp-a', input)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/email-sender')
    expect(init?.method).toBe('PUT')
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>
    expect(body).toEqual({
      host: 'smtp.vendor-a.example',
      port: 587,
      tls_mode: 'starttls',
      from: 'ops@acme-corp.example',
      username: 'mailer',
    })
    expect('password' in body).toBe(false)
  })

  it('save sends the password in the PUT body only', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: stored }))
    await saveEmailSender('msp-a', { ...input, password: 'hunter2-secret' })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).not.toContain('hunter2')
    expect(JSON.parse(String(init?.body)).password).toBe('hunter2-secret')
  })

  it('save keeps the server message and code on a validation rejection, without the password', async () => {
    fetchMock.mockResolvedValueOnce(
      json(400, { error: { code: 'INVALID_EMAIL_SENDER', message: 'a password is required for a first-time sender' } }),
    )
    const err = await saveEmailSender('msp-a', { ...input, password: 'hunter2-secret' }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(TenantApiError)
    expect(err).toMatchObject({ status: 400, code: 'INVALID_EMAIL_SENDER' })
    expect((err as Error).message).not.toContain('hunter2')
  })

  it('remove issues a DELETE and returns the unconfigured sender', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { configured: false, password_present: false } }))
    const sender = await removeEmailSender('msp-a')
    expect(sender.configured).toBe(false)
    expect(fetchMock.mock.calls[0]![1]?.method).toBe('DELETE')
  })

  it('test POSTs the test route with no body', async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, { data: { delivered: true, recipients: [{ address: 'ops@acme-corp.example', accepted: true }] } }),
    )
    const result = await testEmailSender('msp-a')
    expect(result.delivered).toBe(true)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/tenants/msp-a/email-sender/test')
    expect(init?.method).toBe('POST')
    expect(init?.body).toBeUndefined()
  })

  it('maps the crossing challenge, which carries a string error, to a coded 401', async () => {
    fetchMock.mockResolvedValueOnce(json(401, { error: 'tenant_crossing_required' }))
    await expect(fetchEmailSender('msp-a')).rejects.toMatchObject({ status: 401, code: 'tenant_crossing_required' })
  })

  it('falls back to a status message when the error body is empty', async () => {
    fetchMock.mockResolvedValueOnce(json(500, {}))
    await expect(fetchEmailSender('msp-a')).rejects.toMatchObject({ status: 500, message: 'Load email sender failed — 500' })
  })
})

describe('classifyFailure', () => {
  it('separates the crossing challenge, forbidden, a cancelled passkey and other errors', () => {
    expect(classifyFailure(new TenantApiError('x', 'tenant_crossing_required', 401)).failure).toBe('crossing')
    expect(classifyFailure(new TenantApiError('no', 'FORBIDDEN', 403)).failure).toBe('forbidden')
    expect(classifyFailure(new TenantApiError('x', '', 401))).toEqual({
      failure: 'error',
      error: 'The passkey check was cancelled. Try again.',
    })
    expect(classifyFailure(new TypeError('network down'))).toEqual({ failure: 'error', error: 'network down' })
    expect(classifyFailure('boom')).toEqual({ failure: 'error', error: 'Request failed' })
  })
})

describe('useEmailSender', () => {
  it('loads, reports an error, then retries', async () => {
    fetchMock.mockResolvedValueOnce(json(500, {}))
    const { result } = renderHook(() => useEmailSender('msp-a'))
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.failure).toBe('error'))
    fetchMock.mockResolvedValueOnce(json(200, { data: stored }))
    result.current.refetch()
    await waitFor(() => expect(result.current.sender?.host).toBe('smtp.vendor-a.example'))
    expect(result.current.failure).toBeNull()
  })

  it('reports the crossing challenge and a 403 as their own failures', async () => {
    fetchMock.mockResolvedValueOnce(json(401, { error: 'tenant_crossing_required' }))
    const crossing = renderHook(() => useEmailSender('msp-a'))
    await waitFor(() => expect(crossing.result.current.failure).toBe('crossing'))

    fetchMock.mockResolvedValueOnce(json(403, { error: { code: 'FORBIDDEN', message: 'permission denied' } }))
    const forbidden = renderHook(() => useEmailSender('msp-b'))
    await waitFor(() => expect(forbidden.result.current.failure).toBe('forbidden'))
  })

  it('setSender replaces the loaded sender', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { configured: false, password_present: false } }))
    const { result } = renderHook(() => useEmailSender('msp-a'))
    await waitFor(() => expect(result.current.sender).not.toBeNull())
    result.current.setSender(parseEmailSender(stored))
    await waitFor(() => expect(result.current.sender?.configured).toBe(true))
  })

  it('makes no request for a null tenant', () => {
    const { result } = renderHook(() => useEmailSender(null))
    expect(result.current).toMatchObject({ sender: null, loading: false, failure: null })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
