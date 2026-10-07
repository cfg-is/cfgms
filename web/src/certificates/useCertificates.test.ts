// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useCertificates test suite (Issue #3135):
 * parseCertificateInfo parse helpers, useCertificateList hook,
 * and mutation functions (provision, revoke, rotate).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import {
  parseCertificateInfo,
  parseCertificateList,
  useCertificateList,
  provisionCertificate,
  revokeCertificate,
  rotateSigningCA,
  RotationInProgressError,
} from './useCertificates.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// ── parseCertificateInfo ──────────────────────────────────────────────────────

describe('parseCertificateInfo', () => {
  it('parses a valid certificate object', () => {
    const result = parseCertificateInfo({
      serial_number: '7f:3a:9c:01',
      common_name: 'dc-01.acme-corp',
      steward_id: 'steward-abc',
      is_valid: true,
      expires_at: '2027-01-14T00:00:00Z',
      days_until_expiration: 168,
      needs_renewal: false,
    })
    expect(result).toEqual({
      serial_number: '7f:3a:9c:01',
      common_name: 'dc-01.acme-corp',
      steward_id: 'steward-abc',
      is_valid: true,
      expires_at: '2027-01-14T00:00:00Z',
      days_until_expiration: 168,
      needs_renewal: false,
    })
  })

  it('returns null for null input', () => {
    expect(parseCertificateInfo(null)).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parseCertificateInfo('string')).toBeNull()
    expect(parseCertificateInfo(42)).toBeNull()
  })

  it('returns null when serial_number is missing', () => {
    expect(parseCertificateInfo({ common_name: 'host', is_valid: true })).toBeNull()
  })

  it('defaults missing optional fields to safe values', () => {
    const result = parseCertificateInfo({ serial_number: 'aa:bb' })
    expect(result).not.toBeNull()
    expect(result!.common_name).toBe('')
    expect(result!.steward_id).toBe('')
    expect(result!.is_valid).toBe(false)
    expect(result!.days_until_expiration).toBe(0)
    expect(result!.needs_renewal).toBe(false)
  })

  it('parses a revoked certificate (is_valid=false, days>=0)', () => {
    const result = parseCertificateInfo({
      serial_number: 'b2:60:44:19',
      common_name: 'edge-fw-02',
      is_valid: false,
      expires_at: '2026-05-20T00:00:00Z',
      days_until_expiration: 10,
      needs_renewal: false,
    })
    expect(result!.is_valid).toBe(false)
    expect(result!.days_until_expiration).toBe(10)
  })

  it('parses an expired certificate (is_valid=false, days<0)', () => {
    const result = parseCertificateInfo({
      serial_number: '44:2d:88:aa',
      common_name: 'client-vpn',
      is_valid: false,
      expires_at: '2026-06-01T00:00:00Z',
      days_until_expiration: -1,
      needs_renewal: false,
    })
    expect(result!.is_valid).toBe(false)
    expect(result!.days_until_expiration).toBe(-1)
  })
})

// ── parseCertificateList ──────────────────────────────────────────────────────

describe('parseCertificateList', () => {
  it('parses an array of certificate objects', () => {
    const result = parseCertificateList([
      { serial_number: 'aa:01', common_name: 'host-a', is_valid: true, expires_at: '2027-01-01T00:00:00Z', days_until_expiration: 150, needs_renewal: false },
      { serial_number: 'bb:02', common_name: 'host-b', is_valid: false, expires_at: '2026-01-01T00:00:00Z', days_until_expiration: -5, needs_renewal: false },
    ])
    expect(result).toHaveLength(2)
    expect(result[0]?.serial_number).toBe('aa:01')
    expect(result[1]?.serial_number).toBe('bb:02')
  })

  it('throws when data is not an array', () => {
    expect(() => parseCertificateList(null)).toThrow('unexpected response shape')
    expect(() => parseCertificateList({ data: [] })).toThrow('unexpected response shape')
  })

  it('skips invalid items', () => {
    const result = parseCertificateList([
      { serial_number: 'aa:01', is_valid: true },
      null,
      'string',
      { common_name: 'no-serial' },
    ])
    expect(result).toHaveLength(1)
  })

  it('returns empty array for empty array input', () => {
    expect(parseCertificateList([])).toEqual([])
  })
})

// ── useCertificateList ────────────────────────────────────────────────────────

function makeCertResponse(certs: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: certs }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeCert(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    serial_number: '7f:3a:9c:01',
    common_name: 'dc-01.acme-corp',
    steward_id: 'steward-abc',
    is_valid: true,
    expires_at: '2027-01-14T00:00:00Z',
    days_until_expiration: 168,
    needs_renewal: false,
    ...overrides,
  }
}

describe('useCertificateList', () => {
  it('starts in loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useCertificateList())
    expect(result.current.loading).toBe(true)
    expect(result.current.certificates).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('returns certificates on success', async () => {
    fetchMock.mockResolvedValue(
      makeCertResponse([makeCert(), makeCert({ serial_number: 'a1:c4', common_name: 'host-b' })]),
    )
    const { result } = renderHook(() => useCertificateList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.certificates).toHaveLength(2)
    expect(result.current.error).toBeNull()
  })

  it('returns empty array when no certificates', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([]))
    const { result } = renderHook(() => useCertificateList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.certificates).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('sets error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeCertResponse([], 500))
    const { result } = renderHook(() => useCertificateList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toMatch(/500/)
    expect(result.current.certificates).toEqual([])
  })

  it('sets error on network failure', async () => {
    fetchMock.mockRejectedValue(new Error('network error'))
    const { result } = renderHook(() => useCertificateList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBe('network error')
  })

  it('retries on retry() call and succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(makeCertResponse([], 500))
      .mockResolvedValueOnce(makeCertResponse([makeCert()]))
    const { result } = renderHook(() => useCertificateList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toBeTruthy()

    result.current.retry()
    // Wait until the second fetch resolves and data is populated.
    await waitFor(() => expect(result.current.certificates).toHaveLength(1))
    expect(result.current.error).toBeNull()
  })
})

// ── provisionCertificate ──────────────────────────────────────────────────────

function makeProvisionResponse(status = 201) {
  return new Response(
    JSON.stringify({
      data: {
        certificate_pem: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n',
        private_key_pem: '-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----\n',
        ca_certificate_pem: '-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----\n',
        serial_number: 'aa:bb:cc:dd',
        expires_at: '2027-07-30T00:00:00Z',
      },
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('provisionCertificate', () => {
  it('calls POST /api/v1/certificates/provision with stewardId', async () => {
    fetchMock.mockResolvedValue(makeProvisionResponse())
    await provisionCertificate({ stewardId: 'new-host.acme-corp' })
    expect(fetchMock).toHaveBeenCalledOnce()
    const call = fetchMock.mock.calls[0]
    expect(call).toBeDefined()
    const opts = call?.[1]
    expect(opts?.method).toBe('POST')
    expect(JSON.parse(opts?.body as string)).toMatchObject({ steward_id: 'new-host.acme-corp' })
  })

  it('includes optional fields when provided', async () => {
    fetchMock.mockResolvedValue(makeProvisionResponse())
    await provisionCertificate({
      stewardId: 'host',
      commonName: 'host.example.com',
      organization: 'Acme Corp',
      validityDays: 365,
    })
    const call = fetchMock.mock.calls[0]
    expect(call).toBeDefined()
    const opts = call?.[1]
    expect(JSON.parse(opts?.body as string)).toMatchObject({
      steward_id: 'host',
      common_name: 'host.example.com',
      organization: 'Acme Corp',
      validity_days: 365,
    })
  })

  it('returns parsed provision result', async () => {
    fetchMock.mockResolvedValue(makeProvisionResponse())
    const result = await provisionCertificate({ stewardId: 'host' })
    expect(result.serial_number).toBe('aa:bb:cc:dd')
    expect(result.certificate_pem).toContain('BEGIN CERTIFICATE')
  })

  it('throws on non-ok response', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Steward ID is required', code: 'MISSING_STEWARD_ID' } }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    await expect(provisionCertificate({ stewardId: 'host' })).rejects.toThrow('Steward ID is required')
  })

  it('throws generic error when no message in response', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 500, headers: { 'Content-Type': 'application/json' } }),
    )
    await expect(provisionCertificate({ stewardId: 'host' })).rejects.toThrow('Provision failed — 500')
  })
})

// ── revokeCertificate ─────────────────────────────────────────────────────────

describe('revokeCertificate', () => {
  it('calls POST /api/v1/certificates/{serial}/revoke', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { serial_number: '7f:3a:9c:01', is_valid: false, is_revoked: true } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    await revokeCertificate('7f:3a:9c:01')
    expect(fetchMock).toHaveBeenCalledOnce()
    const call = fetchMock.mock.calls[0]
    expect(call).toBeDefined()
    expect(String(call?.[0])).toContain('/api/v1/certificates/7f%3A3a%3A9c%3A01/revoke')
    expect(call?.[1]?.method).toBe('POST')
  })

  it('throws on revoke failure', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Certificate not found', code: 'CERTIFICATE_NOT_FOUND' } }),
        { status: 404, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    await expect(revokeCertificate('bad:serial')).rejects.toThrow('Certificate not found')
  })
})

// ── rotateSigningCA ───────────────────────────────────────────────────────────

function makeRotateResponse(status = 200) {
  return new Response(
    JSON.stringify({
      data: {
        old_serial: 'aa:bb:01',
        new_serial: 'cc:dd:02',
        overlap_days: 7,
        stewards_notified: 42,
        overlap_expires_at: '2026-08-20T00:00:00Z',
      },
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

describe('rotateSigningCA', () => {
  it('calls POST /api/v1/certificates/signing/rotate without forcing by default', async () => {
    fetchMock.mockResolvedValue(makeRotateResponse())
    await rotateSigningCA()
    expect(fetchMock).toHaveBeenCalledOnce()
    const call = fetchMock.mock.calls[0]
    expect(call).toBeDefined()
    expect(String(call?.[0])).toContain('/api/v1/certificates/signing/rotate')
    expect(call?.[1]?.method).toBe('POST')
    expect(JSON.parse(call?.[1]?.body as string)).toMatchObject({ force: false })
  })

  it('sends force=true only when explicitly requested', async () => {
    fetchMock.mockResolvedValue(makeRotateResponse())
    await rotateSigningCA(true)
    const call = fetchMock.mock.calls[0]
    expect(JSON.parse(call?.[1]?.body as string)).toMatchObject({ force: true })
  })

  it('returns parsed rotation result', async () => {
    fetchMock.mockResolvedValue(makeRotateResponse())
    const result = await rotateSigningCA()
    expect(result.old_serial).toBe('aa:bb:01')
    expect(result.new_serial).toBe('cc:dd:02')
    expect(result.overlap_days).toBe(7)
    expect(result.stewards_notified).toBe(42)
  })

  it('throws RotationInProgressError on 409 so callers can offer wait-or-override', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Rotation already in progress', code: 'ROTATION_IN_PROGRESS' } }),
        { status: 409, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    const error = await rotateSigningCA().catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(RotationInProgressError)
    expect((error as Error).message).toBe('Rotation already in progress')
    expect((error as RotationInProgressError).code).toBe('ROTATION_IN_PROGRESS')
  })

  it('throws on rotation failure', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Rotation failed', code: 'ROTATION_ERROR' } }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    const error = await rotateSigningCA().catch((cause: unknown) => cause)
    expect(error).toBeInstanceOf(Error)
    expect(error).not.toBeInstanceOf(RotationInProgressError)
    expect((error as Error).message).toBe('Rotation failed')
  })

  it('throws generic error when no error message', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } }),
    )
    await expect(rotateSigningCA()).rejects.toThrow('Rotate failed — 503')
  })
})
