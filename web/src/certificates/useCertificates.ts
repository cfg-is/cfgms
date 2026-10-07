// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Certificate fetch hooks and mutations (Issue #3135).
 *
 * Endpoints covered:
 *   GET  /api/v1/certificates                        → useCertificateList
 *   POST /api/v1/certificates/provision              → provisionCertificate
 *   POST /api/v1/certificates/{serial}/revoke        → revokeCertificate (#3129)
 *   POST /api/v1/certificates/signing/rotate         → rotateSigningCA
 *
 * Response shape: list endpoint returns { data: [...] } envelope.
 * Provision/revoke/rotate return { data: {...} } envelope.
 *
 * Distinguishing Expired from Revoked using the API shape:
 *   is_valid === false AND days_until_expiration < 0  → Expired
 *   is_valid === false AND days_until_expiration >= 0 → Revoked
 *   is_valid === true                                  → Valid (visual state from days)
 *
 * Security A9.1: serial_number, common_name, steward_id originate from
 * server-controlled data, not user input. All string fields are coerced via str().
 * Callers must render them as text nodes only, never via dangerouslySetInnerHTML.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'

// ── Primitive coercers ────────────────────────────────────────────────────────

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function num(value: unknown): number {
  return typeof value === 'number' ? value : 0
}

function bool(value: unknown): boolean {
  return value === true
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface CertificateInfo {
  serial_number: string
  common_name: string
  steward_id: string
  is_valid: boolean
  expires_at: string
  days_until_expiration: number
  needs_renewal: boolean
}

export interface CertificateProvisionResult {
  certificate_pem: string
  private_key_pem: string
  ca_certificate_pem: string
  serial_number: string
  expires_at: string
}

export interface RotateSigningCAResult {
  old_serial: string
  new_serial: string
  overlap_days: number
  stewards_notified: number
  overlap_expires_at: string
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

export function parseCertificateInfo(value: unknown): CertificateInfo | null {
  if (typeof value !== 'object' || value === null) return null
  const r = value as Record<string, unknown>
  const serial_number = str(r.serial_number)
  if (!serial_number) return null
  return {
    serial_number,
    common_name: str(r.common_name),
    steward_id: str(r.steward_id),
    is_valid: bool(r.is_valid),
    expires_at: str(r.expires_at),
    days_until_expiration: num(r.days_until_expiration),
    needs_renewal: bool(r.needs_renewal),
  }
}

export function parseCertificateList(data: unknown): CertificateInfo[] {
  if (!Array.isArray(data)) throw new Error('unexpected response shape')
  const list: CertificateInfo[] = []
  for (const item of data) {
    const c = parseCertificateInfo(item)
    if (c !== null) list.push(c)
  }
  return list
}

// ── Generic fetch outcome ─────────────────────────────────────────────────────

interface FetchOutcome<T> {
  key: string
  data?: T
  error?: string
  fetchedAtMs: number
}

// ── useCertificateList ────────────────────────────────────────────────────────

export interface UseCertificateListResult {
  certificates: CertificateInfo[]
  loading: boolean
  error: string | null
  retry: () => void
}

export function useCertificateList(): UseCertificateListResult {
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<FetchOutcome<CertificateInfo[]> | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `certificates:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/v1/certificates')
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`GET /api/v1/certificates — ${response.status}`)
        const body: unknown = await response.json()
        const parsed = parseCertificateList(
          (body as Record<string, unknown> | null)?.data,
        )
        if (cancelled) return
        setOutcome({ key, data: parsed, fetchedAtMs: Date.now() })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/certificates — request failed',
          fetchedAtMs: Date.now(),
        })
      })
    return () => {
      cancelled = true
    }
  }, [key, attempt])

  const current = outcome?.key === key ? outcome : null
  return {
    certificates: current?.data ?? [],
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}

// ── Mutations ─────────────────────────────────────────────────────────────────

export interface ProvisionCertificateOptions {
  stewardId: string
  commonName?: string
  organization?: string
  validityDays?: number
}

/**
 * Provision a new certificate via POST /api/v1/certificates/provision.
 * stewardId is required; commonName defaults server-side to stewardId if omitted.
 */
export async function provisionCertificate(
  options: ProvisionCertificateOptions,
): Promise<CertificateProvisionResult> {
  const body: Record<string, unknown> = { steward_id: options.stewardId }
  if (options.commonName && options.commonName.trim())
    body.common_name = options.commonName.trim()
  if (options.organization && options.organization.trim())
    body.organization = options.organization.trim()
  if (options.validityDays && options.validityDays > 0)
    body.validity_days = options.validityDays

  const response = await apiFetch('/api/v1/certificates/provision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const errMsg =
      (errBody?.error as Record<string, unknown>)?.message as string ||
      `Provision failed — ${response.status}`
    throw new Error(errMsg)
  }
  const respBody = (await response.json()) as Record<string, unknown>
  const data = (respBody.data ?? respBody) as Record<string, unknown>
  if (!data || typeof data !== 'object') throw new Error('Unexpected response shape from provision')
  return {
    certificate_pem: str(data.certificate_pem),
    private_key_pem: str(data.private_key_pem),
    ca_certificate_pem: str(data.ca_certificate_pem),
    serial_number: str(data.serial_number),
    expires_at: str(data.expires_at),
  }
}

/**
 * Revoke a certificate via POST /api/v1/certificates/{serial}/revoke.
 * Requires #3129 revoke endpoint.
 */
export async function revokeCertificate(serial: string): Promise<void> {
  const response = await apiFetch(
    `/api/v1/certificates/${encodeURIComponent(serial)}/revoke`,
    { method: 'POST' },
  )
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const errMsg =
      (errBody?.error as Record<string, unknown>)?.message as string ||
      `Revoke failed — ${response.status}`
    throw new Error(errMsg)
  }
}

/**
 * Thrown when the server rejects a rotation with 409 ROTATION_IN_PROGRESS: the
 * previous rotation's overlap window is still open. Callers must treat this as a
 * distinct, recoverable state (wait for the window, or take the explicit forced
 * override) rather than a generic failure.
 */
export class RotationInProgressError extends Error {
  readonly code = 'ROTATION_IN_PROGRESS'

  constructor(message: string) {
    super(message)
    this.name = 'RotationInProgressError'
  }
}

/**
 * Rotate the signing CA via POST /api/v1/certificates/signing/rotate.
 * This affects all stewards' trust chain — the UI requires explicit type-to-confirm.
 *
 * force defaults to false so the server's overlap-window guard stays in effect:
 * while a previous rotation's overlap window is open the accepted-signer set is
 * {current, rotating}, and forcing a second rotation evicts the earlier signer
 * immediately, breaking config-signature validation for every steward that has
 * not yet renewed. A non-forced call hits 409 ROTATION_IN_PROGRESS instead, which
 * surfaces as RotationInProgressError. Only pass force=true from a UI path that
 * states that consequence and collects separate consent for it.
 */
export async function rotateSigningCA(force = false): Promise<RotateSigningCAResult> {
  const response = await apiFetch('/api/v1/certificates/signing/rotate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ force }),
  })
  if (!response.ok) {
    const errBody = (await response.json().catch(() => ({}))) as Record<string, unknown>
    const err = errBody?.error as Record<string, unknown> | undefined
    const errMsg =
      (err?.message as string) || `Rotate failed — ${response.status}`
    if (response.status === 409 || err?.code === 'ROTATION_IN_PROGRESS') {
      throw new RotationInProgressError(errMsg)
    }
    throw new Error(errMsg)
  }
  const respBody = (await response.json()) as Record<string, unknown>
  const data = (respBody.data ?? respBody) as Record<string, unknown>
  return {
    old_serial: str(data.old_serial),
    new_serial: str(data.new_serial),
    overlap_days: num(data.overlap_days),
    stewards_notified: num(data.stewards_notified),
    overlap_expires_at: str(data.overlap_expires_at),
  }
}
