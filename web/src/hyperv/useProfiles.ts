// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Hyper-V provisioning profile hooks (Issue #5461, Epic #5300).
 *
 * Endpoints covered (features/controller/api/routes_hyperv_profiles.go):
 *   GET    /api/v1/hyperv/profiles          → useProfiles    (names only: {profiles: [string]})
 *   GET    /api/v1/hyperv/profiles/{name}   → useProfile     (the full profile)
 *   POST   /api/v1/hyperv/profiles          → create         (Strong step-up + presence tap)
 *   DELETE /api/v1/hyperv/profiles/{name}   → remove         (Strong step-up + presence tap)
 *
 * Tenant: a tenant-scoped caller is pinned to its own tenant by the server; a
 * root-scoped admin must send ?tenant=<id> on every call or receives 400
 * TENANT_REQUIRED. Every call here sends the tenant from useTenantScope() when one
 * is in scope, and a TENANT_REQUIRED reply surfaces as an error state.
 *
 * The passkey tap is done by the apiFetch interceptor and StepUpModal, which retry
 * the request with X-Presence-Token; this module never builds that header. A
 * cancelled tap hands back the original 401, which maps to the 'CANCELLED' code.
 *
 * Security A9.1: every wire value, the template included, is coerced through a
 * parse* validator and must be rendered as JSX text only, never as HTML.
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch, unwrapEnvelope } from '../api/client.ts'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'

const profilesPath = '/api/v1/hyperv/profiles'

/** Largest stored profile the controller accepts (profileMaxSizeBytes). Shown only. */
export const maxTemplateBytes = 256 * 1024

export type OsFamily = 'linux' | 'windows'

type FormatList = ReadonlyArray<readonly [string, string]>

const linuxFormats: FormatList = [
  ['cloud-init', 'Linux cloud image (NoCloud seed).'],
  ['preseed', 'Debian-family netinst ISO.'],
]

const windowsFormats: FormatList = [['autounattend', 'Windows Setup answer file.']]

/** Answer formats the controller accepts for an OS family, with a one-line description. */
export function answerFormatsFor(os: OsFamily): FormatList {
  return os === 'windows' ? windowsFormats : linuxFormats
}

export interface ProfileEnroll {
  registration_token_secret_key: string
  bundle_url: string
  correlation_label: string
}

export interface Profile {
  name: string
  os_family: string
  answer_format: string
  template: string
  enroll: ProfileEnroll
}

export type ProfileCreateInput = Profile

export interface TemplatePlaceholder {
  /** The expression between the braces, trimmed. */
  expr: string
  /** True for `secret "key"` references, which are read from the secret store. */
  secret: boolean
}

/** A failed profile API call: the HTTP status and the server's error code and message. */
export class ProfileApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(message: string, status: number, code: string) {
    super(message)
    this.name = 'ProfileApiError'
    this.status = status
    this.code = code
  }
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/** Accepts `{ profiles: [string] }`; null/absent profiles is an empty list. */
export function parseProfileNames(data: unknown): string[] {
  if (data === null || data === undefined) return []
  if (typeof data !== 'object' || Array.isArray(data)) throw new Error('unexpected response shape')
  const profiles = (data as Record<string, unknown>).profiles
  if (profiles === null || profiles === undefined) return []
  if (!Array.isArray(profiles)) throw new Error('unexpected response shape')
  return profiles.filter((p): p is string => typeof p === 'string' && p !== '')
}

export function parseProfile(data: unknown): Profile | null {
  if (typeof data !== 'object' || data === null) return null
  const r = data as Record<string, unknown>
  const name = str(r.name)
  if (!name) return null
  const enroll = typeof r.enroll === 'object' && r.enroll !== null ? (r.enroll as Record<string, unknown>) : {}
  return {
    name,
    os_family: str(r.os_family),
    answer_format: str(r.answer_format),
    template: str(r.template),
    enroll: {
      registration_token_secret_key: str(enroll.registration_token_secret_key),
      bundle_url: str(enroll.bundle_url),
      correlation_label: str(enroll.correlation_label),
    },
  }
}

/** The account the template runs as on first boot. */
export function runsAs(osFamily: string): 'root' | 'SYSTEM' {
  return osFamily === 'windows' ? 'SYSTEM' : 'root'
}

/** The template split into lines, exactly as stored (no trimming). */
export function templateLines(template: string): string[] {
  return template.split('\n')
}

/** Distinct `{{ … }}` expressions in first-seen order; `secret` flags secret-store reads. */
export function templatePlaceholders(template: string): TemplatePlaceholder[] {
  const seen = new Set<string>()
  const found: TemplatePlaceholder[] = []
  for (const match of template.match(/\{\{.*?\}\}/g) ?? []) {
    const expr = match.replace(/^\{\{\s*|\s*\}\}$/g, '')
    if (seen.has(expr)) continue
    seen.add(expr)
    found.push({ expr, secret: /^secret\s/.test(expr) })
  }
  return found
}

function withTenant(path: string, tenant: string): string {
  return tenant === '' ? path : `${path}?tenant=${encodeURIComponent(tenant)}`
}

function profilePath(name: string, tenant: string): string {
  return withTenant(`${profilesPath}/${encodeURIComponent(name)}`, tenant)
}

/** Builds the error for a non-OK response from the server's `{error: {code, message}}` body. */
async function apiError(response: Response, fallback: string): Promise<ProfileApiError> {
  // A 401 reaching here is the original challenge handed back after a cancelled tap.
  if (response.status === 401) {
    return new ProfileApiError('The passkey tap was cancelled or did not complete.', 401, 'CANCELLED')
  }
  const body = (await response.json().catch(() => null)) as Record<string, unknown> | null
  const err = body?.error
  let code = ''
  let message = ''
  if (typeof err === 'string') {
    message = err
  } else if (typeof err === 'object' && err !== null) {
    code = str((err as Record<string, unknown>).code)
    message = str((err as Record<string, unknown>).message)
  }
  return new ProfileApiError(message || `${fallback} — ${response.status}`, response.status, code)
}

function failure(cause: unknown, fallback: string): { message: string; code: string } {
  if (cause instanceof ProfileApiError) return { message: cause.message, code: cause.code }
  return { message: cause instanceof Error && cause.message ? cause.message : fallback, code: '' }
}

interface ListOutcome {
  key: string
  names?: string[]
  error?: string
  errorCode?: string
}

export interface UseProfilesResult {
  /** The tenant sent on every call; '' when none is in scope. */
  tenant: string
  names: string[]
  loading: boolean
  error: string | null
  /** The server's error code for a failed list, e.g. TENANT_REQUIRED; '' otherwise. */
  errorCode: string
  retry: () => void
  /** POST; resolves with the stored profile, rejects with ProfileApiError. */
  create: (input: ProfileCreateInput) => Promise<Profile>
  /** DELETE; rejects with ProfileApiError. */
  remove: (name: string) => Promise<void>
}

export function useProfiles(): UseProfilesResult {
  const { scope } = useTenantScope()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<ListOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `${scope}:${attempt}`

  useEffect(() => {
    let cancelled = false
    apiFetch(withTenant(profilesPath, scope))
      .then(async (response) => {
        if (!response.ok) throw await apiError(response, `GET ${profilesPath}`)
        const names = parseProfileNames(unwrapEnvelope<unknown>(await response.json()))
        if (cancelled) return
        setOutcome({ key, names })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        const { message, code } = failure(cause, `GET ${profilesPath} — request failed`)
        setOutcome({ key, error: message, errorCode: code })
      })
    return () => {
      cancelled = true
    }
  }, [key, scope])

  const create = useCallback(
    async (input: ProfileCreateInput): Promise<Profile> => {
      const response = await apiFetch(withTenant(profilesPath, scope), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      })
      if (!response.ok) throw await apiError(response, 'Create failed')
      const created = parseProfile(unwrapEnvelope<unknown>(await response.json()))
      if (created === null) throw new Error('Unexpected response shape from profile create')
      return created
    },
    [scope],
  )

  const remove = useCallback(
    async (name: string): Promise<void> => {
      const response = await apiFetch(profilePath(name, scope), { method: 'DELETE' })
      if (!response.ok) throw await apiError(response, 'Delete failed')
    },
    [scope],
  )

  const current = outcome?.key === key ? outcome : null
  return {
    tenant: scope,
    names: current?.names ?? [],
    loading: current === null,
    error: current?.error ?? null,
    errorCode: current?.errorCode ?? '',
    retry,
    create,
    remove,
  }
}

interface DetailOutcome {
  key: string
  profile?: Profile
  error?: string
}

export interface UseProfileResult {
  profile: Profile | null
  loading: boolean
  error: string | null
  retry: () => void
}

/** Fetches one profile when a name is selected; idle (not loading) for null. */
export function useProfile(name: string | null): UseProfileResult {
  const { scope } = useTenantScope()
  const [attempt, setAttempt] = useState(0)
  const [outcome, setOutcome] = useState<DetailOutcome | null>(null)
  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  const key = `${scope}:${name ?? ''}:${attempt}`

  useEffect(() => {
    if (name === null) return
    let cancelled = false
    apiFetch(profilePath(name, scope))
      .then(async (response) => {
        if (!response.ok) throw await apiError(response, `GET ${profilesPath}/{name}`)
        const profile = parseProfile(unwrapEnvelope<unknown>(await response.json()))
        if (profile === null) throw new Error('unexpected response shape')
        if (cancelled) return
        setOutcome({ key, profile })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setOutcome({ key, error: failure(cause, 'Could not load the profile').message })
      })
    return () => {
      cancelled = true
    }
  }, [key, name, scope])

  if (name === null) return { profile: null, loading: false, error: null, retry }
  const current = outcome?.key === key ? outcome : null
  return {
    profile: current?.profile ?? null,
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
