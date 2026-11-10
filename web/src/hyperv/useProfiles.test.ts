// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { createElement, type ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
import { TenantScopeProvider } from '../shell/TenantScopeContext.tsx'
import {
  ProfileApiError,
  parseProfile,
  parseProfileNames,
  runsAs,
  templateLines,
  templatePlaceholders,
  useProfile,
  useProfiles,
  type ProfileCreateInput,
} from './useProfiles.ts'

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

function wrapper(rootPath: string) {
  return function Wrapper({ children }: { children: ReactNode }) {
    // This file is .ts (no JSX); the provider requires children as a prop for its type.
    // eslint-disable-next-line react/no-children-prop
    return createElement(TenantScopeProvider, { rootPath, children })
  }
}

const input: ProfileCreateInput = {
  name: 'linux-cloud-base',
  os_family: 'linux',
  answer_format: 'cloud-init',
  template: '#cloud-config\nhostname: {{ .VMName }}',
  enroll: {
    registration_token_secret_key: 'hyperv/enroll/regtoken',
    bundle_url: 'https://controller.acme-corp.example/bundles/steward-linux-amd64',
    correlation_label: 'vm-build',
  },
}

describe('parseProfileNames', () => {
  it('reads the names-only list payload', () => {
    expect(parseProfileNames({ profiles: ['b', 'a'] })).toEqual(['b', 'a'])
  })

  it('treats null, absent and null profiles as an empty list', () => {
    expect(parseProfileNames(null)).toEqual([])
    expect(parseProfileNames({})).toEqual([])
    expect(parseProfileNames({ profiles: null })).toEqual([])
  })

  it('drops non-string entries and rejects a wrong shape', () => {
    expect(parseProfileNames({ profiles: ['a', 3, '', null] })).toEqual(['a'])
    expect(() => parseProfileNames([])).toThrow()
    expect(() => parseProfileNames({ profiles: 'a' })).toThrow()
  })
})

describe('parseProfile', () => {
  it('coerces the wire shape and defaults a missing enroll block', () => {
    const p = parseProfile({ name: 'n', os_family: 'linux', answer_format: 'preseed', template: 't' })
    expect(p).toEqual({
      name: 'n',
      os_family: 'linux',
      answer_format: 'preseed',
      template: 't',
      enroll: { registration_token_secret_key: '', bundle_url: '', correlation_label: '' },
    })
  })

  it('returns null for a payload with no name', () => {
    expect(parseProfile({ template: 't' })).toBeNull()
    expect(parseProfile(null)).toBeNull()
    expect(parseProfile('x')).toBeNull()
  })
})

describe('template helpers', () => {
  it('lists each distinct placeholder once and flags secret references', () => {
    const found = templatePlaceholders(
      'a {{ .VMName }} b {{ .VMName }}\npw {{ secret "hyperv/apt-mirror-password" }} {{.BundleURL}}',
    )
    expect(found).toEqual([
      { expr: '.VMName', secret: false },
      { expr: 'secret "hyperv/apt-mirror-password"', secret: true },
      { expr: '.BundleURL', secret: false },
    ])
  })

  it('splits a template into numbered lines and reports runs-as', () => {
    expect(templateLines('a\nb\n')).toEqual(['a', 'b', ''])
    expect(runsAs('windows')).toBe('SYSTEM')
    expect(runsAs('linux')).toBe('root')
  })
})

describe('useProfiles', () => {
  it('lists names with the tenant from the tenant scope on the query string', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { profiles: ['a', 'b'] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('acme-corp') })
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.names).toEqual(['a', 'b'])
    expect(result.current.error).toBeNull()
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/hyperv/profiles?tenant=acme-corp')
  })

  it('surfaces TENANT_REQUIRED as an error state', async () => {
    fetchMock.mockResolvedValue(
      json(400, { error: { code: 'TENANT_REQUIRED', message: 'tenant is required: pass ?tenant=<id>' } }),
    )
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('') })
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.errorCode).toBe('TENANT_REQUIRED')
    expect(result.current.error).toContain('tenant is required')
    expect(result.current.names).toEqual([])
    // No tenant is in scope, so none is sent.
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/hyperv/profiles')
  })

  it('reports a failed list as an error and retries', async () => {
    fetchMock.mockResolvedValueOnce(json(500, { error: { code: 'INTERNAL_ERROR', message: 'boom' } }))
    fetchMock.mockResolvedValueOnce(json(200, { data: { profiles: ['a'] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('t1') })
    await waitFor(() => expect(result.current.error).not.toBeNull())
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.names).toEqual(['a']))
    expect(result.current.error).toBeNull()
  })

  it('create POSTs {name, os_family, answer_format, template, enroll} to the tenant', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { profiles: [] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('acme-corp') })
    await waitFor(() => expect(result.current.loading).toBe(false))
    fetchMock.mockResolvedValueOnce(json(201, { data: { ...input } }))
    let created = null as Awaited<ReturnType<typeof result.current.create>> | null
    await act(async () => {
      created = await result.current.create(input)
    })
    expect(created?.name).toBe('linux-cloud-base')
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST')
    expect(String(post?.[0])).toBe('/api/v1/hyperv/profiles?tenant=acme-corp')
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(input)
  })

  it('surfaces server validation errors', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { profiles: [] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('acme-corp') })
    await waitFor(() => expect(result.current.loading).toBe(false))
    const message = 'hyperv: invalid profile template: template: x:14: function "secrt" not defined'
    fetchMock.mockResolvedValueOnce(json(400, { error: { code: 'INVALID_TEMPLATE', message } }))
    let caught: unknown = null
    await act(async () => {
      await result.current.create(input).catch((e: unknown) => {
        caught = e
      })
    })
    expect(caught).toBeInstanceOf(ProfileApiError)
    const err = caught as ProfileApiError
    expect(err.code).toBe('INVALID_TEMPLATE')
    expect(err.status).toBe(400)
    expect(err.message).toBe(message)
  })

  it('maps a handed-back 401 (cancelled passkey tap) to a cancelled error', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { profiles: [] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('t1') })
    await waitFor(() => expect(result.current.loading).toBe(false))
    fetchMock.mockResolvedValueOnce(json(401, {}))
    let caught: unknown = null
    await act(async () => {
      await result.current.create(input).catch((e: unknown) => {
        caught = e
      })
    })
    expect((caught as ProfileApiError).code).toBe('CANCELLED')
  })

  it('remove DELETEs the encoded name on the tenant', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { profiles: ['a'] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('acme-corp') })
    await waitFor(() => expect(result.current.loading).toBe(false))
    fetchMock.mockResolvedValueOnce(json(200, { data: { deleted: 'a' } }))
    await act(async () => {
      await result.current.remove('a/b')
    })
    const del = fetchMock.mock.calls.find(([, init]) => init?.method === 'DELETE')
    expect(String(del?.[0])).toBe('/api/v1/hyperv/profiles/a%2Fb?tenant=acme-corp')
  })

  it('remove surfaces a not-found response', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { profiles: ['a'] } }))
    const { result } = renderHook(() => useProfiles(), { wrapper: wrapper('t1') })
    await waitFor(() => expect(result.current.loading).toBe(false))
    fetchMock.mockResolvedValueOnce(json(404, { error: { code: 'NOT_FOUND', message: 'Hyperv profile not found' } }))
    await expect(result.current.remove('a')).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 })
  })
})

describe('useProfile', () => {
  it('fetches the detail of the selected name with the tenant', async () => {
    fetchMock.mockResolvedValue(
      json(200, { data: { name: 'a', os_family: 'linux', answer_format: 'cloud-init', template: 'x', enroll: {} } }),
    )
    const { result } = renderHook(() => useProfile('a'), { wrapper: wrapper('acme-corp') })
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.profile?.name).toBe('a'))
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('/api/v1/hyperv/profiles/a?tenant=acme-corp')
  })

  it('does not fetch without a selection', () => {
    const { result } = renderHook(() => useProfile(null), { wrapper: wrapper('t1') })
    expect(result.current.profile).toBeNull()
    expect(result.current.loading).toBe(false)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('reports a failed detail fetch', async () => {
    fetchMock.mockResolvedValue(json(404, { error: { code: 'NOT_FOUND', message: 'Hyperv profile not found' } }))
    const { result } = renderHook(() => useProfile('gone'), { wrapper: wrapper('t1') })
    await waitFor(() => expect(result.current.error).toBe('Hyperv profile not found'))
    expect(result.current.profile).toBeNull()
  })
})
