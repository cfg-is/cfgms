// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CredentialsError,
  listCredentials,
  parsePendingCredential,
  parsePendingCredentialList,
  parseRevealedPassword,
  revealCredential,
} from './credentialsApi.ts'

const fetchMock = vi.fn<typeof fetch>()
const SECRET = 'S3cret-Initial-Pw!'
const ID = '0123456789abcdef0123456789abcdef'

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

let logged: string[] = []

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  logged = []
  for (const method of ['log', 'info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      logged.push(args.map(String).join(' '))
    })
  }
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('parsers', () => {
  it('parsePendingCredential requires an id and coerces other fields', () => {
    expect(parsePendingCredential(null)).toBeNull()
    expect(parsePendingCredential({ resource_id: 'x' })).toBeNull()
    expect(parsePendingCredential({ id: 'a', resource_id: 5, created_at: 't' })).toEqual({
      id: 'a',
      resource_id: '',
      created_at: 't',
      expires_at: '',
    })
  })

  it('parsePendingCredentialList accepts null, skips bad items, throws on other shapes', () => {
    expect(parsePendingCredentialList(null)).toEqual([])
    expect(parsePendingCredentialList({ items: null })).toEqual([])
    expect(parsePendingCredentialList({ items: [{ id: 'a' }, 'junk'] })).toHaveLength(1)
    expect(() => parsePendingCredentialList([])).toThrow()
    expect(() => parsePendingCredentialList({ items: {} })).toThrow()
    expect(() => parsePendingCredentialList('x')).toThrow()
  })

  it('parseRevealedPassword needs a non-empty string password', () => {
    expect(parseRevealedPassword(null)).toBeNull()
    expect(parseRevealedPassword({ password: '' })).toBeNull()
    expect(parseRevealedPassword({ password: 5 })).toBeNull()
    expect(parseRevealedPassword({ password: 'p' })).toBe('p')
  })
})

describe('listCredentials', () => {
  it('reads the pending list from the list route', async () => {
    fetchMock.mockResolvedValue(
      json(200, { data: { items: [{ id: ID, resource_id: 'user-a', created_at: 'c', expires_at: 'e' }] } }),
    )
    const items = await listCredentials()
    expect(items).toEqual([{ id: ID, resource_id: 'user-a', created_at: 'c', expires_at: 'e' }])
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/directory/credentials')
  })

  it('throws a status-only error on a failed list', async () => {
    fetchMock.mockResolvedValue(json(500, { error: 'boom' }))
    await expect(listCredentials()).rejects.toMatchObject({ httpStatus: 500 })
  })
})

describe('revealCredential', () => {
  it('POSTs with only the record id in the URL and no body, and returns the password', async () => {
    fetchMock.mockResolvedValue(json(200, { data: { id: ID, resource_id: 'user-a', password: SECRET } }))
    await expect(revealCredential(ID)).resolves.toEqual({ status: 'revealed', password: SECRET })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0] ?? []
    expect(url).toBe(`/api/v1/directory/credentials/${ID}/reveal`)
    expect(String(url)).not.toContain(SECRET)
    expect(String(url)).not.toContain('?')
    expect(init?.method).toBe('POST')
    expect(init?.body).toBeUndefined()
    expect(new Headers(init?.headers).get('X-Presence-Token')).toBeNull()
  })

  it('encodes the id as a single path segment', async () => {
    fetchMock.mockResolvedValue(json(410, {}))
    await revealCredential('a/b?c=d')
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/directory/credentials/a%2Fb%3Fc%3Dd/reveal')
  })

  it('never logs the response, on success or on failure', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { password: SECRET } }))
    await revealCredential(ID)
    fetchMock.mockResolvedValueOnce(json(500, { error: SECRET }))
    await revealCredential(ID).catch(() => {})
    fetchMock.mockResolvedValueOnce(json(200, { data: { password: 5, note: SECRET } }))
    await revealCredential(ID).catch(() => {})
    expect(logged).toEqual([])
  })

  it('reports 410 as gone, not as an error', async () => {
    fetchMock.mockResolvedValue(json(410, { error: 'credential is no longer available' }))
    await expect(revealCredential(ID)).resolves.toEqual({ status: 'gone' })
  })

  it('never puts the value or response text in an error', async () => {
    for (const status of [401, 403, 404, 409, 500]) {
      fetchMock.mockResolvedValueOnce(json(status, { error: SECRET, password: SECRET }))
      const err = await revealCredential(ID).catch((e: unknown) => e)
      expect(err).toBeInstanceOf(CredentialsError)
      expect((err as CredentialsError).httpStatus).toBe(status)
      expect((err as CredentialsError).message).not.toContain(SECRET)
    }
  })

  it('treats an unexpected 200 body as an error without echoing it', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { password: '', extra: SECRET } }))
    const err = await revealCredential(ID).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(CredentialsError)
    expect((err as Error).message).not.toContain(SECRET)
    fetchMock.mockResolvedValueOnce(new Response('not json', { status: 200 }))
    await expect(revealCredential(ID)).rejects.toBeInstanceOf(CredentialsError)
  })
})
