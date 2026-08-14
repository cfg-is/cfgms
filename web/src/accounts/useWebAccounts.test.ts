// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createRole,
  updateRole,
  deleteRole,
  validateJustification,
  JUSTIFICATION_MIN_LENGTH,
  JUSTIFICATION_MAX_LENGTH,
  parseWebAccountInfo,
  parseWebAccountList,
  parseWebAccountCreateResult,
  parseRoleInfo,
  parseRoleList,
  parsePermissionInfo,
  parsePermissionList,
  createWebAccount,
  revokeEnrollmentLink,
  assignSubjectRole,
  revokeSubjectRole,
  updateWebAccount,
  EscalationError,
} from './useWebAccounts.ts'

describe('parseWebAccountInfo', () => {
  it('parses a valid account record', () => {
    const raw = {
      id: 'acc-1',
      username: 'fleet-admin',
      tenant_id: 'tenant-a',
      permissions: ['steward:list', 'steward:read'],
      created_at: '2026-01-01T00:00:00Z',
    }
    const result = parseWebAccountInfo(raw)
    expect(result).not.toBeNull()
    expect(result?.id).toBe('acc-1')
    expect(result?.username).toBe('fleet-admin')
    expect(result?.tenant_id).toBe('tenant-a')
    expect(result?.permissions).toEqual(['steward:list', 'steward:read'])
    expect(result?.created_at).toBe('2026-01-01T00:00:00Z')
  })

  it('returns null for missing id', () => {
    expect(parseWebAccountInfo({ username: 'no-id', tenant_id: 't' })).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parseWebAccountInfo(null)).toBeNull()
    expect(parseWebAccountInfo('string')).toBeNull()
    expect(parseWebAccountInfo(42)).toBeNull()
  })

  it('coerces missing optional fields to safe defaults', () => {
    const result = parseWebAccountInfo({ id: 'x' })
    expect(result?.username).toBe('')
    expect(result?.permissions).toEqual([])
    expect(result?.tenant_id).toBe('')
    expect(result?.has_outstanding_enrollment_link).toBe(false)
    expect(result?.disabled).toBe(false)
  })

  it('parses disabled field correctly', () => {
    const enabled = parseWebAccountInfo({ id: 'x', disabled: false })
    expect(enabled?.disabled).toBe(false)
    const disabled = parseWebAccountInfo({ id: 'x', disabled: true })
    expect(disabled?.disabled).toBe(true)
    const missing = parseWebAccountInfo({ id: 'x' })
    expect(missing?.disabled).toBe(false)
  })

  it('parses has_outstanding_enrollment_link correctly', () => {
    const withLink = parseWebAccountInfo({ id: 'x', has_outstanding_enrollment_link: true })
    expect(withLink?.has_outstanding_enrollment_link).toBe(true)
    const withoutLink = parseWebAccountInfo({ id: 'x', has_outstanding_enrollment_link: false })
    expect(withoutLink?.has_outstanding_enrollment_link).toBe(false)
    const missingField = parseWebAccountInfo({ id: 'x' })
    expect(missingField?.has_outstanding_enrollment_link).toBe(false)
  })

  it('filters non-string entries from permissions', () => {
    const result = parseWebAccountInfo({
      id: 'x',
      permissions: ['steward:list', 42, null, 'steward:read'],
    })
    expect(result?.permissions).toEqual(['steward:list', 'steward:read'])
  })
})

describe('parseWebAccountList', () => {
  it('parses a list of account records', () => {
    const raw = [
      { id: 'a1', username: 'user-a', tenant_id: 'ta', permissions: [], created_at: '' },
      { id: 'a2', username: 'user-b', tenant_id: 'tb', permissions: ['steward:read'], created_at: '' },
    ]
    const result = parseWebAccountList(raw)
    expect(result).toHaveLength(2)
    expect(result[0]!.id).toBe('a1')
    expect(result[1]!.permissions).toEqual(['steward:read'])
  })

  it('skips invalid entries', () => {
    const raw = [{ id: 'valid', username: 'u', tenant_id: 't', permissions: [], created_at: '' }, null, 42]
    const result = parseWebAccountList(raw)
    expect(result).toHaveLength(1)
    expect(result[0]!.id).toBe('valid')
  })

  it('throws for non-array input', () => {
    expect(() => parseWebAccountList({})).toThrow()
    expect(() => parseWebAccountList(null)).toThrow()
  })

  it('returns empty list for empty array', () => {
    expect(parseWebAccountList([])).toEqual([])
  })
})

describe('parseRoleInfo', () => {
  it('parses a valid role record', () => {
    const raw = {
      id: 'role-1',
      name: 'fleet-viewer',
      description: 'Read-only fleet access',
      permissions: ['steward:list', 'steward:read'],
      tenant_id: 'tenant-a',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-02-01T00:00:00Z',
    }
    const result = parseRoleInfo(raw)
    expect(result).not.toBeNull()
    expect(result?.id).toBe('role-1')
    expect(result?.name).toBe('fleet-viewer')
    expect(result?.permissions).toEqual(['steward:list', 'steward:read'])
  })

  it('returns null for missing id', () => {
    expect(parseRoleInfo({ name: 'no-id' })).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parseRoleInfo(null)).toBeNull()
    expect(parseRoleInfo('string')).toBeNull()
  })

  it('coerces missing fields to safe defaults', () => {
    const result = parseRoleInfo({ id: 'r1' })
    expect(result?.name).toBe('')
    expect(result?.description).toBe('')
    expect(result?.permissions).toEqual([])
  })
})

describe('parseRoleList', () => {
  it('parses a list of role records', () => {
    const raw = [
      { id: 'r1', name: 'role-a', description: '', permissions: [], tenant_id: '', created_at: '', updated_at: '' },
      { id: 'r2', name: 'role-b', description: 'desc', permissions: ['rbac:list-roles'], tenant_id: 'ta', created_at: '', updated_at: '' },
    ]
    const result = parseRoleList(raw)
    expect(result).toHaveLength(2)
    expect(result[1]!.name).toBe('role-b')
  })

  it('throws for non-array input', () => {
    expect(() => parseRoleList(null)).toThrow()
  })

  it('returns empty list for empty array', () => {
    expect(parseRoleList([])).toEqual([])
  })
})

describe('parsePermissionInfo', () => {
  it('parses a valid permission record', () => {
    const raw = {
      id: 'perm-1',
      name: 'steward:list',
      description: 'List stewards',
      resource_type: 'steward',
      actions: ['list'],
    }
    const result = parsePermissionInfo(raw)
    expect(result).not.toBeNull()
    expect(result?.id).toBe('perm-1')
    expect(result?.name).toBe('steward:list')
    expect(result?.description).toBe('List stewards')
    expect(result?.resource_type).toBe('steward')
    expect(result?.actions).toEqual(['list'])
  })

  it('returns null for missing id', () => {
    expect(parsePermissionInfo({ name: 'no-id' })).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parsePermissionInfo(null)).toBeNull()
    expect(parsePermissionInfo(42)).toBeNull()
    expect(parsePermissionInfo('string')).toBeNull()
  })

  it('coerces missing fields to safe defaults', () => {
    const result = parsePermissionInfo({ id: 'p1' })
    expect(result?.name).toBe('')
    expect(result?.description).toBe('')
    expect(result?.resource_type).toBe('')
    expect(result?.actions).toEqual([])
  })

  it('filters non-string entries from actions', () => {
    const result = parsePermissionInfo({ id: 'p1', actions: ['list', 42, null, 'read'] })
    expect(result?.actions).toEqual(['list', 'read'])
  })
})

describe('parsePermissionList', () => {
  it('parses a list of permission records', () => {
    const raw = [
      { id: 'p1', name: 'steward:list', description: 'List stewards', resource_type: 'steward', actions: ['list'] },
      { id: 'p2', name: 'steward:read', description: 'Read steward', resource_type: 'steward', actions: ['read'] },
    ]
    const result = parsePermissionList(raw)
    expect(result).toHaveLength(2)
    expect(result[0]!.id).toBe('p1')
    expect(result[1]!.name).toBe('steward:read')
  })

  it('skips invalid entries', () => {
    const raw = [
      { id: 'p1', name: 'perm-a', description: '', resource_type: '', actions: [] },
      null,
      42,
    ]
    const result = parsePermissionList(raw)
    expect(result).toHaveLength(1)
    expect(result[0]!.id).toBe('p1')
  })

  it('throws for non-array input', () => {
    expect(() => parsePermissionList(null)).toThrow()
    expect(() => parsePermissionList({})).toThrow()
  })

  it('returns empty list for empty array', () => {
    expect(parsePermissionList([])).toEqual([])
  })
})

describe('validateJustification (M-AUTH-2)', () => {
  it('accepts a justification at the server minimum length', () => {
    expect(validateJustification('a'.repeat(JUSTIFICATION_MIN_LENGTH))).toBeNull()
  })

  it('accepts a justification at the server maximum length', () => {
    expect(validateJustification('a'.repeat(JUSTIFICATION_MAX_LENGTH))).toBeNull()
  })

  it('rejects an empty or whitespace-only justification', () => {
    expect(validateJustification('')).toMatch(/required/i)
    expect(validateJustification('    ')).toMatch(/required/i)
  })

  it('rejects a justification below the server minimum length', () => {
    expect(validateJustification('a'.repeat(JUSTIFICATION_MIN_LENGTH - 1))).toMatch(
      /at least 10 characters/i,
    )
  })

  it('measures length after trimming, matching the server', () => {
    expect(validateJustification('   short   ')).toMatch(/at least 10 characters/i)
  })

  it('rejects a justification above the server maximum length', () => {
    expect(validateJustification('a'.repeat(JUSTIFICATION_MAX_LENGTH + 1))).toMatch(
      /at most 1000 characters/i,
    )
  })

  it('rejects control characters that would allow header injection', () => {
    expect(validateJustification('rotating perms\r\nX-Injected: yes')).toMatch(/plain text/i)
    expect(validateJustification('rotating perms\u0000 padded')).toMatch(/plain text/i)
  })

  it('rejects code points the fetch Headers ByteString cannot carry', () => {
    // A pasted smart quote would otherwise throw inside apiFetch.
    expect(validateJustification('rotating the operator\u2019s permissions')).toMatch(
      /plain text/i,
    )
  })

  it('accepts Latin-1 accented text', () => {
    expect(validateJustification('rotation des permissions requise')).toBeNull()
    expect(validateJustification('r\u00e9vocation des permissions op\u00e9rateur')).toBeNull()
  })
})

// ── Role mutation requests (M-AUTH-2 + tenant attribution) ───────────────────

describe('role mutations', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: {} }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function lastRequest(): { headers: Headers; body: unknown } {
    const call = fetchMock.mock.calls.at(-1)
    expect(call).toBeDefined()
    const init = call![1] as RequestInit
    const raw = init.body
    return {
      headers: new Headers(init.headers),
      body: typeof raw === 'string' ? JSON.parse(raw) : null,
    }
  }

  it('sends the justification header on create', async () => {
    await createRole('fleet-viewer', 'read only', ['p1'], 'granting read-only fleet access')
    expect(lastRequest().headers.get('X-Justification')).toBe('granting read-only fleet access')
  })

  it('sends the justification header on update and no browser-supplied tenant', async () => {
    await updateRole('role-1', 'fleet-viewer', 'read only', ['p1'], 'narrowing fleet permissions')
    const req = lastRequest()
    expect(req.headers.get('X-Justification')).toBe('narrowing fleet permissions')
    expect(req.body).toMatchObject({ name: 'fleet-viewer', permissions: ['p1'] })
    // The server derives the tenant from the session and carries the stored
    // role's attribution into the update; a client tenant would be a
    // cross-tenant write vector.
    expect(req.body).not.toHaveProperty('tenant_id')
  })

  it('sends the justification header on delete', async () => {
    await deleteRole('role-1', 'role superseded by fleet-viewer')
    expect(lastRequest().headers.get('X-Justification')).toBe('role superseded by fleet-viewer')
  })

  it('trims the justification before sending it', async () => {
    await deleteRole('role-1', '   role superseded by fleet-viewer   ')
    expect(lastRequest().headers.get('X-Justification')).toBe('role superseded by fleet-viewer')
  })

  it('issues no request when the create justification is unusable', async () => {
    await expect(createRole('fleet-viewer', '', [], 'short')).rejects.toThrow(/at least 10 characters/i)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('issues no request when the update justification is unusable', async () => {
    await expect(updateRole('role-1', 'fleet-viewer', '', [], '')).rejects.toThrow(
      /required/i,
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('issues no request when the delete justification is unusable', async () => {
    await expect(deleteRole('role-1', 'brief')).rejects.toThrow(/at least 10 characters/i)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('issues no request when the justification would inject a header', async () => {
    await expect(
      deleteRole('role-1', 'superseded role\r\nX-Injected: yes'),
    ).rejects.toThrow(/plain text/i)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

// ── parseWebAccountCreateResult ───────────────────────────────────────────────

describe('parseWebAccountCreateResult', () => {
  it('parses a valid create response with enrollment_magic_link', () => {
    const raw = {
      id: 'acc-1',
      username: 'fleet-admin',
      tenant_id: 'tenant-a',
      permissions: [],
      created_at: '2026-01-01T00:00:00Z',
      has_outstanding_enrollment_link: true,
      enrollment_magic_link: 'deadbeef1234567890abcdef12345678deadbeef',
    }
    const result = parseWebAccountCreateResult(raw)
    expect(result).not.toBeNull()
    expect(result?.account.id).toBe('acc-1')
    expect(result?.account.username).toBe('fleet-admin')
    expect(result?.account.has_outstanding_enrollment_link).toBe(true)
    expect(result?.enrollment_magic_link).toBe('deadbeef1234567890abcdef12345678deadbeef')
  })

  it('returns null for non-object input', () => {
    expect(parseWebAccountCreateResult(null)).toBeNull()
    expect(parseWebAccountCreateResult('string')).toBeNull()
    expect(parseWebAccountCreateResult(42)).toBeNull()
  })

  it('returns null when account id is missing', () => {
    expect(parseWebAccountCreateResult({ username: 'x' })).toBeNull()
  })

  it('coerces missing enrollment_magic_link to empty string', () => {
    const result = parseWebAccountCreateResult({ id: 'x' })
    expect(result?.enrollment_magic_link).toBe('')
  })
})

// ── createWebAccount — no password, step-up transparent ──────────────────────

describe('createWebAccount', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            id: 'acc-new',
            username: 'new-admin',
            tenant_id: 'default',
            permissions: [],
            created_at: '2026-01-01T00:00:00Z',
            has_outstanding_enrollment_link: true,
            enrollment_magic_link: 'aabbcc112233445566778899aabbcc1122334455',
          },
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends POST to /api/v1/web/accounts without a password field', async () => {
    await createWebAccount('new-admin', 'default')
    const call = fetchMock.mock.calls.at(-1)
    expect(call).toBeDefined()
    const init = call![1] as RequestInit
    expect(init.method).toBe('POST')
    const body = typeof init.body === 'string' ? JSON.parse(init.body) as Record<string, unknown> : null
    expect(body).not.toBeNull()
    expect(body).not.toHaveProperty('password', 'password must never be sent')
    expect(body).toHaveProperty('username', 'new-admin')
  })

  it('returns the enrollment_magic_link from the server response', async () => {
    const result = await createWebAccount('new-admin')
    expect(result.enrollment_magic_link).toBe('aabbcc112233445566778899aabbcc1122334455')
    expect(result.account.has_outstanding_enrollment_link).toBe(true)
  })

  it('throws on server error', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Account already exists' } }),
        { status: 409 },
      ),
    )
    await expect(createWebAccount('existing')).rejects.toThrow(/Account already exists/i)
  })

  it('does not include tenantId in body when omitted', async () => {
    await createWebAccount('new-admin')
    const call = fetchMock.mock.calls.at(-1)!
    const body = JSON.parse((call[1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).not.toHaveProperty('tenant_id')
  })
})

// ── revokeEnrollmentLink ──────────────────────────────────────────────────────

describe('revokeEnrollmentLink', () => {
  const fetchMock = vi.fn<typeof fetch>()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: { username: 'fleet-admin', revoked: true } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends POST to the revoke endpoint for the given username', async () => {
    await revokeEnrollmentLink('fleet-admin')
    const call = fetchMock.mock.calls.at(-1)
    expect(call).toBeDefined()
    expect(call![0]).toContain('/api/v1/web/accounts/fleet-admin/enrollment-link/revoke')
    expect((call![1] as RequestInit).method).toBe('POST')
  })

  it('URL-encodes the username in the path', async () => {
    await revokeEnrollmentLink('fleet.admin_01')
    const call = fetchMock.mock.calls.at(-1)!
    expect(call[0]).toContain(encodeURIComponent('fleet.admin_01'))
  })

  it('throws on server error', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'No outstanding link' } }),
        { status: 409 },
      ),
    )
    await expect(revokeEnrollmentLink('fleet-admin')).rejects.toThrow(/No outstanding link/i)
  })
})

// ── assignSubjectRole (Issue #3134) ───────────────────────────────────────────

describe('assignSubjectRole', () => {
  const fetchMock = vi.fn<typeof fetch>()
  const why = 'granting fleet-viewer for on-call rotation'

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: {} }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends POST to /api/v1/rbac/subjects/{id}/roles with the role_id', async () => {
    await assignSubjectRole('subject-1', 'role-1', why)
    const call = fetchMock.mock.calls.at(-1)!
    expect(call[0]).toContain('/api/v1/rbac/subjects/subject-1/roles')
    expect((call[1] as RequestInit).method).toBe('POST')
    const body = JSON.parse((call[1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).toHaveProperty('role_id', 'role-1')
  })

  it('URL-encodes the subject ID', async () => {
    await assignSubjectRole('subject/1', 'role-1', why)
    expect(fetchMock.mock.calls.at(-1)![0]).toContain(encodeURIComponent('subject/1'))
  })

  // M-AUTH-2: the controller's ValidateSensitiveOperation refuses the grant
  // before any store write unless this header is present.
  it('sends the trimmed justification in the X-Justification header', async () => {
    await assignSubjectRole('subject-1', 'role-1', `   ${why}   `)
    const headers = new Headers((fetchMock.mock.calls.at(-1)![1] as RequestInit).headers)
    expect(headers.get('X-Justification')).toBe(why)
    expect(headers.get('Content-Type')).toBe('application/json')
  })

  it('issues no request when the justification is missing or too short', async () => {
    await expect(assignSubjectRole('subject-1', 'role-1', '')).rejects.toThrow(/required/i)
    await expect(assignSubjectRole('subject-1', 'role-1', 'short')).rejects.toThrow(
      /at least 10 characters/i,
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('throws EscalationError on 403 response', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Assigning this role would allow privilege escalation' } }),
        { status: 403 },
      ),
    )
    await expect(assignSubjectRole('subject-1', 'role-1', why)).rejects.toBeInstanceOf(
      EscalationError,
    )
  })

  it('includes the server message in the EscalationError', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Escalation prevented' } }),
        { status: 403 },
      ),
    )
    try {
      await assignSubjectRole('subject-1', 'role-1', why)
      expect.fail('should have thrown')
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(EscalationError)
      expect((e as Error).message).toMatch(/Escalation prevented/)
    }
  })

  it('EscalationError has isEscalationPrevention property', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: { message: 'blocked' } }), { status: 403 }),
    )
    try {
      await assignSubjectRole('subject-1', 'role-1', why)
      expect.fail('should have thrown')
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(EscalationError)
      expect((e as EscalationError).isEscalationPrevention).toBe(true)
    }
  })

  // A 403 JUSTIFICATION_REQUIRED or SYSTEM_ROLE_IMMUTABLE is not an escalation
  // refusal — labelling it as one would misstate why the grant was blocked.
  it('throws a plain Error for non-escalation 403 codes', async () => {
    for (const code of ['JUSTIFICATION_REQUIRED', 'SYSTEM_ROLE_IMMUTABLE']) {
      fetchMock.mockResolvedValue(
        new Response(JSON.stringify({ error: { code, message: `refused: ${code}` } }), {
          status: 403,
        }),
      )
      let thrown: unknown
      try {
        await assignSubjectRole('subject-1', 'role-1', why)
      } catch (e: unknown) {
        thrown = e
      }
      expect(thrown).toBeInstanceOf(Error)
      expect(thrown).not.toBeInstanceOf(EscalationError)
      expect((thrown as Error).message).toBe(`refused: ${code}`)
    }
  })

  it('throws EscalationError for the ESCALATION_BLOCKED code', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: 'ESCALATION_BLOCKED', message: 'Role assignment blocked' },
        }),
        { status: 403 },
      ),
    )
    await expect(assignSubjectRole('subject-1', 'role-1', why)).rejects.toBeInstanceOf(
      EscalationError,
    )
  })

  it('throws a plain Error (not EscalationError) on non-403 failures', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Server error' } }),
        { status: 500 },
      ),
    )
    let thrown: unknown
    try {
      await assignSubjectRole('subject-1', 'role-1', why)
    } catch (e: unknown) {
      thrown = e
    }
    expect(thrown).toBeInstanceOf(Error)
    expect(thrown).not.toBeInstanceOf(EscalationError)
  })

  it('uses a fallback message when the server body carries no message', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 403 }))
    await expect(assignSubjectRole('subject-1', 'role-1', why)).rejects.toThrow(
      /Assign failed — 403/,
    )
  })
})

// ── revokeSubjectRole (Issue #3134) ───────────────────────────────────────────

describe('revokeSubjectRole', () => {
  const fetchMock = vi.fn<typeof fetch>()
  const why = 'removing fleet-viewer after rotation ended'

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    fetchMock.mockResolvedValue(new Response('', { status: 200 }))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends DELETE to /api/v1/rbac/subjects/{id}/roles/{role_id}', async () => {
    await revokeSubjectRole('subject-1', 'role-1', why)
    const call = fetchMock.mock.calls.at(-1)!
    expect(call[0]).toContain('/api/v1/rbac/subjects/subject-1/roles/role-1')
    expect((call[1] as RequestInit).method).toBe('DELETE')
  })

  it('URL-encodes both the subject and role IDs', async () => {
    await revokeSubjectRole('sub/1', 'rol/1', why)
    const url = fetchMock.mock.calls.at(-1)![0] as string
    expect(url).toContain(encodeURIComponent('sub/1'))
    expect(url).toContain(encodeURIComponent('rol/1'))
  })

  // M-AUTH-2: Manager.RevokeRole refuses without a justification on the context.
  it('sends the trimmed justification in the X-Justification header', async () => {
    await revokeSubjectRole('subject-1', 'role-1', `  ${why}  `)
    const headers = new Headers((fetchMock.mock.calls.at(-1)![1] as RequestInit).headers)
    expect(headers.get('X-Justification')).toBe(why)
  })

  it('issues no request when the justification is missing or too short', async () => {
    await expect(revokeSubjectRole('subject-1', 'role-1', '')).rejects.toThrow(/required/i)
    await expect(revokeSubjectRole('subject-1', 'role-1', 'short')).rejects.toThrow(
      /at least 10 characters/i,
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('throws with the server message on failure', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Role not assigned to subject' } }),
        { status: 404 },
      ),
    )
    await expect(revokeSubjectRole('subject-1', 'role-1', why)).rejects.toThrow(
      /Role not assigned to subject/,
    )
  })

  it('uses a fallback message when the server body carries no message', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 500 }))
    await expect(revokeSubjectRole('subject-1', 'role-1', why)).rejects.toThrow(
      /Revoke failed — 500/,
    )
  })
})

// ── updateWebAccount (Issue #3132) ────────────────────────────────────────────

describe('updateWebAccount', () => {
  const fetchMock = vi.fn<typeof fetch>()

  function makeUpdateBody(overrides: Record<string, unknown> = {}) {
    return {
      id: 'acc-1',
      username: 'fleet-admin',
      tenant_id: 'tenant-a',
      permissions: ['steward:list'],
      disabled: false,
      created_at: '2026-01-01T00:00:00Z',
      has_outstanding_enrollment_link: false,
      ...overrides,
    }
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: makeUpdateBody() }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends PUT to /api/v1/web/accounts/{username}', async () => {
    await updateWebAccount('fleet-admin', { permissions: ['steward:list'] })
    const call = fetchMock.mock.calls.at(-1)!
    expect(call[0]).toContain('/api/v1/web/accounts/fleet-admin')
    expect((call[1] as RequestInit).method).toBe('PUT')
  })

  it('URL-encodes the username', async () => {
    await updateWebAccount('fleet.admin/01', { permissions: [] })
    const call = fetchMock.mock.calls.at(-1)!
    expect(call[0]).toContain(encodeURIComponent('fleet.admin/01'))
  })

  it('sends permissions in the request body when provided', async () => {
    await updateWebAccount('fleet-admin', { permissions: ['steward:list', 'steward:read'] })
    const call = fetchMock.mock.calls.at(-1)!
    const body = JSON.parse((call[1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).toHaveProperty('permissions', ['steward:list', 'steward:read'])
  })

  it('sends disabled in the request body when provided', async () => {
    await updateWebAccount('fleet-admin', { disabled: true })
    const body = JSON.parse((fetchMock.mock.calls.at(-1)![1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).toHaveProperty('disabled', true)
  })

  it('sends reset_credentials in the request body when provided', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: makeUpdateBody({ enrollment_magic_link: 'deadbeef1234567890' }) }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    await updateWebAccount('fleet-admin', { resetCredentials: true })
    const body = JSON.parse((fetchMock.mock.calls.at(-1)![1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).toHaveProperty('reset_credentials', true)
  })

  it('omits permissions when not provided', async () => {
    await updateWebAccount('fleet-admin', { disabled: false })
    const body = JSON.parse((fetchMock.mock.calls.at(-1)![1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).not.toHaveProperty('permissions')
  })

  it('omits disabled when not provided', async () => {
    await updateWebAccount('fleet-admin', { permissions: [] })
    const body = JSON.parse((fetchMock.mock.calls.at(-1)![1] as RequestInit).body as string) as Record<string, unknown>
    expect(body).not.toHaveProperty('disabled')
  })

  it('returns the updated account info', async () => {
    const result = await updateWebAccount('fleet-admin', { permissions: ['steward:list'] })
    expect(result.account.id).toBe('acc-1')
    expect(result.account.username).toBe('fleet-admin')
    expect(result.account.disabled).toBe(false)
  })

  it('returns enrollment_magic_link when reset_credentials triggers one', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ data: makeUpdateBody({ enrollment_magic_link: 'deadbeef1234567890abcdef' }) }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    const result = await updateWebAccount('fleet-admin', { resetCredentials: true })
    expect(result.enrollmentMagicLink).toBe('deadbeef1234567890abcdef')
  })

  it('returns undefined enrollmentMagicLink when not in response', async () => {
    const result = await updateWebAccount('fleet-admin', { permissions: [] })
    expect(result.enrollmentMagicLink).toBeUndefined()
  })

  it('throws with the server message on 400 error', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ error: { message: 'Permissions list exceeds maximum' } }),
        { status: 400 },
      ),
    )
    await expect(updateWebAccount('fleet-admin', { permissions: [] })).rejects.toThrow(
      /Permissions list exceeds maximum/,
    )
  })

  it('uses a fallback message when the server body carries no message', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 500 }))
    await expect(updateWebAccount('fleet-admin', {})).rejects.toThrow(/Update failed — 500/)
  })

  it('throws when the server returns a malformed success body', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await expect(updateWebAccount('fleet-admin', {})).rejects.toThrow(/Unexpected response shape/)
  })
})
