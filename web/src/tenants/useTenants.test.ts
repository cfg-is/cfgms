// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  parseTenantInfo,
  parseTenantList,
  parsePendingDeletion,
  suspendTenant,
  restoreTenant,
  createTenant,
  updateTenant,
  requestTenantDeletion,
  cancelTenantDeletion,
  approveTenantDeletion,
  errCodeSameApprover,
  TenantApiError,
} from './useTenants.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function jsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// ── parseTenantInfo ────────────────────────────────────────────────────────────

describe('parseTenantInfo', () => {
  it('parses a valid active tenant', () => {
    const raw = {
      id: 'msp-a',
      name: 'msp-a',
      description: 'MSP A tenant',
      parent_id: 'root',
      status: 'active',
      directly_suspended: false,
      cascade_suspended_from: null,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z',
    }
    const result = parseTenantInfo(raw)
    expect(result).not.toBeNull()
    expect(result?.id).toBe('msp-a')
    expect(result?.name).toBe('msp-a')
    expect(result?.description).toBe('MSP A tenant')
    expect(result?.parent_id).toBe('root')
    expect(result?.status).toBe('active')
    expect(result?.directly_suspended).toBe(false)
    expect(result?.cascade_suspended_from).toBeNull()
  })

  it('parses a directly-suspended tenant', () => {
    const raw = {
      id: 'client-1',
      name: 'client-1',
      parent_id: 'msp-a',
      status: 'suspended',
      directly_suspended: true,
      cascade_suspended_from: null,
      created_at: '',
      updated_at: '',
    }
    const result = parseTenantInfo(raw)
    expect(result?.status).toBe('suspended')
    expect(result?.directly_suspended).toBe(true)
    expect(result?.cascade_suspended_from).toBeNull()
  })

  it('parses a cascade-suspended tenant', () => {
    const raw = {
      id: 'child-1',
      name: 'child-1',
      parent_id: 'client-1',
      status: 'suspended',
      directly_suspended: false,
      cascade_suspended_from: 'client-1',
      created_at: '',
      updated_at: '',
    }
    const result = parseTenantInfo(raw)
    expect(result?.status).toBe('suspended')
    expect(result?.directly_suspended).toBe(false)
    expect(result?.cascade_suspended_from).toBe('client-1')
  })

  it('parses a tenant with both direct and cascade suspension', () => {
    const raw = {
      id: 'client-2',
      name: 'client-2',
      parent_id: 'msp-a',
      status: 'suspended',
      directly_suspended: true,
      cascade_suspended_from: 'msp-a',
      created_at: '',
      updated_at: '',
    }
    const result = parseTenantInfo(raw)
    expect(result?.directly_suspended).toBe(true)
    expect(result?.cascade_suspended_from).toBe('msp-a')
  })

  it('returns null for missing id', () => {
    expect(parseTenantInfo({ name: 'no-id', status: 'active' })).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parseTenantInfo(null)).toBeNull()
    expect(parseTenantInfo('string')).toBeNull()
    expect(parseTenantInfo(42)).toBeNull()
  })

  it('coerces missing optional fields to safe defaults', () => {
    const result = parseTenantInfo({ id: 'x' })
    expect(result?.name).toBe('')
    expect(result?.description).toBe('')
    expect(result?.parent_id).toBe('')
    expect(result?.status).toBe('active')
    expect(result?.directly_suspended).toBe(false)
    expect(result?.cascade_suspended_from).toBeNull()
  })

  it('defaults unknown status to active', () => {
    const result = parseTenantInfo({ id: 'x', status: 'unknown-value' })
    expect(result?.status).toBe('active')
  })

  it('parses deleted status', () => {
    const result = parseTenantInfo({ id: 'x', status: 'deleted' })
    expect(result?.status).toBe('deleted')
  })
})

// ── parseTenantList ────────────────────────────────────────────────────────────

describe('parseTenantList', () => {
  it('parses an array of valid tenants', () => {
    const list = parseTenantList([
      { id: 'root', name: 'root', status: 'active' },
      { id: 'msp-a', name: 'msp-a', parent_id: 'root', status: 'active' },
    ])
    expect(list).toHaveLength(2)
    expect(list[0]!.id).toBe('root')
    expect(list[1]!.id).toBe('msp-a')
  })

  it('skips invalid entries', () => {
    const list = parseTenantList([
      { id: 'valid', name: 'v', status: 'active' },
      null,
      { name: 'no-id' },
      'string',
    ])
    expect(list).toHaveLength(1)
    expect(list[0]!.id).toBe('valid')
  })

  it('throws for non-array input', () => {
    expect(() => parseTenantList(null)).toThrow('unexpected response shape')
    expect(() => parseTenantList({ id: 'x' })).toThrow('unexpected response shape')
  })

  it('returns empty array for empty list', () => {
    expect(parseTenantList([])).toEqual([])
  })
})

// ── parsePendingDeletion ──────────────────────────────────────────────────────

describe('parsePendingDeletion', () => {
  it('parses a hold-state pending deletion', () => {
    const raw = {
      subtree_root_id: 'client-4',
      requested_by: 'msp-a-ops',
      requested_at: '2026-07-24T00:00:00Z',
      eligible_at: '2026-08-24T00:00:00Z',
      state: 'hold',
      pinned_member_ids: ['client-4', 'child-a'],
    }
    const result = parsePendingDeletion(raw)
    expect(result).not.toBeNull()
    expect(result?.subtree_root_id).toBe('client-4')
    expect(result?.state).toBe('hold')
    expect(result?.requested_by).toBe('msp-a-ops')
    expect(result?.pinned_member_ids).toEqual(['client-4', 'child-a'])
  })

  it('parses an eligible-state pending deletion', () => {
    const raw = {
      subtree_root_id: 'client-5',
      requested_by: 'msp-a-owner',
      requested_at: '2026-06-28T00:00:00Z',
      eligible_at: '2026-07-28T00:00:00Z',
      state: 'eligible',
      pinned_member_ids: ['client-5'],
    }
    const result = parsePendingDeletion(raw)
    expect(result?.state).toBe('eligible')
  })

  it('returns null for unknown state', () => {
    const raw = {
      subtree_root_id: 'x',
      state: 'unknown',
    }
    expect(parsePendingDeletion(raw)).toBeNull()
  })

  it('returns null for missing subtree_root_id', () => {
    expect(parsePendingDeletion({ state: 'hold' })).toBeNull()
  })

  it('returns null for non-object input', () => {
    expect(parsePendingDeletion(null)).toBeNull()
    expect(parsePendingDeletion('string')).toBeNull()
  })
})

// ── suspendTenant ──────────────────────────────────────────────────────────────

describe('suspendTenant', () => {
  it('calls POST /api/v1/tenants/{id}/suspend and returns result', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        data: {
          target: 'client-1',
          newly_cascade_suspended: ['child-a', 'child-b'],
          already_suspended: [],
        },
      }),
    )
    const result = await suspendTenant('client-1')
    expect(result.target).toBe('client-1')
    expect(result.newly_cascade_suspended).toEqual(['child-a', 'child-b'])
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-1/suspend'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('throws on non-ok response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, { error: { message: 'cannot suspend default tenant' } }),
    )
    await expect(suspendTenant('default')).rejects.toThrow('cannot suspend default tenant')
  })
})

// ── restoreTenant ─────────────────────────────────────────────────────────────

describe('restoreTenant', () => {
  it('calls POST /api/v1/tenants/{id}/restore and returns result', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        data: {
          target: 'client-2',
          restored: ['child-a'],
          still_suspended: ['child-b'],
        },
      }),
    )
    const result = await restoreTenant('client-2')
    expect(result.target).toBe('client-2')
    expect(result.restored).toEqual(['child-a'])
    expect(result.still_suspended).toEqual(['child-b'])
  })

  it('throws on non-ok response with server error message', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(500, { error: { message: 'restore failed' } }),
    )
    await expect(restoreTenant('client-1')).rejects.toThrow('restore failed')
  })
})

// ── createTenant ───────────────────────────────────────────────────────────────

describe('createTenant', () => {
  it('calls POST /api/v1/tenants with name and parent_id', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(201, {
        data: { id: 'new-client', name: 'new-client', parent_id: 'msp-a', status: 'active' },
      }),
    )
    const result = await createTenant({ name: 'new-client', parent_id: 'msp-a' })
    expect(result.id).toBe('new-client')
    expect(result.name).toBe('new-client')
    const [, init] = fetchMock.mock.calls[0]!
    const body = JSON.parse((init as RequestInit).body as string) as Record<string, unknown>
    expect(body.name).toBe('new-client')
    expect(body.parent_id).toBe('msp-a')
  })

  it('throws on non-ok response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(409, { error: { message: 'tenant already exists' } }),
    )
    await expect(createTenant({ name: 'dup' })).rejects.toThrow('tenant already exists')
  })

  it('throws on unexpected response shape', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, { data: null }))
    await expect(createTenant({ name: 'x' })).rejects.toThrow('Unexpected response shape')
  })
})

// ── updateTenant ───────────────────────────────────────────────────────────────

describe('updateTenant', () => {
  it('calls PUT /api/v1/tenants/{id} with updated fields', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        data: { id: 'client-1', name: 'client-1-renamed', status: 'active' },
      }),
    )
    const result = await updateTenant('client-1', { name: 'client-1-renamed', description: 'Updated desc' })
    expect(result.id).toBe('client-1')
    const [, init] = fetchMock.mock.calls[0]!
    const body = JSON.parse((init as RequestInit).body as string) as Record<string, unknown>
    expect(body.name).toBe('client-1-renamed')
    expect(body.description).toBe('Updated desc')
  })

  it('throws on non-ok response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(404, { error: { message: 'tenant not found' } }),
    )
    await expect(updateTenant('ghost', { name: 'x' })).rejects.toThrow('tenant not found')
  })
})

// ── requestTenantDeletion ─────────────────────────────────────────────────────

describe('requestTenantDeletion', () => {
  it('calls POST /api/v1/tenants/{id}/delete and returns pending deletion', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        data: {
          subtree_root_id: 'client-4',
          requested_by: 'ops-admin',
          requested_at: '2026-08-01T00:00:00Z',
          eligible_at: '2026-09-01T00:00:00Z',
          state: 'hold',
          pinned_member_ids: ['client-4'],
        },
      }),
    )
    const result = await requestTenantDeletion('client-4')
    expect(result.state).toBe('hold')
    expect(result.subtree_root_id).toBe('client-4')
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-4/delete'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('throws with server error message when subtree not fully suspended', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, {
        error: { message: 'subtree not fully suspended — tenant child-a is not suspended' },
      }),
    )
    await expect(requestTenantDeletion('client-3')).rejects.toThrow(
      'subtree not fully suspended',
    )
  })
})

// ── cancelTenantDeletion ──────────────────────────────────────────────────────

describe('cancelTenantDeletion', () => {
  it('calls DELETE /api/v1/tenants/{id}/delete', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { data: { cancelled: true } }))
    await cancelTenantDeletion('client-4')
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-4/delete'),
      expect.objectContaining({ method: 'DELETE' }),
    )
  })

  it('throws on non-ok response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(404, { error: { message: 'no pending deletion found' } }),
    )
    await expect(cancelTenantDeletion('x')).rejects.toThrow('no pending deletion found')
  })
})

// ── approveTenantDeletion ─────────────────────────────────────────────────────

describe('approveTenantDeletion', () => {
  it('calls POST /api/v1/tenants/{id}/delete/approve and returns deleted ids', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        data: { deleted_ids: ['client-5', 'child-a'] },
      }),
    )
    const result = await approveTenantDeletion('client-5')
    expect(result).toEqual(['client-5', 'child-a'])
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/tenants/client-5/delete/approve'),
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('throws with server message on dual-control violation', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(409, {
        error: { message: 'approver must differ from the principal who requested this deletion' },
      }),
    )
    await expect(approveTenantDeletion('client-5')).rejects.toThrow(
      'approver must differ from the principal who requested this deletion',
    )
  })

  it('surfaces the SAME_APPROVER code so callers can lock the action', async () => {
    // The browser never learns its own server-side principal ID, so this code is
    // the only in-domain signal that the operator is the original requester
    // (ADR-027 Decision 4) — it must survive the error path, not just the message.
    fetchMock.mockResolvedValueOnce(
      jsonResponse(403, {
        error: {
          code: 'SAME_APPROVER',
          message: 'approver must differ from the principal who requested this deletion',
        },
      }),
    )
    const cause = await approveTenantDeletion('client-5').catch((e: unknown) => e)
    expect(cause).toBeInstanceOf(TenantApiError)
    const err = cause as TenantApiError
    expect(err.code).toBe(errCodeSameApprover)
    expect(err.status).toBe(403)
    expect(err.message).toBe(
      'approver must differ from the principal who requested this deletion',
    )
  })

  it('leaves the code empty when the server sends no error envelope', async () => {
    fetchMock.mockResolvedValueOnce(new Response('not json', { status: 502 }))
    const cause = await approveTenantDeletion('client-5').catch((e: unknown) => e)
    expect(cause).toBeInstanceOf(TenantApiError)
    expect((cause as TenantApiError).code).toBe('')
    expect((cause as TenantApiError).message).toBe('Approve deletion failed — 502')
  })

  it('throws on non-ok response', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(409, { error: { message: 'hold period has not yet elapsed' } }),
    )
    await expect(approveTenantDeletion('client-4')).rejects.toThrow(
      'hold period has not yet elapsed',
    )
  })
})
