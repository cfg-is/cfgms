// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it } from 'vitest'
import {
  parseWebAccountInfo,
  parseWebAccountList,
  parseRoleInfo,
  parseRoleList,
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
