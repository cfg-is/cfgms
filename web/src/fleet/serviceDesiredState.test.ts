// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it } from 'vitest'
import { deriveDesiredServices, isDrifted } from './serviceDesiredState.ts'

// Shape of pkg/config EffectiveConfiguration with stewardconfig.StewardConfig.Resources.
const effective = (tenant: string) => ({
  steward_id: 'st-1',
  tenant_id: tenant,
  config: {
    resources: [
      { name: 'nginx', module: 'service', config: { state: 'running' } },
      { name: 'cron', module: 'service', config: { state: 'stopped' } },
      { name: '/etc/motd', module: 'file', config: { state: 'present' } },
    ],
  },
  sources: {},
  generated_at: '2026-07-20T10:00:00Z',
})

describe('deriveDesiredServices', () => {
  it('reads service resources only', () => {
    const d = deriveDesiredServices(effective('acme/client-1'))
    expect(d).not.toBeNull()
    expect([...d!.entries()]).toEqual([['nginx', 'running'], ['cron', 'stopped']])
  })

  it('unwraps a data envelope', () => {
    expect(deriveDesiredServices({ data: effective('acme') })?.get('nginx')).toBe('running')
  })

  it('returns null for the defaulted tenant and malformed payloads', () => {
    expect(deriveDesiredServices(effective('default'))).toBeNull()
    expect(deriveDesiredServices(effective(''))).toBeNull()
    expect(deriveDesiredServices(null)).toBeNull()
    expect(deriveDesiredServices({ tenant_id: 'acme', config: null })).toBeNull()
  })

  it('returns an empty map when no resources', () => {
    expect(deriveDesiredServices({ tenant_id: 'acme', config: {} })?.size).toBe(0)
  })
})

describe('isDrifted', () => {
  it('flags mismatches', () => {
    expect(isDrifted('running', 'stopped')).toBe(true)
    expect(isDrifted('running', 'failed')).toBe(true)
    expect(isDrifted('stopped', 'running')).toBe(true)
  })
  it('does not flag matches', () => {
    expect(isDrifted('running', 'Running')).toBe(false)
    expect(isDrifted('running', 'active')).toBe(false)
    expect(isDrifted('stopped', 'stopped')).toBe(false)
  })
})
