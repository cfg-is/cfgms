// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { parseRebootWindow, useRebootWindow } from './useRebootWindow.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const win = { tenant_id: 'root/msp-a', status: 'scheduled', next_occurrence_display: 'Sun 02:00' }

describe('useRebootWindow', () => {
  it('parses and rejects malformed payloads', () => {
    expect(parseRebootWindow(win)).toEqual(win)
    expect(parseRebootWindow({ status: 'unrestricted' })).toEqual({ status: 'unrestricted' })
    expect(parseRebootWindow({ status: 'other' })).toBeNull()
    expect(parseRebootWindow({ status: 'scheduled', next_occurrence: 5 })).toBeNull()
    expect(parseRebootWindow(null)).toBeNull()
  })

  it('save sends no step-up and no presence request', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: win }))
    const result = await useRebootWindow('tenants').save('root/msp-a', {
      schedule_yaml: 'days: [sun]',
      tenant_default_timezone: 'UTC',
    })
    expect(result.status).toBe('scheduled')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/tenants/root/msp-a/reboot-window')
    expect(init?.method).toBe('PUT')
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes('/api/v1/webauthn/presence/begin'))).toBe(false)
  })

  it('omits the timezone on the steward scope', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: { steward_id: 'stw-1', status: 'unrestricted' } }))
    await useRebootWindow('stewards').save('stw-1', { schedule_yaml: 'x', tenant_default_timezone: 'UTC' })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/stewards/stw-1/reboot-window')
    expect(JSON.parse(String(init?.body))).toEqual({ schedule_yaml: 'x' })
  })

  it('surfaces the server validation message verbatim', async () => {
    fetchMock.mockResolvedValueOnce(json(400, { error: { message: 'invalid schedule: bad day' } }))
    await expect(useRebootWindow('stewards').save('stw-1', { schedule_yaml: 'x' })).rejects.toThrow(
      'invalid schedule: bad day',
    )
  })

  it('gets the window', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { data: win }))
    await expect(useRebootWindow('tenants').get('root/msp-a')).resolves.toEqual(win)
    fetchMock.mockResolvedValueOnce(json(200, { data: { status: 'bogus' } }))
    await expect(useRebootWindow('tenants').get('root/msp-a')).rejects.toThrow('malformed')
  })
})
