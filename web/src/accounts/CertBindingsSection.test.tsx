// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import CertBindingsSection from './CertBindingsSection.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function binding(overrides: Partial<Record<string, unknown>> = {}) {
  return { serial: '3a:2f', fingerprint: 'sha256:abc', label: 'laptop', bound_at: '2026-01-01T00:00:00Z', ...overrides }
}

function json(status: number, body: unknown = {}) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))
}

function setup(list: object[] = [binding()]) {
  fetchMock.mockImplementation((_url, init) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    if (method === 'GET') return json(200, { data: list })
    return json(200, {})
  })
  return render(
    <MemoryRouter>
      <AuthProvider>
        <CertBindingsSection username="alice" />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function writes() {
  return fetchMock.mock.calls.filter(([, init]) => (init?.method ?? 'GET').toUpperCase() !== 'GET')
}

describe('CertBindingsSection', () => {
  it('lists bindings and shows an empty state', async () => {
    setup()
    await waitFor(() => expect(screen.getByTestId('cert-serial')).toHaveTextContent('3a:2f'))
    cleanup()
    setup([])
    await waitFor(() => expect(screen.getByTestId('cert-bindings-empty')).toBeInTheDocument())
  })

  it('binds a certificate and reloads the list', async () => {
    setup([])
    await waitFor(() => screen.getByTestId('cert-bindings-empty'))
    fireEvent.change(screen.getByTestId('cert-bind-serial-input'), { target: { value: 's9' } })
    fireEvent.change(screen.getByTestId('cert-bind-fingerprint-input'), { target: { value: 'f9' } })
    fireEvent.click(screen.getByTestId('cert-bind-btn'))
    await waitFor(() => expect(writes()).toHaveLength(1))
    expect(String(writes()[0]![0])).toBe('/api/v1/accounts/alice/certs/bind')
    expect(JSON.parse(String(writes()[0]![1]!.body))).toEqual({ serial: 's9', fingerprint: 'f9' })
  })

  it('revoke sends nothing until Confirm', async () => {
    setup()
    await waitFor(() => screen.getByTestId('cert-revoke-btn'))
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    expect(writes()).toHaveLength(0)
    fireEvent.click(screen.getByTestId('cert-cancel-btn'))
    expect(writes()).toHaveLength(0)
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    fireEvent.click(screen.getByTestId('cert-confirm-btn'))
    await waitFor(() => expect(writes()).toHaveLength(1))
    expect(String(writes()[0]![0])).toBe('/api/v1/accounts/alice/certs/revoke/3a%3A2f')
  })

  it('rotate needs the new serial, then posts it to the old serial path', async () => {
    setup()
    await waitFor(() => screen.getByTestId('cert-rotate-btn'))
    fireEvent.click(screen.getByTestId('cert-rotate-btn'))
    fireEvent.click(screen.getByTestId('cert-confirm-btn'))
    expect(screen.getByTestId('cert-action-error')).toHaveTextContent(/new certificate serial/i)
    expect(writes()).toHaveLength(0)
    fireEvent.change(screen.getByTestId('cert-rotate-serial-input'), { target: { value: 'new-1' } })
    fireEvent.click(screen.getByTestId('cert-confirm-btn'))
    await waitFor(() => expect(writes()).toHaveLength(1))
    expect(String(writes()[0]![0])).toBe('/api/v1/accounts/alice/certs/rotate/3a%3A2f')
    expect(JSON.parse(String(writes()[0]![1]!.body))).toEqual({ serial: 'new-1' })
  })

  it('shows a server refusal', async () => {
    fetchMock.mockImplementation((_u, init) =>
      (init?.method ?? 'GET') === 'GET'
        ? json(200, { data: [binding()] })
        : json(503, { error: { message: 'Certificate management unavailable' } }),
    )
    render(
      <MemoryRouter>
        <AuthProvider>
          <CertBindingsSection username="alice" />
        </AuthProvider>
      </MemoryRouter>,
    )
    await waitFor(() => screen.getByTestId('cert-revoke-btn'))
    fireEvent.click(screen.getByTestId('cert-revoke-btn'))
    fireEvent.click(screen.getByTestId('cert-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('cert-action-error')).toHaveTextContent('unavailable'))
  })
})
