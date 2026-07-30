// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AuthProvider, useAuth } from '../auth/AuthContext.tsx'
import UserMenu from './UserMenu.tsx'

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  document.documentElement.removeAttribute('data-theme')
  localStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
})

const MOCK_PASSKEY_BEGIN_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    timeout: 60000,
    rpId: 'localhost',
    allowCredentials: [],
    userVerification: 'required' as const,
  },
}

function makePublicKeyCredential(): PublicKeyCredential {
  const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
  return {
    id: 'cred-id',
    type: 'public-key',
    rawId: toArrayBuffer('cred-id'),
    response: {
      clientDataJSON: toArrayBuffer('{"type":"webauthn.get"}'),
      authenticatorData: toArrayBuffer('auth-data'),
      signature: toArrayBuffer('sig'),
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({} as AuthenticationExtensionsClientOutputs),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

// Drives a real sign-in through AuthProvider.login() — UserMenu has no
// login form of its own, so a principal only exists once something calls
// the provider's login() (same mechanism App.tsx's Login screen uses).
function SignedInHarness({ username }: { username: string }) {
  const { login } = useAuth()
  return (
    <>
      <button type="button" onClick={() => void login(username)}>
        drive-login
      </button>
      <UserMenu />
    </>
  )
}

async function signIn(username: string) {
  vi.stubGlobal('navigator', {
    credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) },
  })
  fetchMock.mockImplementation((input) => {
    const url = String(input)
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
      return Promise.resolve(jsonResponse(204))
    }
    if (url.endsWith('/api/v1/web/passkey/login/begin')) {
      return Promise.resolve(jsonResponse(200, MOCK_PASSKEY_BEGIN_OPTIONS))
    }
    if (url.endsWith('/api/v1/web/passkey/login/finish')) {
      return Promise.resolve(
        jsonResponse(200, {
          data: { ok: true, username, tenant_id: '', root_scope: false },
        }),
      )
    }
    return Promise.resolve(jsonResponse(200))
  })
  render(
    <AuthProvider>
      <SignedInHarness username={username} />
    </AuthProvider>,
  )
  fireEvent.click(screen.getByRole('button', { name: 'drive-login' }))
  await waitFor(() =>
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/web/passkey/login/finish',
      expect.objectContaining({ method: 'POST' }),
    ),
  )
}

describe('UserMenu', () => {
  it('shows initials derived from the signed-in principal', async () => {
    await signIn('admin@msp-a')
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /account menu/i })).toHaveTextContent('AD'),
    )
    fireEvent.click(screen.getByRole('button', { name: /account menu/i }))
    expect(screen.getByText('admin@msp-a')).toBeInTheDocument()
  })

  it('derives initials from a two-part local address (dot-separated)', async () => {
    await signIn('jane.doe@msp-a')
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /account menu/i })).toHaveTextContent('JD'),
    )
  })

  it('shows the fallback avatar when no principal is signed in', () => {
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    expect(screen.getByRole('button', { name: /account menu/i })).toHaveTextContent('?')
  })

  it('opens the menu and dispatches logout on click', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(204))
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    fireEvent.click(screen.getByRole('button', { name: /account menu/i }))
    const signOut = screen.getByRole('menuitem', { name: /sign out/i })
    fireEvent.click(signOut)
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/web/logout',
        expect.objectContaining({ method: 'POST' }),
      )
    })
  })

  it('toggles the theme attribute on the document root', () => {
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    fireEvent.click(screen.getByRole('button', { name: /account menu/i }))
    fireEvent.click(screen.getByRole('button', { name: /^dark$/i }))
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    fireEvent.click(screen.getByRole('button', { name: /^light$/i }))
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    fireEvent.click(screen.getByRole('button', { name: /^auto$/i }))
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
  })

  it('persists the theme choice to localStorage under the allowlisted key', () => {
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    fireEvent.click(screen.getByRole('button', { name: /account menu/i }))
    fireEvent.click(screen.getByRole('button', { name: /^dark$/i }))
    expect(localStorage.getItem('cfgms.theme')).toBe('dark')
  })

  it('restores the persisted theme choice on mount', () => {
    localStorage.setItem('cfgms.theme', 'dark')
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('ignores a corrupt stored theme value and falls back to auto', () => {
    localStorage.setItem('cfgms.theme', 'not-a-real-theme')
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
  })

  it('closes on Escape', () => {
    render(
      <AuthProvider>
        <UserMenu />
      </AuthProvider>,
    )
    fireEvent.click(screen.getByRole('button', { name: /account menu/i }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    act(() => {
      fireEvent.keyDown(document, { key: 'Escape' })
    })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
