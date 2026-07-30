// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { AuthProvider } from '../auth/AuthContext.tsx'
import Login from './Login.tsx'

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

// ── WebAuthn helpers ─────────────────────────────────────────────────────────

const MOCK_PASSKEY_BEGIN_OPTIONS = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVz',
    timeout: 60000,
    rpId: 'localhost',
    allowCredentials: [],
    userVerification: 'required' as const,
  },
}

function makePublicKeyCredential(id = 'cred-id'): PublicKeyCredential {
  const toArrayBuffer = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer
  return {
    id,
    type: 'public-key',
    rawId: toArrayBuffer(id),
    response: {
      clientDataJSON: toArrayBuffer('{"type":"webauthn.get"}'),
      authenticatorData: toArrayBuffer('authenticator-data'),
      signature: toArrayBuffer('signature'),
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({} as AuthenticationExtensionsClientOutputs),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  } as unknown as PublicKeyCredential
}

// ── Fetch mock helpers ───────────────────────────────────────────────────────

const fetchMock = vi.fn<typeof fetch>()

/**
 * Wire up the three passkey login endpoints. The navigator.credentials stub
 * must be set separately per test (or globally in beforeEach) because tests
 * that test the "invalid" path need credentials.get to fail.
 */
function mockPasskeyEndpoints(finishStatus: number, finishBody: unknown = {}) {
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
      return Promise.resolve(jsonResponse(finishStatus, finishBody))
    }
    return Promise.resolve(jsonResponse(200))
  })
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
  window.localStorage.clear()
  window.sessionStorage.clear()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function renderLogin() {
  return render(
    <AuthProvider>
      <Login />
    </AuthProvider>,
  )
}

describe('Login screen states (mockup: docs/design/mockups/login.html)', () => {
  it('signin: renders wordmark, lead copy, username field, remember checkbox, and sign-in button', () => {
    renderLogin()
    expect(screen.getByText('CFGMS')).toBeInTheDocument()
    expect(screen.getByText('Sign in to the controller')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /username/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in with a passkey/i })).toBeInTheDocument()
    // No password field.
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
    // No error/expired copy in the default state.
    expect(screen.queryByText(/no passkey matched/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument()
  })

  it('waiting: shows "Waiting for your passkey" while the ceremony is in progress', async () => {
    // credentials.get never resolves → keeps the component in the waiting state.
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn(() => new Promise(() => undefined)) },
    })
    mockPasskeyEndpoints(200)
    renderLogin()
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() =>
      expect(screen.getByText(/waiting for your passkey/i)).toBeInTheDocument(),
    )
    // Sign-in button is replaced by the waiting state.
    expect(screen.queryByRole('button', { name: /sign in with a passkey/i })).not.toBeInTheDocument()
    // Cancel button is available.
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  it('waiting: cancel returns to the sign-in form', async () => {
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn(() => new Promise(() => undefined)) },
    })
    mockPasskeyEndpoints(200)
    renderLogin()
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() => screen.getByRole('button', { name: /cancel/i }))
    act(() => screen.getByRole('button', { name: /cancel/i }).click())
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /sign in with a passkey/i })).toBeInTheDocument(),
    )
  })

  it('invalid: shows the no-passkey error copy when credentials.get() throws', async () => {
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(new DOMException('No passkey', 'NotAllowedError')),
      },
    })
    mockPasskeyEndpoints(200)
    renderLogin()
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() =>
      expect(screen.getByText(/no passkey matched/i)).toBeInTheDocument(),
    )
    // Username field is still visible and preserved.
    expect(screen.getByRole('textbox', { name: /username/i })).toBeInTheDocument()
  })

  it('invalid: shows error copy when the server rejects the assertion', async () => {
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) },
    })
    mockPasskeyEndpoints(400)
    renderLogin()
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() =>
      expect(screen.getByText(/no passkey matched/i)).toBeInTheDocument(),
    )
  })

  it('expired: shows the session-expired banner when auth state is expired', async () => {
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) },
    })
    mockPasskeyEndpoints(200, {
      data: { ok: true, username: 'admin@msp-a', tenant_id: '', root_scope: false },
    })
    renderLogin()
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))

    // Wait for login to complete.
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /sign in with a passkey/i })).not.toBeInTheDocument(),
    )
    // After login, the login screen is swapped out by RequireAuth. Trigger a
    // mid-session 401 to force the 'expired' state and re-render the login screen.
    fetchMock.mockResolvedValue(jsonResponse(401))
    const { apiFetch } = await import('../api/client.ts')
    await act(async () => {
      await apiFetch('/api/v1/stewards')
    })

    await waitFor(() =>
      expect(
        screen.getByText(/session expired\. sign in again with your passkey to continue\./i),
      ).toBeInTheDocument(),
    )
  })
})

describe('Remember Username (UI preference — not auth data)', () => {
  it('remembers the username in localStorage when checkbox is checked', async () => {
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(new DOMException('No passkey', 'NotAllowedError')),
      },
    })
    mockPasskeyEndpoints(200)
    renderLogin()
    fireEvent.change(screen.getByRole('textbox', { name: /username/i }), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() => screen.getByText(/no passkey matched/i))
    expect(window.localStorage.getItem('cfgms.login.username')).toBe('admin@msp-a')
  })

  it('loads the remembered username from localStorage on mount', () => {
    window.localStorage.setItem('cfgms.login.username', 'admin@msp-a')
    renderLogin()
    expect(screen.getByRole<HTMLInputElement>('textbox', { name: /username/i }).value).toBe('admin@msp-a')
  })

  it('clears localStorage for username when Remember Username is unchecked', async () => {
    window.localStorage.setItem('cfgms.login.username', 'admin@msp-a')
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(new DOMException('No passkey', 'NotAllowedError')),
      },
    })
    mockPasskeyEndpoints(200)
    renderLogin()
    // Uncheck "Remember Username".
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() => screen.getByText(/no passkey matched/i))
    expect(window.localStorage.getItem('cfgms.login.username')).toBeNull()
  })
})

describe('no auth data in web storage (security A7.2)', () => {
  it('never stores auth/session data in sessionStorage', async () => {
    vi.stubGlobal('navigator', {
      credentials: { get: vi.fn().mockResolvedValue(makePublicKeyCredential()) },
    })
    mockPasskeyEndpoints(200, {
      data: { ok: true, username: 'admin@msp-a', tenant_id: '', root_scope: false },
    })
    renderLogin()
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(window.sessionStorage.length).toBe(0)
  })

  it('only the username display-preference key is written to localStorage (not auth data)', async () => {
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn().mockRejectedValue(new DOMException('No passkey', 'NotAllowedError')),
      },
    })
    mockPasskeyEndpoints(200)
    renderLogin()
    fireEvent.change(screen.getByRole('textbox', { name: /username/i }), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in with a passkey/i }))
    await waitFor(() => screen.getByText(/no passkey matched/i))
    // Only the username prefill key should be present — no session/auth keys.
    expect(window.localStorage.length).toBe(1)
    expect(window.localStorage.getItem('cfgms.login.username')).toBe('admin@msp-a')
    expect(window.localStorage.getItem('cfgms_session')).toBeNull()
  })
})

describe('forbidden references in source (security A7.1 / A7.2)', () => {
  // Raw-import every source file at build time — no fs access needed.
  const sources = import.meta.glob('../**/*.{ts,tsx,css}', {
    query: '?raw',
    import: 'default',
    eager: true,
  }) as Record<string, string>
  const appSources = Object.entries(sources).filter(
    ([path]) => !/\.test\.(ts|tsx)$/.test(path) && !path.includes('/test/'),
  )

  it('no non-test source file references cfgms_session', () => {
    expect(appSources.length).toBeGreaterThan(0)
    const offenders = appSources
      .filter(([, content]) => content.includes('cfgms_session'))
      .map(([path]) => path)
    expect(offenders).toEqual([])
  })

  // A7.2 forbids AUTH data in web storage, not the storage API itself — a
  // non-auth UI preference (e.g. theme, remembered username) may legitimately
  // persist there. Rather than a keyword blocklist (bypassable by any key that
  // doesn't happen to match a listed word), this is a closed allowlist: every
  // localStorage/sessionStorage call site must use a literal string key that
  // exactly matches an explicit (file, key) pair below. Adding a new entry is a
  // deliberate, reviewable source change — nothing can add itself to this list.
  // A call whose key isn't a plain string literal (e.g. computed or a variable)
  // fails closed: it can't be checked against the allowlist, so it's a violation
  // regardless of intent.
  //
  // NEVER add an auth/session/principal/credential key here — that data must
  // stay in-memory only (React context), per A7.2.
  const STORAGE_ALLOWLIST: ReadonlyArray<{ path: string; key: string }> = [
    // Theme preference (Story #2496) — a UI display preference, not auth
    // data; persists across reloads so the sidebar/topbar don't reset to
    // "auto" every visit.
    { path: 'shell/UserMenu.tsx', key: 'cfgms.theme' },
    // Fleet column selection (Story #2497) — which device-DNA columns the
    // technician shows; a display preference, not auth data. Values read
    // back are shape-validated as untrusted input (columns.ts).
    { path: 'fleet/columns.ts', key: 'cfgms.fleet.columns' },
    // Saved fleet views (Story #2498) — named view configurations (filter,
    // sort, columns, page size), keyed per principal INSIDE the stored
    // record (the storage key itself stays literal). Display preference,
    // not auth data. Values read back are shape- and type-validated as
    // untrusted input (SavedViews.tsx, security A10.2).
    { path: 'fleet/SavedViews.tsx', key: 'cfgms.fleet.views' },
    // Login username prefill (Story #2993) — the optional username field
    // value for the "Remember Username" convenience feature. A username is
    // a public identifier, not a secret or auth credential (A7.2). Path
    // is relative to the test file (same directory), so the glob returns
    // "./Login.tsx" which ends with just "Login.tsx".
    { path: 'Login.tsx', key: 'cfgms.login.username' },
  ]

  it('no non-test source file uses localStorage/sessionStorage outside the explicit allowlist', () => {
    const offenders: string[] = []
    const anyCallPattern = /(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\(/g
    const literalCallPattern =
      /(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\(\s*(['"`])([^'"`]*)\3/g
    for (const [path, content] of appSources) {
      const anyCalls = content.match(anyCallPattern) ?? []
      if (anyCalls.length === 0) continue
      const literalCalls = [...content.matchAll(literalCallPattern)]
      if (literalCalls.length < anyCalls.length) {
        offenders.push(`${path}: storage call with a non-literal key (cannot verify against allowlist)`)
        continue
      }
      for (const match of literalCalls) {
        const key = match[4]
        const allowed = STORAGE_ALLOWLIST.some((entry) => path.endsWith(entry.path) && entry.key === key)
        if (!allowed) offenders.push(`${path}: unauthorized storage key "${key}"`)
      }
    }
    expect(offenders).toEqual([])
  })

  // Proves the allowlist mechanism is live: an allowlisted literal key is
  // accepted, an unauthorized literal key is rejected, and a non-literal
  // (computed) key is rejected even if its runtime value would be fine.
  // Uses synthetic source text so the test doesn't depend on any real
  // file's current content.
  it('the storage allowlist accepts only the exact allowlisted key', () => {
    const check = (path: string, content: string) => {
      const anyCallPattern = /(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\(/g
      const literalCallPattern =
        /(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\(\s*(['"`])([^'"`]*)\3/g
      const anyCalls = content.match(anyCallPattern) ?? []
      const literalCalls = [...content.matchAll(literalCallPattern)]
      if (literalCalls.length < anyCalls.length) return 'non-literal'
      for (const match of literalCalls) {
        const key = match[4]
        if (!STORAGE_ALLOWLIST.some((entry) => path.endsWith(entry.path) && entry.key === key)) {
          return 'unauthorized'
        }
      }
      return 'ok'
    }
    // The real, currently-allowlisted entry (Story #2496 theme toggle).
    expect(check('shell/UserMenu.tsx', "localStorage.setItem('cfgms.theme', mode)")).toBe('ok')
    // A different key on the same file is not automatically allowed.
    expect(check('shell/UserMenu.tsx', "localStorage.setItem('cfgms.session_hint', mode)")).toBe(
      'unauthorized',
    )
    // The login username prefill is allowed on Login.tsx.
    expect(
      check('pages/Login.tsx', "localStorage.setItem('cfgms.login.username', username)"),
    ).toBe('ok')
    // The same key on a different file is not allowed.
    expect(
      check('shell/UserMenu.tsx', "localStorage.setItem('cfgms.login.username', username)"),
    ).toBe('unauthorized')
    // A computed key is rejected even though it can't be inspected — fails
    // closed rather than trusting the call site.
    expect(check('shell/UserMenu.tsx', 'localStorage.setItem(dynamicKey, mode)')).toBe('non-literal')
  })
})
