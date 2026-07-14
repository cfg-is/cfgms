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

const fetchMock = vi.fn<typeof fetch>()

function mockLoginEndpoints(loginStatus: number, delayMs = 0) {
  fetchMock.mockImplementation((input) => {
    const url = String(input)
    if (url.endsWith('/api/v1/web/csrf')) {
      document.cookie = 'cfgms_csrf_pre=pre-tok; path=/'
      return Promise.resolve(jsonResponse(204))
    }
    if (url.endsWith('/api/v1/web/login')) {
      if (delayMs > 0) {
        return new Promise((resolve) =>
          setTimeout(() => resolve(jsonResponse(loginStatus)), delayMs),
        )
      }
      return Promise.resolve(jsonResponse(loginStatus))
    }
    return Promise.resolve(jsonResponse(200))
  })
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
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
  it('signin: renders wordmark, lead copy, fields, and the sign-in button', () => {
    renderLogin()
    expect(screen.getByText('CFGMS')).toBeInTheDocument()
    expect(screen.getByText('Sign in to the controller')).toBeInTheDocument()
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    // No error/expired copy in the default state.
    expect(
      screen.queryByText('Invalid username or password.'),
    ).not.toBeInTheDocument()
    expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument()
  })

  it('loading: disables the button while the login request is in flight', async () => {
    mockLoginEndpoints(200, 50)
    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(screen.getByRole('button', { name: /sign in/i })).toBeDisabled()
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /sign in/i }),
      ).toBeEnabled(),
    )
  })

  it('invalid: shows the mockup error copy and preserves the username field', async () => {
    mockLoginEndpoints(401)
    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'wrong-password' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() =>
      expect(
        screen.getByText('Invalid username or password.'),
      ).toBeInTheDocument(),
    )
    expect(screen.getByLabelText(/username/i)).toHaveValue('admin@msp-a')
  })

  it('expired: shows the session-expired banner when auth state is expired', async () => {
    // Sign in, then 401 an API call to force the expired state.
    mockLoginEndpoints(200)
    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    fetchMock.mockResolvedValue(jsonResponse(401))
    const { apiFetch } = await import('../api/client.ts')
    await act(async () => {
      await apiFetch('/api/v1/stewards')
    })

    await waitFor(() =>
      expect(
        screen.getByText(/session expired\. sign in again to continue\./i),
      ).toBeInTheDocument(),
    )
  })
})

describe('no auth data in web storage (security A7.2)', () => {
  it('leaves localStorage and sessionStorage empty across a full login', async () => {
    mockLoginEndpoints(200)
    renderLogin()
    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin@msp-a' },
    })
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'pw-pw-pw-pw' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
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
  // non-auth UI preference (e.g. theme) may legitimately persist there.
  // Rather than a keyword blocklist (bypassable by any key that doesn't
  // happen to match a listed word), this is a closed allowlist: every
  // localStorage/sessionStorage call site must use a literal string key
  // that exactly matches an explicit (file, key) pair below. Adding a new
  // entry is a deliberate, reviewable source change — nothing can add
  // itself to this list. A call whose key isn't a plain string literal
  // (e.g. computed or a variable) fails closed: it can't be checked
  // against the allowlist, so it's a violation regardless of intent.
  //
  // NEVER add an auth/session/principal/credential key here — that data
  // must stay in-memory only (React context), per A7.2.
  const STORAGE_ALLOWLIST: ReadonlyArray<{ path: string; key: string }> = [
    // Theme preference (Story #2496) — a UI display preference, not auth
    // data; persists across reloads so the sidebar/topbar don't reset to
    // "auto" every visit.
    { path: 'shell/UserMenu.tsx', key: 'cfgms.theme' },
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
    // A computed key is rejected even though it can't be inspected — fails
    // closed rather than trusting the call site.
    expect(check('shell/UserMenu.tsx', 'localStorage.setItem(dynamicKey, mode)')).toBe('non-literal')
  })
})
