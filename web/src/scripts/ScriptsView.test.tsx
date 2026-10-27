// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ScriptsView test suite (Issue #2988).
 *
 * Covers: loading, error, empty, and populated table states; row selection
 * opens RunPanel and deselects on second click; history toggle mounts
 * RunsView; script count label; Security A9.1 (no dangerouslySetInnerHTML).
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ScriptsView from './ScriptsView.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeScript(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'script-1',
    name: 'Patch System',
    description: 'Apply OS patches',
    version: { major: 1, minor: 2, patch: 0, prerelease: '', build_meta: '' },
    author: 'test-author',
    tags: ['patch'],
    category: 'maintenance',
    platform: ['linux'],
    shell: 'bash',
    parameters: [],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    idempotent: true,
    ...overrides,
  }
}

function makeScriptListResponse(scripts: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: scripts, timestamp: new Date().toISOString() }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeRunListResponse(status = 200) {
  return new Response(
    JSON.stringify({ data: [], timestamp: new Date().toISOString() }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderScriptsView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ScriptsView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Data states ───────────────────────────────────────────────────────────────

describe('ScriptsView — data states', () => {
  it('shows loading skeleton before the response arrives', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderScriptsView()
    expect(screen.getByTestId('scripts-loading')).toBeInTheDocument()
  })

  it('shows error card when the API returns a non-ok status', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([], 503))
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /couldn't load scripts/i })).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('scripts-loading')).not.toBeInTheDocument()
  })

  it('shows empty state when the library is empty', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([]))
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('scripts-empty')).toBeInTheDocument(),
    )
  })

  it('shows the scripts table when scripts are returned', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([makeScript()]))
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('scripts-table')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('script-row')).toBeInTheDocument()
  })

  it('renders the script name as a text node (security A9.1)', async () => {
    fetchMock.mockResolvedValue(
      makeScriptListResponse([makeScript({ name: '<script>alert(1)</script>' })]),
    )
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('script-row')).toBeInTheDocument(),
    )
    // Must appear as escaped text, not injected HTML
    expect(document.querySelector('script[src]')).toBeNull()
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
  })

  it('shows the script count label after loading', async () => {
    fetchMock.mockResolvedValue(
      makeScriptListResponse([makeScript(), makeScript({ id: 'script-2', name: 'Script 2' })]),
    )
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('script-count')).toHaveTextContent('2 scripts'),
    )
  })

  it('shows singular "script" when there is exactly one', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([makeScript()]))
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('script-count')).toHaveTextContent('1 script'),
    )
  })

  it('retries the list fetch when the error card retry button is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeScriptListResponse([], 500))
    fetchMock.mockResolvedValueOnce(makeScriptListResponse([makeScript()]))
    renderScriptsView()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() =>
      expect(screen.getByTestId('scripts-table')).toBeInTheDocument(),
    )
  })
})

// ── Row selection → RunPanel ──────────────────────────────────────────────────

describe('ScriptsView — row selection and RunPanel', () => {
  it('opens RunPanel when a script row is clicked', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([makeScript()]))
    renderScriptsView()

    await waitFor(() =>
      expect(screen.getByTestId('script-row')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('script-row'))

    expect(screen.getByTestId('run-panel')).toBeInTheDocument()
  })

  it('closes RunPanel when the same row is clicked again', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([makeScript()]))
    renderScriptsView()

    await waitFor(() =>
      expect(screen.getByTestId('script-row')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('script-row'))
    expect(screen.getByTestId('run-panel')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('script-row'))
    expect(screen.queryByTestId('run-panel')).not.toBeInTheDocument()
  })

  it('closes RunPanel when its Cancel button is clicked', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([makeScript()]))
    renderScriptsView()

    await waitFor(() =>
      expect(screen.getByTestId('script-row')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('script-row'))
    expect(screen.getByTestId('run-panel')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('run-panel')).not.toBeInTheDocument()
  })
})

// ── History toggle ────────────────────────────────────────────────────────────

describe('ScriptsView — history toggle', () => {
  it('shows the history toggle button', async () => {
    fetchMock.mockResolvedValue(makeScriptListResponse([]))
    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('toggle-history-btn')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('toggle-history-btn')).toHaveTextContent('Run history')
  })

  it('clicking the history button shows RunsView', async () => {
    // Resolve scripts list, then handle runs and jobs endpoints
    fetchMock.mockResolvedValueOnce(makeScriptListResponse([makeScript()]))
    fetchMock.mockResolvedValue(makeRunListResponse())

    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('toggle-history-btn')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-history-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('runs-view')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('toggle-history-btn')).toHaveTextContent('Close history')
  })

  it('clicking the history button again hides RunsView', async () => {
    fetchMock.mockResolvedValueOnce(makeScriptListResponse([]))
    fetchMock.mockResolvedValue(makeRunListResponse())

    renderScriptsView()
    await waitFor(() =>
      expect(screen.getByTestId('toggle-history-btn')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-history-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('runs-view')).toBeInTheDocument(),
    )
    fireEvent.click(screen.getByTestId('toggle-history-btn'))
    expect(screen.queryByTestId('runs-view')).not.toBeInTheDocument()
  })
})

// ── Privilege editing (Issue #5447) ──────────────────────────────────────────

describe('ScriptsView privilege', () => {
  const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json', ...headers },
    })
  const envelope = (data: unknown) => ({ data, timestamp: new Date().toISOString() })

  const credential = {
    id: 'cred-id',
    type: 'public-key',
    rawId: new TextEncoder().encode('cred-id').buffer,
    response: {
      clientDataJSON: new TextEncoder().encode('{"type":"webauthn.get"}').buffer,
      authenticatorData: new TextEncoder().encode('authenticator-data').buffer,
      signature: new TextEncoder().encode('signature').buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({}),
    authenticatorAttachment: null,
    toJSON: () => ({}),
  }

  let puts: { token: string | null; body: unknown }[]

  function installRoutes() {
    puts = []
    fetchMock.mockImplementation((input, init) => {
      const url = String(input)
      if (url === '/api/v1/scripts') {
        return Promise.resolve(
          makeScriptListResponse([
            makeScript({
              parameters: [{ name: 'target', description: '', type: 'string', required: false }],
            }),
          ]),
        )
      }
      if (url.includes('presence/begin')) {
        return Promise.resolve(
          json(
            200,
            envelope({
              publicKey: {
                challenge: 'Y2hhbGxlbmdl',
                timeout: 60000,
                rpId: 'localhost',
                allowCredentials: [{ type: 'public-key', id: 'Y3JlZA', transports: ['internal'] }],
                userVerification: 'required',
              },
            }),
          ),
        )
      }
      if (url.includes('presence/finish')) {
        return Promise.resolve(json(200, envelope({ presence_token: 'tap-token-1', expires_in: 30 })))
      }
      if (url === '/api/v1/scripts/script-1/privilege') {
        const token = new Headers(init?.headers).get('X-Presence-Token')
        puts.push({ token, body: JSON.parse(String(init?.body)) })
        if (['tap-token-1'].includes(token ?? '')) return Promise.resolve(json(200, envelope({})))
        return Promise.resolve(
          json(
            401,
            { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
            {
              'WWW-Authenticate':
                'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="script:admin"',
            },
          ),
        )
      }
      return Promise.resolve(makeRunListResponse())
    })
  }

  async function fillAndSave() {
    renderScriptsView()
    await waitFor(() => expect(screen.getByTestId('script-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('script-row'))
    fireEvent.change(screen.getByLabelText(/required api scopes/i), {
      target: { value: 'steward:read-dna\n\n  script:admin  \n' },
    })
    fireEvent.click(screen.getByTestId('privilege-add-binding-btn'))
    fireEvent.change(screen.getByLabelText('Binding parameter 1'), { target: { value: 'target' } })
    fireEvent.change(screen.getByLabelText('Binding platform 1'), { target: { value: 'linux' } })
    fireEvent.click(screen.getByTestId('privilege-save-btn'))
  }

  it('privilege save sends X-Presence-Token after the tap', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    installRoutes()
    await fillAndSave()

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(puts).toHaveLength(1)
    await waitFor(() => screen.getByTestId('step-up-verify-btn'))
    fireEvent.click(screen.getByTestId('step-up-verify-btn'))

    await waitFor(() => expect(puts).toHaveLength(2))
    expect(puts[1]!.token).toBe('tap-token-1')
    expect(puts[1]!.body).toEqual({
      required_api_scope: ['steward:read-dna', 'script:admin'],
      param_platform_bindings: { target: 'linux' },
    })
    await waitFor(() => expect(screen.getByTestId('privilege-saved')).toBeInTheDocument())
  })

  it('privilege cancelled tap sends no second request', async () => {
    installRoutes()
    await fillAndSave()

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('privilege-error')).toHaveTextContent(/nothing was saved/i),
    )
    expect(puts).toHaveLength(1)
  })

  it('shows the server error verbatim for bad values', async () => {
    installRoutes()
    fetchMock.mockImplementation((input) => {
      const url = String(input)
      if (url === '/api/v1/scripts') return Promise.resolve(makeScriptListResponse([makeScript()]))
      if (url.endsWith('/privilege')) {
        return Promise.resolve(
          json(400, { error: { code: 'INVALID_REQUEST', message: 'unknown platform "amiga"' } }),
        )
      }
      return Promise.resolve(makeRunListResponse())
    })
    renderScriptsView()
    await waitFor(() => expect(screen.getByTestId('script-row')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('script-row'))
    fireEvent.click(screen.getByTestId('privilege-save-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('privilege-error')).toHaveTextContent('unknown platform "amiga"'),
    )
  })
})
