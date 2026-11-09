// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * LibraryModePanel test suite (Issue #5856): the confirm step, the presence
 * flow of the mode change, the state refresh after it, and reuse for the
 * workflow library kind. Only the network boundary (fetch) is stubbed.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import LibraryModePanel from './LibraryModePanel.tsx'
import type { LibraryKind } from './useScriptApprovals.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

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

let mode: string
let puts: { url: string; token: string | null; body: unknown }[]

/** A library whose PUT demands a presence tap and whose GET reports the current mode. */
function serveLibrary() {
  puts = []
  fetchMock.mockImplementation((input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
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
    if (url.endsWith('/mode') && method === 'GET') {
      return Promise.resolve(json(200, envelope({ kind: 'script', mode })))
    }
    if (url.endsWith('/mode') && method === 'PUT') {
      const token = new Headers(init?.headers).get('X-Presence-Token')
      const body = JSON.parse(String(init?.body)) as { mode: string }
      puts.push({ url, token, body })
      if (['tap-token-1'].includes(token ?? '')) {
        mode = body.mode
        return Promise.resolve(json(200, envelope({ kind: 'script', mode })))
      }
      return Promise.resolve(
        json(
          401,
          { error: 'step_up_required', required_assurance: 'strong', presence_required: true },
          {
            'WWW-Authenticate':
              'CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="content-library:set-mode"',
          },
        ),
      )
    }
    return Promise.resolve(json(404, { error: 'unexpected request' }))
  })
}

function renderPanel(kind: LibraryKind = 'script', onChanged?: () => void) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <LibraryModePanel kind={kind} onChanged={onChanged} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

async function stageMode(target: 'signed' | 'approve' | 'comment') {
  await waitFor(() => expect(screen.getByTestId('library-mode-signed')).toBeInTheDocument())
  fireEvent.click(screen.getByTestId(`library-mode-${target}`))
}

describe('LibraryModePanel', () => {
  it('selects the current mode and offers no change until another is chosen', async () => {
    mode = 'approve'
    serveLibrary()
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('library-mode-approve')).toBeChecked())
    expect(screen.getByTestId('library-mode-signed')).not.toBeChecked()
    expect(screen.queryByTestId('library-mode-change-btn')).toBeNull()
  })

  it('sends nothing until the change is confirmed, and states the comment-mode consequence', async () => {
    mode = 'signed'
    serveLibrary()
    renderPanel()

    await stageMode('comment')
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))

    expect(screen.getByTestId('library-mode-confirm')).toBeInTheDocument()
    expect(screen.getByTestId('library-mode-consequence')).toHaveTextContent(
      /no signature and no approval/i,
    )
    expect(puts).toHaveLength(0)

    fireEvent.click(screen.getByTestId('library-mode-cancel-btn'))
    expect(screen.queryByTestId('library-mode-confirm')).toBeNull()
    expect(puts).toHaveLength(0)
  })

  it('requires the presence flow to change the mode, then refreshes the mode and tells the caller', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(credential) } })
    mode = 'signed'
    serveLibrary()
    const onChanged = vi.fn()
    renderPanel('script', onChanged)

    await stageMode('approve')
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))
    fireEvent.click(screen.getByTestId('library-mode-confirm-btn'))

    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    expect(puts).toHaveLength(1)
    expect(puts[0]!.token).toBeNull()
    expect(onChanged).not.toHaveBeenCalled()
    fireEvent.click(await screen.findByTestId('step-up-verify-btn'))

    await waitFor(() => expect(puts).toHaveLength(2))
    expect(puts[1]!.token).toBe('tap-token-1')
    expect(puts[1]!.url).toBe('/api/v1/automation/libraries/script/mode')
    expect(puts[1]!.body).toEqual({ mode: 'approve' })

    await waitFor(() => expect(screen.getByTestId('library-mode-changed')).toHaveTextContent('Approve'))
    expect(onChanged).toHaveBeenCalledTimes(1)
    // The state was refetched from the server, not assumed.
    await waitFor(() => expect(screen.getByTestId('library-mode-approve')).toBeChecked())
    const gets = fetchMock.mock.calls.filter(
      ([u, i]) => String(u).endsWith('/mode') && (i?.method ?? 'GET') === 'GET',
    )
    expect(gets.length).toBeGreaterThanOrEqual(2)
  })

  it('leaves the mode unchanged and the caller uninformed when the tap is cancelled', async () => {
    mode = 'signed'
    serveLibrary()
    const onChanged = vi.fn()
    renderPanel('script', onChanged)

    await stageMode('approve')
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))
    fireEvent.click(screen.getByTestId('library-mode-confirm-btn'))
    await waitFor(() => expect(screen.getByTestId('step-up-overlay')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('step-up-cancel-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('library-mode-error')).toHaveTextContent(/mode was not changed/i),
    )
    expect(puts).toHaveLength(1)
    expect(onChanged).not.toHaveBeenCalled()
    expect(mode).toBe('signed')
    expect(screen.queryByTestId('library-mode-changed')).toBeNull()
  })

  it('shows the server refusal verbatim', async () => {
    mode = 'signed'
    serveLibrary()
    const base = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation((input, init) =>
      String(input).endsWith('/mode') && init?.method === 'PUT'
        ? Promise.resolve(
            json(503, { error: { code: 'AUDIT_UNAVAILABLE', message: 'Audit trail unavailable; mode not changed' } }),
          )
        : base(input, init),
    )
    renderPanel()

    await stageMode('approve')
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))
    fireEvent.click(screen.getByTestId('library-mode-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('library-mode-error')).toHaveTextContent(
        'Audit trail unavailable; mode not changed',
      ),
    )
  })

  it('takes the library kind as a prop and uses it for the route and the wording', async () => {
    mode = 'signed'
    serveLibrary()
    renderPanel('workflow')

    await stageMode('approve')
    expect(screen.getByText('Approval mode of the workflow library')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('library-mode-change-btn'))
    expect(screen.getByTestId('library-mode-consequence')).toHaveTextContent(/workflow version/i)

    const modeGets = fetchMock.mock.calls.map(([u]) => String(u)).filter((u) => u.endsWith('/mode'))
    expect(modeGets).toContain('/api/v1/automation/libraries/workflow/mode')
    expect(modeGets).not.toContain('/api/v1/automation/libraries/script/mode')
  })

  it('shows a retry when the mode cannot be loaded and offers no radio', async () => {
    fetchMock.mockResolvedValue(json(500, { error: 'boom' }))
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('library-mode-load-error')).toBeInTheDocument())
    expect(screen.queryByTestId('library-mode-signed')).toBeNull()
  })

  it('refuses an unrecognised mode from the server rather than showing it as one of the three', async () => {
    fetchMock.mockResolvedValue(json(200, envelope({ kind: 'script', mode: 'anything-goes' })))
    renderPanel()

    await waitFor(() => expect(screen.getByTestId('library-mode-load-error')).toBeInTheDocument())
    expect(screen.queryByTestId('library-mode-signed')).toBeNull()
  })
})
