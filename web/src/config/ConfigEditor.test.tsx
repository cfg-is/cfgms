// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ConfigEditor test suite (Story #2730): per-steward config view/edit/validate,
 * effective-config reachability, and delete confirm-step gating.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ConfigEditor from './ConfigEditor.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function makeConfigEnvelope(config: object, stewardId = 'sw-1') {
  return new Response(
    JSON.stringify({
      data: {
        steward_id: stewardId,
        version: '3',
        config,
        updated_at: '2026-01-01T00:00:00Z',
      },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeValidateResponse(valid: boolean, errors: object[] = []) {
  return new Response(
    JSON.stringify({
      data: { valid, errors, metadata: {} },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeEffectiveResponse(effective: object) {
  return new Response(
    JSON.stringify({
      data: effective,
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makePointsResponse() {
  return new Response(
    JSON.stringify({ rollback_points: [] }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderEditor(stewardId = 'sw-1', onClose = vi.fn()) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ConfigEditor stewardId={stewardId} onClose={onClose} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('ConfigEditor — rendering', () => {
  it('shows loading state while config is fetched', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderEditor()
    expect(screen.getByTestId('editor-loading')).toBeInTheDocument()
  })

  it('shows config content after loading', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({ resources: [] }))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())
    expect(screen.getByTestId('editor-config-pre')).toHaveTextContent('resources')
  })

  it('shows an error when config fetch fails', async () => {
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 500, headers: { 'Content-Type': 'application/json' } }),
    )
    renderEditor()
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('renders tabs: Config, Effective, Rollback', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({}))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: /^config$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /effective/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /rollback/i })).toBeInTheDocument()
  })

  it('shows the steward id in the header', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({}, 'my-steward'))
    renderEditor('my-steward')
    await waitFor(() => expect(screen.getByText('my-steward')).toBeInTheDocument())
  })

  it('calls onClose when the close button is clicked', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({}))
    const onClose = vi.fn()
    renderEditor('sw-1', onClose)
    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /close config editor/i }))
    expect(onClose).toHaveBeenCalled()
  })
})

describe('ConfigEditor — edit/save', () => {
  it('switches to textarea on Edit click', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({ resources: [] }))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-edit-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-edit-btn'))
    expect(screen.getByTestId('editor-textarea')).toBeInTheDocument()
  })

  it('cancel edit returns to read view', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({ resources: [] }))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-edit-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-edit-btn'))
    expect(screen.getByTestId('editor-textarea')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByTestId('editor-textarea')).toBeNull()
    expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument()
  })

  it('shows save error when PUT returns non-ok', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({ resources: [] }))
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'validation failed' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-edit-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-edit-btn'))
    fireEvent.click(screen.getByTestId('editor-save-btn'))
    await waitFor(() => expect(screen.getByTestId('editor-save-error')).toBeInTheDocument())
  })
})

describe('ConfigEditor — validate', () => {
  it('shows valid result after validate click', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({ resources: [] }))
    fetchMock.mockResolvedValue(makeValidateResponse(true))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-validate-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-validate-btn'))
    await waitFor(() =>
      expect(screen.getByTestId('editor-validation-result')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('editor-validation-result')).toHaveTextContent('valid')
  })

  it('shows validation errors when config is invalid', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({ resources: [] }))
    fetchMock.mockResolvedValue(
      makeValidateResponse(false, [{ field: 'resources', message: 'missing name', level: 'error', code: 'MISSING', suggestion: '' }]),
    )
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-validate-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-validate-btn'))
    await waitFor(() => expect(screen.getByTestId('editor-validation-result')).toBeInTheDocument())
    expect(screen.getByTestId('editor-validation-result')).toHaveTextContent('missing name')
  })
})

describe('ConfigEditor — effective config', () => {
  it('shows effective config when Effective tab is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({ resources: [] }))
    fetchMock.mockResolvedValue(makeEffectiveResponse({ effective: true }))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /effective/i }))
    await waitFor(() => expect(screen.getByTestId('editor-effective-pre')).toBeInTheDocument())
    expect(screen.getByTestId('editor-effective-pre')).toHaveTextContent('effective')
  })

  it('shows error when effective config fetch fails', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({ resources: [] }))
    fetchMock.mockResolvedValue(
      new Response('{}', { status: 404, headers: { 'Content-Type': 'application/json' } }),
    )
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /effective/i }))
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
  })
})

describe('ConfigEditor — delete confirm-step', () => {
  it('shows confirm dialog on Delete click', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({}))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-delete-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-delete-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('does NOT fire DELETE without confirming', async () => {
    fetchMock.mockResolvedValue(makeConfigEnvelope({}))
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-delete-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-delete-btn'))

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByRole('dialog')).toBeNull()

    const deleteCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === 'DELETE',
    )
    expect(deleteCalls).toHaveLength(0)
  })

  it('fires DELETE and closes editor after confirmation', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({}))
    // 204 is invalid in jsdom — use 200 (handler accepts both ok responses)
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    const onClose = vi.fn()
    renderEditor('sw-1', onClose)
    await waitFor(() => expect(screen.getByTestId('editor-delete-btn')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('editor-delete-btn'))
    fireEvent.click(screen.getByTestId('editor-confirm-delete-btn'))
    await waitFor(() => expect(onClose).toHaveBeenCalled())
  })
})

describe('ConfigEditor — rollback tab', () => {
  it('shows rollback panel when Rollback tab is clicked', async () => {
    fetchMock.mockResolvedValueOnce(makeConfigEnvelope({}))
    fetchMock.mockResolvedValue(makePointsResponse())
    renderEditor()
    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /rollback/i }))
    await waitFor(() => expect(screen.getByTestId('rollback-panel')).toBeInTheDocument())
  })
})

describe('ConfigEditor — create mode (no existing config)', () => {
  function make404Response() {
    return new Response('{}', { status: 404, headers: { 'Content-Type': 'application/json' } })
  }

  it('shows empty editor textarea when GET returns 404', async () => {
    fetchMock.mockResolvedValue(make404Response())
    renderEditor('sw-new')
    await waitFor(() => expect(screen.getByTestId('editor-textarea')).toBeInTheDocument())
    expect((screen.getByTestId('editor-textarea') as HTMLTextAreaElement).value).toBe('')
  })

  it('does not show an error notice when GET returns 404', async () => {
    fetchMock.mockResolvedValue(make404Response())
    renderEditor('sw-new')
    await waitFor(() => expect(screen.getByTestId('editor-textarea')).toBeInTheDocument())
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('save PUTs the entered config and then shows the saved config', async () => {
    fetchMock.mockResolvedValueOnce(make404Response())
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    fetchMock.mockResolvedValue(makeConfigEnvelope({ resources: [] }, 'sw-new'))

    renderEditor('sw-new')
    await waitFor(() => expect(screen.getByTestId('editor-textarea')).toBeInTheDocument())

    fireEvent.change(screen.getByTestId('editor-textarea'), {
      target: { value: '{"resources":[]}' },
    })
    fireEvent.click(screen.getByTestId('editor-save-btn'))

    await waitFor(() => expect(screen.getByTestId('editor-config-pre')).toBeInTheDocument())

    const putCalls = fetchMock.mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === 'PUT',
    )
    expect(putCalls).toHaveLength(1)
  })

  it('cancel in create mode calls onClose', async () => {
    fetchMock.mockResolvedValue(make404Response())
    const onClose = vi.fn()
    renderEditor('sw-new', onClose)
    await waitFor(() => expect(screen.getByTestId('editor-textarea')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(onClose).toHaveBeenCalled()
  })
})
