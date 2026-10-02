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
