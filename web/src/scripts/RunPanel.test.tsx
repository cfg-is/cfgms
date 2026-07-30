// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RunPanel test suite (Issue #2988, AC: confirm-before-run gate).
 *
 * Key invariants tested:
 * 1. POST /api/v1/runs/script is never called without an explicit confirm step.
 * 2. The confirm dialog shows the resolved target count before committing [REQUIRED].
 * 3. Cancelling the confirm dialog prevents the POST.
 * 4. Confirming fires the POST with the correct body.
 * 5. Param inputs are rendered for scripts with parameters.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RunPanel from './RunPanel.tsx'
import type { ScriptMetadata } from './useScripts.ts'

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

function makeScript(overrides: Partial<ScriptMetadata> = {}): ScriptMetadata {
  return {
    id: 'script-1',
    name: 'Test Script',
    description: 'A test script',
    version: { major: 1, minor: 0, patch: 0, prerelease: '', build_meta: '' },
    author: 'test-author',
    tags: [],
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

function makeFleetResponse(total: number) {
  return new Response(
    JSON.stringify({
      data: { stewards: [], total, limit: 1, offset: 0 },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeRunScriptResponse(runId: string) {
  return new Response(
    JSON.stringify({ data: { run_id: runId }, timestamp: new Date().toISOString() }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeRunStatusResponse(runId: string, status: string) {
  return new Response(
    JSON.stringify({
      data: {
        run_id: runId,
        tenant_id: 'root',
        created_by: 'admin',
        created_at: new Date().toISOString(),
        status,
        script_ref: 'script-1',
        shell: 'bash',
        job_count: 1,
        completed_jobs: status === 'completed' ? 1 : 0,
        failed_jobs: 0,
      },
      timestamp: new Date().toISOString(),
    }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderRunPanel(script = makeScript(), onClose = vi.fn()) {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RunPanel script={script} onClose={onClose} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Resolve and confirm-before-run gate [REQUIRED] ────────────────────────────

describe('RunPanel — confirm-before-run gate [REQUIRED]', () => {
  it('shows the resolve button and disables Run script until count is resolved', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRunPanel()
    expect(screen.getByTestId('resolve-btn')).toBeInTheDocument()
    expect(screen.getByTestId('run-btn')).toBeDisabled()
  })

  it('shows the resolved target count after resolving', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(7))
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'name:web*' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('run-target-count')).toHaveTextContent('7 stewards match'),
    )
  })

  it('enables Run script only after resolve completes', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(3))
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'os:linux' },
    })
    expect(screen.getByTestId('run-btn')).toBeDisabled()

    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    expect(screen.getByTestId('run-btn')).not.toBeDisabled()
  })

  it('shows confirm dialog with resolved count when Run script is clicked [REQUIRED]', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(5))
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'tag:prod' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))

    // Confirm dialog must be visible
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    // The dialog must show the resolved target count
    expect(screen.getByTestId('run-confirm-count')).toHaveTextContent('5 stewards')
    // POST must NOT have been called yet at this point
    expect(fetchMock).toHaveBeenCalledTimes(1) // only the resolve fleet call
  })

  it('does NOT fire POST when the confirm dialog is cancelled', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(4))
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'name:api*' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    // Cancel the dialog — scope to the dialog to avoid matching the panel Cancel button
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /cancel/i }))

    // Dialog dismissed
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    // POST never called
    expect(fetchMock).toHaveBeenCalledTimes(1) // only the resolve call
  })

  it('fires POST to /api/v1/runs/script only after confirm click', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(2))
    fetchMock.mockResolvedValueOnce(makeRunScriptResponse('run-abc'))
    // Run status and jobs polls after POST
    fetchMock.mockResolvedValue(makeRunStatusResponse('run-abc', 'completed'))

    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'id:steward-1' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1) // only resolve, no POST yet

    fireEvent.click(screen.getByTestId('run-confirm-btn'))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))

    // Verify the POST call
    const postCall = fetchMock.mock.calls[1]!
    expect(postCall[0]).toBe('/api/v1/runs/script')
    const init = postCall[1]!
    expect(init.method).toBe('POST')
    const body = JSON.parse(init.body as string) as Record<string, unknown>
    expect(body.script_id).toBe('script-1')
    expect(body.target).toBe('id:steward-1')
  })

  it('posts correct params in request body', async () => {
    const scriptWithParams = makeScript({
      parameters: [
        { name: 'timeout', description: 'Timeout', type: 'int', required: true },
        { name: 'env', description: 'Environment', type: 'string', required: false },
      ],
    })

    fetchMock.mockResolvedValueOnce(makeFleetResponse(1))
    fetchMock.mockResolvedValueOnce(makeRunScriptResponse('run-xyz'))
    fetchMock.mockResolvedValue(makeRunStatusResponse('run-xyz', 'completed'))

    renderRunPanel(scriptWithParams)

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'name:api*' },
    })
    fireEvent.change(screen.getByRole('textbox', { name: /^timeout$/i }), {
      target: { value: '30' },
    })
    fireEvent.change(screen.getByRole('textbox', { name: /^env$/i }), {
      target: { value: 'production' },
    })

    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    fireEvent.click(screen.getByTestId('run-confirm-btn'))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))

    const postCall = fetchMock.mock.calls[1]!
    const body = JSON.parse((postCall[1] as RequestInit).body as string) as Record<string, unknown>
    expect(body.params).toEqual({ timeout: '30', env: 'production' })
  })

  it('clears resolved count when selector changes', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(5))
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'tag:prod' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    // Change the selector
    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'tag:staging' },
    })

    // Count should be cleared; Run script should be disabled again
    expect(screen.queryByTestId('run-target-count')).not.toBeInTheDocument()
    expect(screen.getByTestId('run-btn')).toBeDisabled()
  })

  it('shows singular "steward" when count is 1', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(1))
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'id:single-steward' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    expect(screen.getByTestId('run-confirm-count')).toHaveTextContent('1 steward will')
  })
})

// ── Structure ─────────────────────────────────────────────────────────────────

describe('RunPanel — structure', () => {
  it('renders the panel container', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRunPanel()
    expect(screen.getByTestId('run-panel')).toBeInTheDocument()
  })

  it('calls onClose when Cancel is clicked', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const onClose = vi.fn()
    renderRunPanel(makeScript(), onClose)
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders param inputs for scripts with parameters', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const scriptWithParams = makeScript({
      parameters: [
        { name: 'timeout', description: 'Timeout seconds', type: 'int', required: true },
        { name: 'env', description: 'Environment', type: 'string', required: false },
      ],
    })
    renderRunPanel(scriptWithParams)
    expect(screen.getByTestId('param-input-timeout')).toBeInTheDocument()
    expect(screen.getByTestId('param-input-env')).toBeInTheDocument()
  })

  it('does not render param inputs for scripts without parameters', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRunPanel(makeScript({ parameters: [] }))
    expect(screen.queryByTestId(/param-input-/)).not.toBeInTheDocument()
  })

  it('shows resolve error when fleet query fails', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({}), { status: 500 }),
    )
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'name:web*' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('run-resolve-error')).toBeInTheDocument(),
    )
    expect(screen.queryByTestId('run-target-count')).not.toBeInTheDocument()
  })

  it('shows run error when POST fails', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(3))
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'service unavailable' }), {
        status: 503,
      }),
    )
    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'name:web*' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    fireEvent.click(screen.getByTestId('run-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('run-error')).toBeInTheDocument(),
    )
  })

  it('shows run status after successful POST', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(2))
    fetchMock.mockResolvedValueOnce(makeRunScriptResponse('run-live'))
    fetchMock.mockResolvedValue(makeRunStatusResponse('run-live', 'running'))

    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'tag:prod' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    fireEvent.click(screen.getByTestId('run-confirm-btn'))

    await waitFor(() =>
      expect(screen.getByTestId('run-status')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('run-status')).toHaveTextContent('run-live')
  })

  it('shows run jobs table when jobs are returned', async () => {
    fetchMock.mockResolvedValueOnce(makeFleetResponse(1))
    fetchMock.mockResolvedValueOnce(makeRunScriptResponse('run-jobs'))
    // Run status response
    fetchMock.mockResolvedValueOnce(makeRunStatusResponse('run-jobs', 'running'))
    // Run jobs response
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          data: [
            {
              job_id: 'job-1',
              run_id: 'run-jobs',
              device_id: 'steward-1',
              execution_id: 'exec-1',
              status: 'completed',
              created_at: '2026-01-01T00:00:00Z',
              exit_code: 0,
            },
          ],
          timestamp: new Date().toISOString(),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )

    renderRunPanel()

    fireEvent.change(screen.getByRole('textbox', { name: /target selector/i }), {
      target: { value: 'tag:prod' },
    })
    fireEvent.click(screen.getByTestId('resolve-btn'))
    await waitFor(() => expect(screen.getByTestId('run-target-count')).toBeInTheDocument())

    fireEvent.click(screen.getByTestId('run-btn'))
    fireEvent.click(screen.getByTestId('run-confirm-btn'))

    await waitFor(() =>
      expect(screen.queryByTestId('run-jobs-table')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('run-job-row')).toBeInTheDocument()
  })
})
