// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RunsView test suite (Issue #2988).
 *
 * Covers: loading, error, empty, and table states for both the script-runs
 * section (GET /api/v1/runs) and the batch-jobs section (GET /api/v1/jobs).
 * Security A9.1: run IDs, script refs, job selectors, and status strings are
 * rendered as text nodes — never dangerouslySetInnerHTML.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RunsView from './RunsView.tsx'

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

function makeRunRecord(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    run_id: 'run-1',
    tenant_id: 'root',
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    status: 'completed',
    script_ref: 'patch-system',
    shell: 'bash',
    job_count: 3,
    completed_jobs: 3,
    failed_jobs: 0,
    ...overrides,
  }
}

function makeBatchJob(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'bjob-1',
    tenant_id: 'root',
    selector: 'name:web*',
    status: 'completed',
    targets: ['s-1', 's-2'],
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:01:00Z',
    initiated_by: 'admin',
    ...overrides,
  }
}

function makeRunsResponse(runs: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: runs, timestamp: new Date().toISOString() }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeJobsResponse(jobs: object[], status = 200) {
  return new Response(
    JSON.stringify({ data: jobs, timestamp: new Date().toISOString() }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderRunsView() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <RunsView />
      </AuthProvider>
    </MemoryRouter>,
  )
}

// ── Container ─────────────────────────────────────────────────────────────────

describe('RunsView — container', () => {
  it('renders the runs-view container', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRunsView()
    expect(screen.getByTestId('runs-view')).toBeInTheDocument()
  })

  it('shows both section headings', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    renderRunsView()
    expect(screen.getByRole('heading', { name: /script runs/i })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /batch jobs/i })).toBeInTheDocument()
  })
})

// ── Script runs section ───────────────────────────────────────────────────────

describe('RunsView — script runs section', () => {
  it('shows loading skeleton while runs are loading', () => {
    // Runs never resolves; jobs resolves immediately
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/runs')) return new Promise(() => {})
      return Promise.resolve(makeJobsResponse([]))
    })
    renderRunsView()
    expect(screen.getByTestId('runs-loading')).toBeInTheDocument()
  })

  it('shows error card when the runs API returns non-ok', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/jobs')) return Promise.resolve(makeJobsResponse([]))
      return Promise.resolve(makeRunsResponse([], 500))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /couldn't load runs/i })).toBeInTheDocument(),
    )
  })

  it('shows empty state when there are no script runs', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/jobs')) return Promise.resolve(makeJobsResponse([]))
      return Promise.resolve(makeRunsResponse([]))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByTestId('runs-empty')).toBeInTheDocument(),
    )
  })

  it('renders the runs table with run rows', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/jobs')) return Promise.resolve(makeJobsResponse([]))
      return Promise.resolve(makeRunsResponse([makeRunRecord()]))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByTestId('runs-table')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('run-row')).toBeInTheDocument()
  })

  it('renders run status as a text node (security A9.1)', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/jobs')) return Promise.resolve(makeJobsResponse([]))
      return Promise.resolve(
        makeRunsResponse([makeRunRecord({ run_id: 'run-xss', status: '<script>bad()</script>' })])
      )
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByTestId('run-row')).toBeInTheDocument(),
    )
    expect(document.querySelector('script[src]')).toBeNull()
    expect(screen.getByText('<script>bad()</script>')).toBeInTheDocument()
  })

  it('retries the runs fetch when the retry button is clicked', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/jobs')) return Promise.resolve(makeJobsResponse([]))
      return Promise.resolve(makeRunsResponse([], 503))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getAllByRole('button', { name: /retry/i })[0]).toBeInTheDocument(),
    )

    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/jobs')) return Promise.resolve(makeJobsResponse([]))
      return Promise.resolve(makeRunsResponse([makeRunRecord()]))
    })
    fireEvent.click(screen.getAllByRole('button', { name: /retry/i })[0]!)
    await waitFor(() =>
      expect(screen.getByTestId('runs-table')).toBeInTheDocument(),
    )
  })
})

// ── Batch jobs section ────────────────────────────────────────────────────────

describe('RunsView — batch jobs section', () => {
  it('shows loading skeleton while jobs are loading', () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/runs')) return Promise.resolve(makeRunsResponse([]))
      return new Promise(() => {})
    })
    renderRunsView()
    expect(screen.getByTestId('jobs-loading')).toBeInTheDocument()
  })

  it('shows error card when the jobs API returns non-ok', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/runs') && !input.toString().includes('/jobs'))
        return Promise.resolve(makeRunsResponse([]))
      return Promise.resolve(makeJobsResponse([], 500))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /couldn't load batch jobs/i })).toBeInTheDocument(),
    )
  })

  it('shows empty state when there are no batch jobs', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/runs') && !input.toString().includes('/jobs'))
        return Promise.resolve(makeRunsResponse([]))
      return Promise.resolve(makeJobsResponse([]))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByTestId('jobs-empty')).toBeInTheDocument(),
    )
  })

  it('renders the jobs table with job rows', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/runs') && !input.toString().includes('/jobs'))
        return Promise.resolve(makeRunsResponse([]))
      return Promise.resolve(makeJobsResponse([makeBatchJob()]))
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByTestId('jobs-table')).toBeInTheDocument(),
    )
    expect(screen.getByTestId('job-row')).toBeInTheDocument()
  })

  it('renders job selector as a text node (security A9.1)', async () => {
    fetchMock.mockImplementation((input) => {
      if (String(input).includes('/api/v1/runs') && !input.toString().includes('/jobs'))
        return Promise.resolve(makeRunsResponse([]))
      return Promise.resolve(
        makeJobsResponse([makeBatchJob({ selector: '<b>inject</b>' })])
      )
    })
    renderRunsView()
    await waitFor(() =>
      expect(screen.getByTestId('job-row')).toBeInTheDocument(),
    )
    expect(document.querySelector('b')).toBeNull()
    expect(screen.getByText('<b>inject</b>')).toBeInTheDocument()
  })
})
