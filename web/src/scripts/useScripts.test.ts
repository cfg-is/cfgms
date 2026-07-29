// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * useScripts test suite (Issue #2988).
 *
 * Key invariants tested:
 *   - parseScriptMetadata coerces all fields correctly
 *   - parseRunRecord coerces all fields correctly
 *   - parseJobRecord coerces all fields correctly
 *   - parseBatchJob coerces all fields correctly
 *   - useScriptList fetches and parses the script library
 *   - useRunList fetches and parses the run list
 *   - useRunStatus polls GET /api/v1/runs/{id} until a terminal state [REQUIRED]
 *   - useJobList fetches and parses batch jobs
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import {
  parseScriptMetadata,
  parseScriptList,
  parseRunRecord,
  parseRunList,
  parseJobRecord,
  parseJobList,
  parseBatchJob,
  parseBatchJobList,
  useScriptList,
  useRunList,
  useRunStatus,
  useRunJobs,
  useJobList,
  RUN_POLL_INTERVAL,
  RUN_TERMINAL,
} from './useScripts.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  // Always restore real timers so fake-timer tests don't leak into subsequent ones
  vi.useRealTimers()
})

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeScript(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'script-1',
    name: 'Test Script',
    description: 'A test script',
    version: { major: 1, minor: 0, patch: 0, prerelease: '', build_meta: '' },
    author: 'test-author',
    tags: ['tag1'],
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

function makeRunRecord(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    run_id: 'run-1',
    tenant_id: 'root',
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    status: 'running',
    script_ref: 'script-1',
    shell: 'bash',
    job_count: 3,
    completed_jobs: 1,
    failed_jobs: 0,
    ...overrides,
  }
}

function makeJobRecord(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    job_id: 'job-1',
    run_id: 'run-1',
    device_id: 'steward-1',
    execution_id: 'exec-1',
    status: 'completed',
    created_at: '2026-01-01T00:00:00Z',
    completed_at: '2026-01-01T00:01:00Z',
    output: 'ok',
    stderr: '',
    exit_code: 0,
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

function makeSuccessResponse(data: unknown, status = 200) {
  return new Response(
    JSON.stringify({ data, timestamp: '2026-01-01T00:00:00Z' }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

// ── parseScriptMetadata ───────────────────────────────────────────────────────

describe('parseScriptMetadata', () => {
  it('parses a valid script', () => {
    const s = parseScriptMetadata(makeScript())
    expect(s).not.toBeNull()
    expect(s!.id).toBe('script-1')
    expect(s!.name).toBe('Test Script')
    expect(s!.description).toBe('A test script')
    expect(s!.version?.major).toBe(1)
    expect(s!.shell).toBe('bash')
    expect(s!.idempotent).toBe(true)
  })

  it('returns null for non-object input', () => {
    expect(parseScriptMetadata(null)).toBeNull()
    expect(parseScriptMetadata('string')).toBeNull()
    expect(parseScriptMetadata(42)).toBeNull()
  })

  it('returns null when id is missing', () => {
    expect(parseScriptMetadata({ name: 'no-id' })).toBeNull()
  })

  it('coerces non-string fields to defaults', () => {
    const s = parseScriptMetadata({ id: 'x', name: 42, description: null, shell: false })
    expect(s!.name).toBe('')
    expect(s!.description).toBe('')
    expect(s!.shell).toBe('')
  })

  it('handles missing version gracefully', () => {
    const s = parseScriptMetadata({ id: 'x' })
    expect(s!.version).toBeNull()
  })

  it('handles missing parameters gracefully', () => {
    const s = parseScriptMetadata({ id: 'x' })
    expect(s!.parameters).toEqual([])
  })

  it('parses parameters with required and optional fields', () => {
    const s = parseScriptMetadata(
      makeScript({
        parameters: [
          { name: 'timeout', description: 'Timeout seconds', type: 'int', required: true },
          { name: 'env', type: 'string', required: false },
          { description: 'no-name-param' }, // should be skipped
        ],
      }),
    )
    expect(s!.parameters).toHaveLength(2)
    expect(s!.parameters[0]!.name).toBe('timeout')
    expect(s!.parameters[0]!.required).toBe(true)
    expect(s!.parameters[1]!.name).toBe('env')
    expect(s!.parameters[1]!.required).toBe(false)
  })
})

// ── parseScriptList ───────────────────────────────────────────────────────────

describe('parseScriptList', () => {
  it('parses a valid array of scripts', () => {
    const result = parseScriptList([makeScript(), makeScript({ id: 'script-2', name: 'Script 2' })])
    expect(result).toHaveLength(2)
    expect(result[0]!.id).toBe('script-1')
    expect(result[1]!.id).toBe('script-2')
  })

  it('returns empty array for empty input', () => {
    expect(parseScriptList([])).toEqual([])
  })

  it('throws on non-array input', () => {
    expect(() => parseScriptList(null)).toThrow('unexpected response shape')
    expect(() => parseScriptList({ scripts: [] })).toThrow('unexpected response shape')
  })

  it('skips items without an id', () => {
    const result = parseScriptList([makeScript(), { name: 'no-id' }])
    expect(result).toHaveLength(1)
  })
})

// ── parseRunRecord ────────────────────────────────────────────────────────────

describe('parseRunRecord', () => {
  it('parses a valid run record', () => {
    const r = parseRunRecord(makeRunRecord())
    expect(r).not.toBeNull()
    expect(r!.run_id).toBe('run-1')
    expect(r!.status).toBe('running')
    expect(r!.job_count).toBe(3)
    expect(r!.completed_jobs).toBe(1)
    expect(r!.failed_jobs).toBe(0)
  })

  it('returns null for non-object input', () => {
    expect(parseRunRecord(null)).toBeNull()
    expect(parseRunRecord('string')).toBeNull()
  })

  it('returns null when run_id is missing', () => {
    expect(parseRunRecord({ status: 'running' })).toBeNull()
  })

  it('coerces non-number fields to zero', () => {
    const r = parseRunRecord({ run_id: 'r-1', job_count: 'not-a-num', completed_jobs: null })
    expect(r!.job_count).toBe(0)
    expect(r!.completed_jobs).toBe(0)
  })
})

// ── parseRunList ──────────────────────────────────────────────────────────────

describe('parseRunList', () => {
  it('parses a valid array of runs', () => {
    const result = parseRunList([makeRunRecord(), makeRunRecord({ run_id: 'run-2' })])
    expect(result).toHaveLength(2)
    expect(result[0]!.run_id).toBe('run-1')
    expect(result[1]!.run_id).toBe('run-2')
  })

  it('throws on non-array input', () => {
    expect(() => parseRunList(null)).toThrow('unexpected response shape')
  })

  it('skips items without run_id', () => {
    const result = parseRunList([makeRunRecord(), { status: 'running' }])
    expect(result).toHaveLength(1)
  })
})

// ── parseJobRecord ────────────────────────────────────────────────────────────

describe('parseJobRecord', () => {
  it('parses a valid job record', () => {
    const j = parseJobRecord(makeJobRecord())
    expect(j).not.toBeNull()
    expect(j!.job_id).toBe('job-1')
    expect(j!.device_id).toBe('steward-1')
    expect(j!.status).toBe('completed')
    expect(j!.exit_code).toBe(0)
  })

  it('returns null for non-object or missing job_id', () => {
    expect(parseJobRecord(null)).toBeNull()
    expect(parseJobRecord({ device_id: 'x' })).toBeNull()
  })

  it('coerces non-string stderr to empty string', () => {
    const j = parseJobRecord({ job_id: 'j-1', stderr: 42 })
    expect(j!.stderr).toBe('')
  })
})

// ── parseJobList ──────────────────────────────────────────────────────────────

describe('parseJobList', () => {
  it('parses a valid array of jobs', () => {
    const result = parseJobList([makeJobRecord(), makeJobRecord({ job_id: 'job-2' })])
    expect(result).toHaveLength(2)
  })

  it('throws on non-array input', () => {
    expect(() => parseJobList(null)).toThrow('unexpected response shape')
  })
})

// ── parseBatchJob ─────────────────────────────────────────────────────────────

describe('parseBatchJob', () => {
  it('parses a valid batch job', () => {
    const j = parseBatchJob(makeBatchJob())
    expect(j).not.toBeNull()
    expect(j!.id).toBe('bjob-1')
    expect(j!.selector).toBe('name:web*')
    expect(j!.targets).toEqual(['s-1', 's-2'])
    expect(j!.status).toBe('completed')
  })

  it('returns null for non-object or missing id', () => {
    expect(parseBatchJob(null)).toBeNull()
    expect(parseBatchJob({ selector: 'all' })).toBeNull()
  })

  it('coerces non-array targets to empty array', () => {
    const j = parseBatchJob({ id: 'j-1', targets: 'not-an-array' })
    expect(j!.targets).toEqual([])
  })
})

// ── parseBatchJobList ─────────────────────────────────────────────────────────

describe('parseBatchJobList', () => {
  it('parses a valid array', () => {
    const result = parseBatchJobList([makeBatchJob(), makeBatchJob({ id: 'bjob-2' })])
    expect(result).toHaveLength(2)
  })

  it('throws on non-array input', () => {
    expect(() => parseBatchJobList(null)).toThrow('unexpected response shape')
  })
})

// ── useScriptList ─────────────────────────────────────────────────────────────

describe('useScriptList', () => {
  it('starts in loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useScriptList())
    expect(result.current.loading).toBe(true)
    expect(result.current.scripts).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('returns parsed scripts on success', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([makeScript()]))
    const { result } = renderHook(() => useScriptList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.scripts).toHaveLength(1)
    expect(result.current.scripts[0]!.id).toBe('script-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([], 503))
    const { result } = renderHook(() => useScriptList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('503')
    expect(result.current.scripts).toEqual([])
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValueOnce(makeSuccessResponse([], 500))
    const { result } = renderHook(() => useScriptList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).not.toBeNull()

    fetchMock.mockResolvedValueOnce(makeSuccessResponse([makeScript()]))
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.scripts).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })
})

// ── useRunList ────────────────────────────────────────────────────────────────

describe('useRunList', () => {
  it('starts in loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useRunList())
    expect(result.current.loading).toBe(true)
    expect(result.current.runs).toEqual([])
  })

  it('returns parsed runs on success', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([makeRunRecord()]))
    const { result } = renderHook(() => useRunList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.runs).toHaveLength(1)
    expect(result.current.runs[0]!.run_id).toBe('run-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([], 500))
    const { result } = renderHook(() => useRunList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('500')
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValueOnce(makeSuccessResponse([], 500))
    const { result } = renderHook(() => useRunList())
    await waitFor(() => expect(result.current.loading).toBe(false))

    fetchMock.mockResolvedValueOnce(makeSuccessResponse([makeRunRecord()]))
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.runs).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })
})

// ── useRunStatus — polling to terminal state [REQUIRED] ───────────────────────

describe('useRunStatus', () => {
  it('returns null run and not-loading when runId is null', () => {
    const { result } = renderHook(() => useRunStatus(null))
    expect(result.current.run).toBeNull()
    expect(result.current.loading).toBe(false)
    expect(result.current.error).toBeNull()
  })

  it('starts loading when runId is provided', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useRunStatus('run-1'))
    expect(result.current.loading).toBe(true)
  })

  it('returns parsed run on success', async () => {
    fetchMock.mockResolvedValue(
      makeSuccessResponse(makeRunRecord({ status: 'completed' })),
    )
    const { result } = renderHook(() => useRunStatus('run-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.run?.run_id).toBe('run-1')
    expect(result.current.run?.status).toBe('completed')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse({}, 404))
    const { result } = renderHook(() => useRunStatus('run-bad'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('404')
  })

  it('polls to a terminal state then stops [REQUIRED]', async () => {
    // shouldAdvanceTime lets waitFor's internal setTimeout tick with real time
    // while vi.advanceTimersByTimeAsync() still controls the poll interval explicitly
    vi.useFakeTimers({ shouldAdvanceTime: true })

    // First fetch: run is still in progress
    fetchMock.mockResolvedValueOnce(
      makeSuccessResponse(makeRunRecord({ run_id: 'run-poll', status: 'running' })),
    )

    const { result } = renderHook(() => useRunStatus('run-poll'))

    await waitFor(() => expect(result.current.run?.status).toBe('running'))
    expect(fetchMock).toHaveBeenCalledTimes(1)

    // Second fetch: terminal state
    fetchMock.mockResolvedValueOnce(
      makeSuccessResponse(makeRunRecord({ run_id: 'run-poll', status: 'completed' })),
    )

    // Fire the poll interval timer and flush resulting Promises
    await act(async () => {
      await vi.advanceTimersByTimeAsync(RUN_POLL_INTERVAL)
    })

    await waitFor(() => expect(result.current.run?.status).toBe('completed'))
    expect(fetchMock).toHaveBeenCalledTimes(2)

    // After terminal state, no more fetches should be made even if time advances
    const callCountAfterTerminal = fetchMock.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(RUN_POLL_INTERVAL * 3)
    })
    expect(fetchMock).toHaveBeenCalledTimes(callCountAfterTerminal)
  })

  it('polls until "failed" terminal state', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })

    fetchMock.mockResolvedValueOnce(
      makeSuccessResponse(makeRunRecord({ run_id: 'run-fail', status: 'pending' })),
    )
    fetchMock.mockResolvedValueOnce(
      makeSuccessResponse(makeRunRecord({ run_id: 'run-fail', status: 'failed' })),
    )

    const { result } = renderHook(() => useRunStatus('run-fail'))

    await waitFor(() => expect(result.current.run?.status).toBe('pending'))

    await act(async () => {
      await vi.advanceTimersByTimeAsync(RUN_POLL_INTERVAL)
    })
    await waitFor(() => expect(result.current.run?.status).toBe('failed'))
    expect(RUN_TERMINAL.has('failed')).toBe(true)
  })

  it('all terminal states are in RUN_TERMINAL', () => {
    expect(RUN_TERMINAL.has('completed')).toBe(true)
    expect(RUN_TERMINAL.has('failed')).toBe(true)
    expect(RUN_TERMINAL.has('cancelled')).toBe(true)
    expect(RUN_TERMINAL.has('running')).toBe(false)
    expect(RUN_TERMINAL.has('pending')).toBe(false)
  })
})

// ── useRunJobs ────────────────────────────────────────────────────────────────

describe('useRunJobs', () => {
  it('returns empty and not-loading when runId is null', () => {
    const { result } = renderHook(() => useRunJobs(null, false))
    expect(result.current.jobs).toEqual([])
    expect(result.current.loading).toBe(false)
  })

  it('starts loading when runId is provided', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useRunJobs('run-1', false))
    expect(result.current.loading).toBe(true)
  })

  it('returns parsed jobs on success', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([makeJobRecord()]))
    const { result } = renderHook(() => useRunJobs('run-1', false))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.jobs).toHaveLength(1)
    expect(result.current.jobs[0]!.job_id).toBe('job-1')
    expect(result.current.error).toBeNull()
  })

  it('does not start polling when isRunTerminal is true', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    fetchMock.mockResolvedValue(makeSuccessResponse([makeJobRecord()]))

    const { result } = renderHook(() => useRunJobs('run-1', true))
    await waitFor(() => expect(result.current.loading).toBe(false))

    const callCountAfterInitial = fetchMock.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(RUN_POLL_INTERVAL * 3)
    })
    // Only the initial fetch should have fired
    expect(fetchMock).toHaveBeenCalledTimes(callCountAfterInitial)
  })
})

// ── useJobList ────────────────────────────────────────────────────────────────

describe('useJobList', () => {
  it('starts in loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useJobList())
    expect(result.current.loading).toBe(true)
    expect(result.current.jobs).toEqual([])
  })

  it('returns parsed batch jobs on success', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([makeBatchJob()]))
    const { result } = renderHook(() => useJobList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.jobs).toHaveLength(1)
    expect(result.current.jobs[0]!.id).toBe('bjob-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeSuccessResponse([], 503))
    const { result } = renderHook(() => useJobList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('503')
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValueOnce(makeSuccessResponse([], 500))
    const { result } = renderHook(() => useJobList())
    await waitFor(() => expect(result.current.loading).toBe(false))

    fetchMock.mockResolvedValueOnce(makeSuccessResponse([makeBatchJob()]))
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.jobs).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })
})
