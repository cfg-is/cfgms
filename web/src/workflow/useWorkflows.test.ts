// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import {
  parseWorkflowList,
  parseVersionedWorkflow,
  parseWorkflowExecution,
  parseExecutionList,
  parseTriggerItem,
  parseTriggerList,
  useWorkflowList,
  useWorkflowExecutions,
  useExecutionStatus,
  useTriggerList,
} from './useWorkflows.ts'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeWorkflowListResponse(workflows: object[], status = 200) {
  return new Response(
    JSON.stringify({ workflows, count: workflows.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeWorkflow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    name: 'wf-1',
    description: 'Test workflow',
    version: '1.0.0',
    steps: [{ name: 'step-1', type: 'script' }],
    semantic_version: { major: 1, minor: 0, patch: 0, pre_release: '', build_meta: '' },
    ...overrides,
  }
}

function makeExecution(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'exec-1',
    workflow_name: 'wf-1',
    status: 'running',
    start_time: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeExecutionsResponse(executions: object[], status = 200) {
  return new Response(
    JSON.stringify({ executions, count: executions.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function makeExecutionStatusResponse(exec: object, status = 200) {
  return new Response(JSON.stringify(exec), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeTrigger(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'trig-1',
    name: 'My trigger',
    type: 'schedule',
    status: 'active',
    workflow_name: 'wf-1',
    ...overrides,
  }
}

function makeTriggersResponse(triggers: object[], status = 200) {
  return new Response(
    JSON.stringify({ triggers, count: triggers.length }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

// ── parseVersionedWorkflow ────────────────────────────────────────────────────

describe('parseVersionedWorkflow', () => {
  it('parses a valid workflow', () => {
    const w = parseVersionedWorkflow(makeWorkflow())
    expect(w).not.toBeNull()
    expect(w!.name).toBe('wf-1')
    expect(w!.description).toBe('Test workflow')
    expect(w!.version).toBe('1.0.0')
    expect(w!.steps).toHaveLength(1)
    expect(w!.steps[0]!.name).toBe('step-1')
  })

  it('returns null for non-object input', () => {
    expect(parseVersionedWorkflow(null)).toBeNull()
    expect(parseVersionedWorkflow('string')).toBeNull()
    expect(parseVersionedWorkflow(42)).toBeNull()
  })

  it('returns null when name is missing', () => {
    expect(parseVersionedWorkflow({ description: 'no name', steps: [] })).toBeNull()
  })

  it('coerces non-string description to empty string', () => {
    const w = parseVersionedWorkflow({ name: 'wf-1', description: 42, steps: [] })
    expect(w!.description).toBe('')
  })

  it('handles missing steps gracefully', () => {
    const w = parseVersionedWorkflow({ name: 'wf-1' })
    expect(w!.steps).toEqual([])
  })

  it('parses semantic version', () => {
    const w = parseVersionedWorkflow(makeWorkflow())
    expect(w!.semantic_version.major).toBe(1)
    expect(w!.semantic_version.minor).toBe(0)
    expect(w!.semantic_version.patch).toBe(0)
  })
})

// ── parseWorkflowList ─────────────────────────────────────────────────────────

describe('parseWorkflowList', () => {
  it('parses a valid array of workflows', () => {
    const result = parseWorkflowList([makeWorkflow(), makeWorkflow({ name: 'wf-2' })])
    expect(result).toHaveLength(2)
    expect(result[0]!.name).toBe('wf-1')
    expect(result[1]!.name).toBe('wf-2')
  })

  it('returns an empty array for empty input', () => {
    expect(parseWorkflowList([])).toEqual([])
  })

  it('throws on non-array input', () => {
    expect(() => parseWorkflowList(null)).toThrow('unexpected response shape')
    expect(() => parseWorkflowList({ workflows: [] })).toThrow('unexpected response shape')
  })

  it('skips items without a name', () => {
    const result = parseWorkflowList([makeWorkflow(), { description: 'no name' }])
    expect(result).toHaveLength(1)
  })
})

// ── parseWorkflowExecution ────────────────────────────────────────────────────

describe('parseWorkflowExecution', () => {
  it('parses a valid execution', () => {
    const e = parseWorkflowExecution(makeExecution())
    expect(e).not.toBeNull()
    expect(e!.id).toBe('exec-1')
    expect(e!.workflow_name).toBe('wf-1')
    expect(e!.status).toBe('running')
  })

  it('returns null for non-object or missing id', () => {
    expect(parseWorkflowExecution(null)).toBeNull()
    expect(parseWorkflowExecution({ workflow_name: 'wf-1' })).toBeNull()
  })

  it('handles optional fields gracefully', () => {
    const e = parseWorkflowExecution({ id: 'exec-2', workflow_name: 'wf-1', status: 'pending', start_time: '' })
    expect(e!.end_time).toBeUndefined()
    expect(e!.error).toBeUndefined()
  })
})

// ── parseExecutionList ────────────────────────────────────────────────────────

describe('parseExecutionList', () => {
  it('parses a valid array of executions', () => {
    const result = parseExecutionList([makeExecution(), makeExecution({ id: 'exec-2' })])
    expect(result).toHaveLength(2)
  })

  it('throws on non-array input', () => {
    expect(() => parseExecutionList(null)).toThrow('unexpected response shape')
  })

  it('skips items without id', () => {
    const result = parseExecutionList([makeExecution(), { workflow_name: 'wf-1' }])
    expect(result).toHaveLength(1)
  })
})

// ── parseTriggerItem ──────────────────────────────────────────────────────────

describe('parseTriggerItem', () => {
  it('parses a valid trigger', () => {
    const t = parseTriggerItem(makeTrigger())
    expect(t).not.toBeNull()
    expect(t!.id).toBe('trig-1')
    expect(t!.name).toBe('My trigger')
    expect(t!.type).toBe('schedule')
    expect(t!.status).toBe('active')
  })

  it('returns null for non-object or missing id', () => {
    expect(parseTriggerItem(null)).toBeNull()
    expect(parseTriggerItem({ name: 'no-id' })).toBeNull()
  })
})

// ── parseTriggerList ──────────────────────────────────────────────────────────

describe('parseTriggerList', () => {
  it('parses a valid trigger array', () => {
    const result = parseTriggerList([makeTrigger(), makeTrigger({ id: 'trig-2', name: 'Trigger 2' })])
    expect(result).toHaveLength(2)
  })

  it('throws on non-array', () => {
    expect(() => parseTriggerList(null)).toThrow('unexpected response shape')
  })

  it('skips items without id', () => {
    const result = parseTriggerList([makeTrigger(), { name: 'no-id' }])
    expect(result).toHaveLength(1)
  })
})

// ── useWorkflowList ───────────────────────────────────────────────────────────

describe('useWorkflowList', () => {
  it('starts in loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useWorkflowList())
    expect(result.current.loading).toBe(true)
    expect(result.current.workflows).toEqual([])
    expect(result.current.error).toBeNull()
  })

  it('returns parsed workflows on success', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([makeWorkflow()]))
    const { result } = renderHook(() => useWorkflowList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.workflows).toHaveLength(1)
    expect(result.current.workflows[0]!.name).toBe('wf-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeWorkflowListResponse([], 500))
    const { result } = renderHook(() => useWorkflowList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('500')
    expect(result.current.workflows).toEqual([])
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([], 500))
    const { result } = renderHook(() => useWorkflowList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).not.toBeNull()

    fetchMock.mockResolvedValueOnce(makeWorkflowListResponse([makeWorkflow()]))
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.workflows).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })
})

// ── useWorkflowExecutions ─────────────────────────────────────────────────────

describe('useWorkflowExecutions', () => {
  it('returns empty and not-loading when name is null', () => {
    const { result } = renderHook(() => useWorkflowExecutions(null))
    expect(result.current.executions).toEqual([])
    expect(result.current.loading).toBe(false)
  })

  it('starts loading when name is provided', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useWorkflowExecutions('wf-1'))
    expect(result.current.loading).toBe(true)
  })

  it('returns parsed executions on success', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([makeExecution()]))
    const { result } = renderHook(() => useWorkflowExecutions('wf-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.executions).toHaveLength(1)
    expect(result.current.executions[0]!.id).toBe('exec-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeExecutionsResponse([], 500))
    const { result } = renderHook(() => useWorkflowExecutions('wf-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('500')
  })
})

// ── useExecutionStatus ────────────────────────────────────────────────────────

describe('useExecutionStatus', () => {
  it('returns null and not-loading when name or execId is null', () => {
    const { result } = renderHook(() => useExecutionStatus(null, null))
    expect(result.current.execution).toBeNull()
    expect(result.current.loading).toBe(false)
  })

  it('starts loading when both name and execId are provided', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useExecutionStatus('wf-1', 'exec-1'))
    expect(result.current.loading).toBe(true)
  })

  it('returns parsed execution on success', async () => {
    fetchMock.mockResolvedValue(makeExecutionStatusResponse(makeExecution({ status: 'completed' })))
    const { result } = renderHook(() => useExecutionStatus('wf-1', 'exec-1'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.execution?.id).toBe('exec-1')
    expect(result.current.execution?.status).toBe('completed')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeExecutionStatusResponse({}, 404))
    const { result } = renderHook(() => useExecutionStatus('wf-1', 'exec-bad'))
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('404')
  })
})

// ── useTriggerList ────────────────────────────────────────────────────────────

describe('useTriggerList', () => {
  it('starts in loading state', () => {
    fetchMock.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useTriggerList())
    expect(result.current.loading).toBe(true)
    expect(result.current.triggers).toEqual([])
  })

  it('returns parsed triggers on success', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([makeTrigger()]))
    const { result } = renderHook(() => useTriggerList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.triggers).toHaveLength(1)
    expect(result.current.triggers[0]!.id).toBe('trig-1')
    expect(result.current.error).toBeNull()
  })

  it('surfaces an error on non-ok response', async () => {
    fetchMock.mockResolvedValue(makeTriggersResponse([], 503))
    const { result } = renderHook(() => useTriggerList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).toContain('503')
  })

  it('refetches when retry is called', async () => {
    fetchMock.mockResolvedValueOnce(makeTriggersResponse([], 503))
    const { result } = renderHook(() => useTriggerList())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).not.toBeNull()

    fetchMock.mockResolvedValueOnce(makeTriggersResponse([makeTrigger()]))
    act(() => result.current.retry())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.triggers).toHaveLength(1)
    expect(result.current.error).toBeNull()
  })
})
