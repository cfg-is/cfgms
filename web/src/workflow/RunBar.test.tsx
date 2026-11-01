// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/* RunBar tests (Issue #4616) — real RunBar and apiFetch over a fetch transport. */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import RunBar from './RunBar.tsx'
import type { WorkflowExecution } from './useWorkflows.ts'

afterEach(() => vi.unstubAllGlobals())

const exec = (status: string): WorkflowExecution => ({
  id: 'ex1', workflow_name: 'wf', status, start_time: 't',
})

function bar(over: Partial<React.ComponentProps<typeof RunBar>> = {}) {
  return render(
    <RunBar
      workflowName="wf" executionId="ex1" execution={exec('running')} error={null}
      completedSteps={1} totalSteps={3} onDismiss={() => {}} {...over}
    />,
  )
}

describe('RunBar', () => {
  it('shows loading while the first poll is pending', () => {
    bar({ execution: null })
    expect(screen.getByTestId('run-bar-loading')).toBeInTheDocument()
  })

  it('shows step progress and status, with Cancel only while non-terminal', () => {
    const { unmount } = bar()
    expect(screen.getByTestId('run-bar-progress')).toHaveTextContent('step 1/3')
    expect(screen.getByTestId('run-bar-cancel')).toBeInTheDocument()
    unmount()
    bar({ execution: exec('completed'), completedSteps: 3 })
    expect(screen.getByTestId('run-bar-status')).toHaveTextContent('completed')
    expect(screen.queryByTestId('run-bar-cancel')).toBeNull()
  })

  it('renders the Error state instead of a blank bar', () => {
    bar({ execution: null, error: 'GET … — 503' })
    expect(screen.getByTestId('run-bar-error')).toHaveTextContent('503')
  })

  it('posts to the cancel endpoint and renders a denial', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', (input: RequestInfo | URL) => {
      calls.push(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
      return Promise.resolve(new Response(JSON.stringify({ error: 'permission denied' }), { status: 403 }))
    })
    bar()
    fireEvent.click(screen.getByTestId('run-bar-cancel'))
    expect(await screen.findByTestId('run-bar-cancel-error')).toHaveTextContent('permission denied')
    expect(calls[0]).toMatch(/\/api\/v1\/workflows\/wf\/executions\/ex1\/cancel$/)
  })
})
