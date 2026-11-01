// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RunInputsForm tests (Issue #4617). The component renders declared inputs;
 * the end-to-end cases run it inside the real WorkflowExecutionView against a
 * fetch transport that speaks the controller's execute contract.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import RunInputsForm from './RunInputsForm.tsx'
import WorkflowExecutionView from './WorkflowExecutionView.tsx'
import { buildPayload, initialValues, requiredErrors } from './runInputs.ts'
import type { InputSpec } from './useWorkflows.ts'

const INPUTS: InputSpec[] = [
  { name: 'target', type: 'string', required: true, description: 'Host to patch' },
  { name: 'ring', type: 'enum', options: ['canary', 'broad'], default: 'canary' },
  { name: 'reboot', type: 'bool', default: true },
]

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('RunInputsForm', () => {
  it('renders required markers, an enum select and a bool checkbox', () => {
    render(<RunInputsForm inputs={INPUTS} values={initialValues(INPUTS)} errors={{}} onChange={() => {}} />)
    expect(screen.getByTestId('run-input-required-target')).toBeInTheDocument()
    expect(screen.queryByTestId('run-input-required-ring')).toBeNull()
    const select = screen.getByLabelText('ring') as HTMLSelectElement
    expect(select.tagName).toBe('SELECT')
    expect(select.value).toBe('canary')
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['', 'canary', 'broad'])
    const box = screen.getByLabelText('reboot') as HTMLInputElement
    expect(box.type).toBe('checkbox')
    expect(box.checked).toBe(true)
    expect(screen.getByText('Host to patch')).toBeInTheDocument()
  })

  it('renders nothing when no inputs are declared', () => {
    const { container } = render(<RunInputsForm inputs={[]} values={{}} errors={{}} onChange={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows an error message at its field only', () => {
    render(<RunInputsForm inputs={INPUTS} values={initialValues(INPUTS)} errors={{ ring: 'not an option' }} onChange={() => {}} />)
    expect(screen.getByTestId('run-input-ring')).toContainElement(screen.getByTestId('run-input-error-ring'))
    expect(screen.queryByTestId('run-input-error-target')).toBeNull()
  })

  it('payload carries only declared inputs and omits empty optionals', () => {
    const values = { ...initialValues(INPUTS), target: 'srv1', undeclared: 'x' }
    expect(buildPayload(INPUTS, values)).toEqual({ target: 'srv1', ring: 'canary', reboot: true })
    expect(buildPayload(INPUTS, { target: '', ring: '', reboot: false })).toEqual({ reboot: false })
    expect(requiredErrors(INPUTS, initialValues(INPUTS))).toEqual({ target: 'This input is required' })
  })
})

describe('Run form in the drawer Run tab', () => {
  let bodies: Record<string, unknown>[]
  let executeResponse: () => Response

  beforeEach(() => {
    bodies = []
    executeResponse = () => json(202, { execution_id: 'ex1' })
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.endsWith('/execute')) {
        bodies.push(JSON.parse(init?.body as string) as Record<string, unknown>)
        return Promise.resolve(executeResponse())
      }
      if (url.endsWith('/executions')) return Promise.resolve(json(200, { executions: [], count: 0 }))
      return Promise.resolve(json(200, { id: 'ex1', workflow_name: 'wf', status: 'running', start_time: 't' }))
    })
  })

  function renderView() {
    return render(
      <MemoryRouter>
        <AuthProvider>
          <WorkflowExecutionView workflowName="wf" inputs={INPUTS} />
        </AuthProvider>
      </MemoryRouter>,
    )
  }

  it('[REQUIRED] a server 400 on a field shows the message at that field', async () => {
    executeResponse = () =>
      json(400, { error: 'invalid workflow inputs', fields: [{ field: 'ring', message: 'must be one of canary, broad' }] })
    renderView()
    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.change(screen.getByLabelText(/^target/), { target: { value: 'srv1' } })
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))
    const err = await screen.findByTestId('run-input-error-ring')
    expect(err).toHaveTextContent('must be one of canary, broad')
    expect(screen.getByTestId('run-input-ring')).toContainElement(err)
    // dialog stays open for correction
    expect(screen.getByTestId('exec-confirm-btn')).toBeInTheDocument()
  })

  it('blocks a missing required input locally and sends declared inputs only', async () => {
    renderView()
    fireEvent.click(screen.getByTestId('execute-btn'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))
    expect(screen.getByTestId('run-input-error-target')).toBeInTheDocument()
    expect(bodies).toHaveLength(0)

    fireEvent.change(screen.getByLabelText(/^target/), { target: { value: 'srv1' } })
    fireEvent.click(screen.getByLabelText('reboot'))
    fireEvent.click(screen.getByTestId('exec-confirm-btn'))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies.at(0)).toEqual({ variables: {}, inputs: { target: 'srv1', ring: 'canary', reboot: false } })
  })
})
