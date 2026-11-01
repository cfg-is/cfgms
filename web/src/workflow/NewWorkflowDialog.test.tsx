// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/* NewWorkflowDialog tests (Issue #4582): payload shape, validation, 409/400 handling. */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import NewWorkflowDialog from './NewWorkflowDialog.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  cleanup()
})

function renderDialog() {
  const onClose = vi.fn()
  const onCreated = vi.fn()
  render(
    <MemoryRouter>
      <AuthProvider>
        <NewWorkflowDialog onClose={onClose} onCreated={onCreated} />
      </AuthProvider>
    </MemoryRouter>,
  )
  return { onClose, onCreated }
}

function fill(name: string, step: string) {
  fireEvent.change(screen.getByTestId('new-wf-name'), { target: { value: name } })
  fireEvent.change(screen.getByTestId('new-wf-step-name'), { target: { value: step } })
}

describe('NewWorkflowDialog', () => {
  it('rejects empty name and step inline without calling the API', () => {
    renderDialog()
    fireEvent.click(screen.getByTestId('new-wf-submit'))
    expect(screen.getByTestId('new-wf-name-error')).toBeInTheDocument()
    expect(screen.getByTestId('new-wf-step-error')).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('POSTs only accepted fields and reports the created name', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 201 }))
    const { onCreated } = renderDialog()
    fill('deploy', 'first')
    fireEvent.change(screen.getByTestId('new-wf-description'), { target: { value: 'desc' } })
    fireEvent.change(screen.getByTestId('new-wf-step-module'), { target: { value: 'file' } })
    fireEvent.click(screen.getByTestId('new-wf-submit'))
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith('deploy'))
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe('/api/v1/workflows')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      name: 'deploy',
      description: 'desc',
      steps: [{ name: 'first', type: 'task', module: 'file' }],
    })
  })

  it('409 shows a name field error and keeps submit enabled', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'already exists' }), { status: 409 }))
    const { onCreated } = renderDialog()
    fill('dup', 's1')
    fireEvent.click(screen.getByTestId('new-wf-submit'))
    expect((await screen.findByTestId('new-wf-name-error')).textContent).toBe('already exists')
    expect(onCreated).not.toHaveBeenCalled()
    expect(screen.getByTestId('new-wf-submit')).not.toBeDisabled()
  })

  it('400 shows the server message as a form error', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: 'invalid version format' }), { status: 400 }),
    )
    renderDialog()
    fill('bad', 's1')
    fireEvent.click(screen.getByTestId('new-wf-submit'))
    expect((await screen.findByTestId('new-wf-form-error')).textContent).toBe('invalid version format')
    expect(screen.getByTestId('new-wf-submit')).not.toBeDisabled()
  })

  it('Cancel calls onClose', () => {
    const { onClose } = renderDialog()
    fireEvent.click(screen.getByText('Cancel'))
    expect(onClose).toHaveBeenCalled()
  })
})
