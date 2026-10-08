// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/* ImportYamlDialog tests (Issue #4619): valid import creates, invalid creates nothing. */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ImportYamlDialog from './ImportYamlDialog.tsx'

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
        <ImportYamlDialog onClose={onClose} onCreated={onCreated} />
      </AuthProvider>
    </MemoryRouter>,
  )
  return { onClose, onCreated }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status })
}

describe('ImportYamlDialog', () => {
  it('creates the workflow for a valid document', async () => {
    fetchMock.mockImplementation((url) =>
      Promise.resolve(
        String(url).endsWith('/parse-yaml')
          ? json({ workflow: { name: 'deploy', steps: [{ name: 's', type: 'task' }], extra: 1 }, valid: true, issues: [] })
          : json({}, 201),
      ),
    )
    const { onCreated } = renderDialog()
    fireEvent.change(screen.getByTestId('import-yaml-text'), { target: { value: 'name: deploy' } })
    fireEvent.click(screen.getByTestId('import-yaml-submit'))
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith('deploy'))
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const [url, init] = fetchMock.mock.calls[1]!
    expect(String(url)).toBe('/api/v1/workflows')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({ name: 'deploy', steps: [{ name: 's', type: 'task' }] })
  })

  it('shows server issues and creates nothing for an invalid document', async () => {
    fetchMock.mockResolvedValue(
      json({ workflow: { name: '' }, valid: false, issues: [{ path: 'steps[0].module', message: 'module is required' }] }),
    )
    const { onCreated } = renderDialog()
    fireEvent.change(screen.getByTestId('import-yaml-text'), { target: { value: 'name: ""' } })
    fireEvent.click(screen.getByTestId('import-yaml-submit'))
    expect((await screen.findByTestId('import-yaml-issues')).textContent).toContain('module is required')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(onCreated).not.toHaveBeenCalled()
  })

  it('shows the error and creates nothing when the document cannot be parsed', async () => {
    fetchMock.mockResolvedValue(json({ error: 'invalid workflow YAML' }, 400))
    const { onCreated } = renderDialog()
    fireEvent.change(screen.getByTestId('import-yaml-text'), { target: { value: ': :' } })
    fireEvent.click(screen.getByTestId('import-yaml-submit'))
    expect((await screen.findByTestId('import-yaml-error')).textContent).toBe('invalid workflow YAML')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(onCreated).not.toHaveBeenCalled()
  })

  it('surfaces a 409 from create', async () => {
    fetchMock.mockImplementation((url) =>
      Promise.resolve(
        String(url).endsWith('/parse-yaml')
          ? json({ workflow: { name: 'dup', steps: [] }, valid: true, issues: [] })
          : json({ error: 'already exists' }, 409),
      ),
    )
    const { onCreated } = renderDialog()
    fireEvent.change(screen.getByTestId('import-yaml-text'), { target: { value: 'name: dup' } })
    fireEvent.click(screen.getByTestId('import-yaml-submit'))
    expect((await screen.findByTestId('import-yaml-error')).textContent).toBe('already exists')
    expect(onCreated).not.toHaveBeenCalled()
  })

  it('rejects an empty document without calling the API', () => {
    renderDialog()
    fireEvent.click(screen.getByTestId('import-yaml-submit'))
    expect(screen.getByTestId('import-yaml-error')).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('loads a picked file into the text area', async () => {
    renderDialog()
    const file = new File(['name: from-file'], 'wf.yaml', { type: 'application/yaml' })
    Object.defineProperty(file, 'text', { value: () => Promise.resolve('name: from-file') })
    fireEvent.change(screen.getByTestId('import-yaml-file'), { target: { files: [file] } })
    await waitFor(() =>
      expect((screen.getByTestId('import-yaml-text') as HTMLTextAreaElement).value).toBe('name: from-file'),
    )
  })
})
