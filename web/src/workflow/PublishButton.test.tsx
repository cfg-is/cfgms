// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * PublishButton tests (Issue #5857) — the real button, real publishWorkflow and real
 * apiFetch over a fetch transport. Only navigator.credentials is shimmed.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import PublishButton from './PublishButton.tsx'
import WorkflowBuilder from './WorkflowBuilder.tsx'
import type { PublicationInfo } from './publishWorkflow.ts'

let paths: string[]
let credentialsGet: ReturnType<typeof vi.fn>
let finishStatus: number
let beginStatus: number
let beginCode: string

function jsonResp(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fakeCredential() {
  const buf = new Uint8Array([1, 2, 3]).buffer
  return {
    id: 'cred', type: 'public-key', rawId: buf,
    response: { authenticatorData: buf, clientDataJSON: buf, signature: buf, userHandle: null },
  }
}

beforeEach(() => {
  paths = []
  finishStatus = 200
  beginStatus = 200
  beginCode = 'FORBIDDEN'
  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    const path = String(input)
    paths.push(path)
    if (path.endsWith('/publish/begin')) {
      if (beginStatus !== 200) return jsonResp(beginStatus, { error: { code: beginCode } })
      return jsonResp(200, {
        data: { assertion: { publicKey: { challenge: 'AAEC' } }, name: 'wf', version: '1.0.0', content_hash: 'h' },
      })
    }
    if (path.endsWith('/publish/finish')) {
      if (finishStatus !== 200) return jsonResp(finishStatus, { error: { code: 'CONTENT_CHANGED' } })
      return jsonResp(200, {
        data: { name: 'wf', version: '1.0.0', content_hash: 'h', signer_account_id: 'acct-7', signed_at: '2030-01-02T03:04:05Z' },
      })
    }
    return jsonResp(404, {})
  })
  credentialsGet = vi.fn(async () => fakeCredential())
  Object.defineProperty(navigator, 'credentials', { value: { get: credentialsGet }, configurable: true })
})

afterEach(() => vi.unstubAllGlobals())

const PUBLISHED: PublicationInfo = { signer_account_id: 'acct-7', signed_at: '2030-01-02T03:04:05Z', content_hash: 'h' }

function view(over: Partial<React.ComponentProps<typeof PublishButton>> = {}) {
  const onPublished = vi.fn()
  const utils = render(
    <PublishButton
      name="wf" version="1.0.0" isNew={false} unsaved={false} publication={null}
      onPublished={onPublished} {...over}
    />,
  )
  return { ...utils, onPublished }
}

describe('PublishButton', () => {
  it('runs begin, WebAuthn and finish, then reports the publication', async () => {
    const { onPublished } = view()
    fireEvent.click(screen.getByTestId('builder-publish'))
    await waitFor(() => expect(onPublished).toHaveBeenCalledWith(PUBLISHED))
    expect(paths).toEqual([
      '/api/v1/workflows/wf/versions/1.0.0/publish/begin',
      '/api/v1/workflows/wf/versions/1.0.0/publish/finish',
    ])
    expect(credentialsGet).toHaveBeenCalledTimes(1)
    expect(screen.queryByTestId('publish-error')).toBeNull()
  })

  it('sends no finish request and shows no error when the passkey prompt is cancelled', async () => {
    credentialsGet.mockRejectedValue(new DOMException('cancelled', 'NotAllowedError'))
    const { onPublished } = view()
    fireEvent.click(screen.getByTestId('builder-publish'))
    await waitFor(() => expect(credentialsGet).toHaveBeenCalled())
    await waitFor(() => expect(screen.getByTestId('builder-publish')).toBeEnabled())
    expect(paths).toEqual(['/api/v1/workflows/wf/versions/1.0.0/publish/begin'])
    expect(onPublished).not.toHaveBeenCalled()
    expect(screen.queryByTestId('publish-error')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('disables Publish with a reason while the editor has unsaved edits', () => {
    view({ unsaved: true })
    const btn = screen.getByTestId('builder-publish')
    expect(btn).toBeDisabled()
    expect(screen.getByTestId('publish-disabled-reason')).toHaveTextContent(/save your changes/i)
    fireEvent.click(btn)
    expect(paths).toEqual([])
    expect(credentialsGet).not.toHaveBeenCalled()
  })

  it('disables Publish with a reason for a workflow that is not saved yet', () => {
    view({ isNew: true, version: '' })
    expect(screen.getByTestId('builder-publish')).toBeDisabled()
    expect(screen.getByTestId('publish-disabled-reason')).toHaveTextContent(/save the workflow/i)
  })

  it('disables Publish when the open workflow has no stored version', () => {
    view({ version: '' })
    expect(screen.getByTestId('builder-publish')).toBeDisabled()
  })

  it('shows the Published chip with the signer and time once a publication exists', () => {
    view({ publication: PUBLISHED })
    const chip = screen.getByTestId('publish-chip')
    expect(chip).toHaveTextContent('Published')
    expect(chip).toHaveTextContent('acct-7')
    expect(chip).toHaveTextContent(new Date('2030-01-02T03:04:05Z').toLocaleString())
    expect(screen.getByTestId('builder-publish')).toBeDisabled()
    expect(screen.queryByTestId('publish-disabled-reason')).toBeNull()
  })

  it('shows no chip for an unpublished version', () => {
    view()
    expect(screen.queryByTestId('publish-chip')).toBeNull()
  })

  it('keeps the chip while edits are unsaved: the stored version is still published', () => {
    view({ publication: PUBLISHED, unsaved: true })
    expect(screen.getByTestId('publish-chip')).toBeInTheDocument()
  })

  it('renders a permission denial from begin and never prompts', async () => {
    beginStatus = 403
    view()
    fireEvent.click(screen.getByTestId('builder-publish'))
    expect(await screen.findByTestId('publish-error')).toHaveTextContent(/permission/i)
    expect(credentialsGet).not.toHaveBeenCalled()
    expect(paths).toHaveLength(1)
  })

  it('tells the admin to register a passkey when none exists', async () => {
    beginStatus = 409
    beginCode = 'NO_CREDENTIALS'
    view()
    fireEvent.click(screen.getByTestId('builder-publish'))
    expect(await screen.findByTestId('publish-error')).toHaveTextContent(/passkey/i)
  })

  it('renders a refused finish and reports nothing published', async () => {
    finishStatus = 409
    const { onPublished } = view()
    fireEvent.click(screen.getByTestId('builder-publish'))
    expect(await screen.findByTestId('publish-error')).toHaveTextContent(/409/)
    expect(onPublished).not.toHaveBeenCalled()
  })

  it('ignores a second click while a ceremony is running', async () => {
    let release!: () => void
    credentialsGet.mockImplementation(
      () => new Promise((resolve) => { release = () => resolve(fakeCredential()) }),
    )
    const { onPublished } = view()
    fireEvent.click(screen.getByTestId('builder-publish'))
    await waitFor(() => expect(credentialsGet).toHaveBeenCalledTimes(1))
    expect(screen.getByTestId('builder-publish')).toBeDisabled()
    expect(screen.getByTestId('builder-publish')).toHaveTextContent('Waiting for passkey…')
    fireEvent.click(screen.getByTestId('builder-publish'))
    release()
    await waitFor(() => expect(onPublished).toHaveBeenCalledTimes(1))
    expect(credentialsGet).toHaveBeenCalledTimes(1)
  })
})

/*
 * In the real builder: Publish follows the editor's saved state and the chip follows
 * the stored publication. React Flow needs ResizeObserver and DOMMatrixReadOnly,
 * which jsdom lacks; nothing else is shimmed.
 */
describe('PublishButton in WorkflowBuilder', () => {
  let stored: Record<string, unknown>
  let writes: string[]

  beforeAll(() => {
    if (typeof globalThis.ResizeObserver === 'undefined') {
      globalThis.ResizeObserver = class implements ResizeObserver {
        observe(): void {}
        unobserve(): void {}
        disconnect(): void {}
      }
    }
    if (typeof globalThis.DOMMatrixReadOnly === 'undefined') {
      globalThis.DOMMatrixReadOnly = class {
        m22 = 1
      } as unknown as typeof DOMMatrixReadOnly
    }
  })

  function mountBuilder(extra: Record<string, unknown> = {}) {
    stored = { name: 'wf', version: '1.0.0', description: 'd', steps: [{ id: 's1', name: 'first', type: 'script' }], ...extra }
    writes = []
    const publishFetch = globalThis.fetch
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      const method = (init?.method ?? 'GET').toUpperCase()
      if (method === 'GET' && path.endsWith('/api/v1/workflows')) {
        return jsonResp(200, { workflows: [stored], count: 1 })
      }
      if (method === 'PUT') {
        writes.push(path)
        return jsonResp(200, {})
      }
      return publishFetch(input, init)
    })
    return render(
      <MemoryRouter initialEntries={['/workflows/wf/builder']}>
        <Routes>
          <Route path="/workflows/:name/builder" element={<WorkflowBuilder />} />
        </Routes>
      </MemoryRouter>,
    )
  }

  it('enables Publish for the stored version and disables it once the editor has unsaved edits', async () => {
    mountBuilder()
    await screen.findByTestId('workflow-builder')
    expect(screen.getByTestId('builder-publish')).toBeEnabled()

    fireEvent.click(screen.getByTestId('palette-notify'))
    expect(screen.getByTestId('builder-dirty')).toBeInTheDocument()
    expect(screen.getByTestId('builder-publish')).toBeDisabled()
    expect(screen.getByTestId('publish-disabled-reason')).toHaveTextContent(/save your changes/i)
    fireEvent.click(screen.getByTestId('builder-publish'))
    expect(paths).toEqual([])

    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(writes).toEqual(['/api/v1/workflows/wf'])
    expect(screen.getByTestId('builder-publish')).toBeEnabled()
  })

  it('publishes the stored version and shows the chip in the toolbar', async () => {
    mountBuilder()
    await screen.findByTestId('workflow-builder')
    fireEvent.click(screen.getByTestId('builder-publish'))
    expect(await screen.findByTestId('publish-chip')).toHaveTextContent('acct-7')
    expect(paths).toEqual([
      '/api/v1/workflows/wf/versions/1.0.0/publish/begin',
      '/api/v1/workflows/wf/versions/1.0.0/publish/finish',
    ])
  })

  it('shows Published for a loaded version that carries a publication, and drops it when a save replaces the version', async () => {
    mountBuilder({
      publication: { content_hash: 'h', signer_account_id: 'acct-3', signed_at: '2030-05-06T07:08:09Z', signature: 'x' },
    })
    await screen.findByTestId('workflow-builder')
    expect(screen.getByTestId('publish-chip')).toHaveTextContent('acct-3')

    fireEvent.click(screen.getByTestId('builder-save'))
    await screen.findByTestId('builder-save-success')
    expect(screen.queryByTestId('publish-chip')).toBeNull()
    expect(screen.getByTestId('builder-publish')).toBeEnabled()
  })

  it('disables Publish for a new, unsaved workflow', async () => {
    render(
      <MemoryRouter initialEntries={['/workflows/new/builder']}>
        <Routes>
          <Route path="/workflows/new/builder" element={<WorkflowBuilder />} />
        </Routes>
      </MemoryRouter>,
    )
    expect(screen.getByTestId('builder-publish')).toBeDisabled()
    expect(screen.getByTestId('publish-disabled-reason')).toHaveTextContent(/save the workflow/i)
  })
})
