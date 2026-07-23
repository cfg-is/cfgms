// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * RowActionMenu suite (Story #2938): per-row action popover, stop-propagation
 * guard, and fully functional tag editor (add / remove via the tag endpoints,
 * state reflected immediately in the editor on each successful response).
 *
 * Security A10.2: parseTags validates the untrusted wire envelope; non-string
 * values in the tags array are dropped before any render.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import RowActionMenu, { parseTags } from './RowActionMenu.tsx'

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function mockTagsOk(tags: string[]) {
  fetchMock.mockResolvedValue(
    new Response(
      JSON.stringify({ data: { tags }, timestamp: '' }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    ),
  )
}

function mockTagsSeq(...responses: Array<{ status: number; tags?: string[] }>) {
  for (const r of responses) {
    fetchMock.mockResolvedValueOnce(
      new Response(
        r.tags !== undefined
          ? JSON.stringify({ data: { tags: r.tags }, timestamp: '' })
          : JSON.stringify({ error: 'fail' }),
        { status: r.status, headers: { 'Content-Type': 'application/json' } },
      ),
    )
  }
}

// ---------------------------------------------------------------------------
// parseTags unit tests
// ---------------------------------------------------------------------------

describe('parseTags (untrusted wire data)', () => {
  it('returns empty array for non-object data', () => {
    expect(parseTags(null)).toEqual([])
    expect(parseTags('string')).toEqual([])
    expect(parseTags(42)).toEqual([])
  })

  it('returns empty array when tags field is absent or not an array', () => {
    expect(parseTags({})).toEqual([])
    expect(parseTags({ tags: 'not-array' })).toEqual([])
    expect(parseTags({ tags: null })).toEqual([])
  })

  it('drops non-string values from the tags array', () => {
    expect(parseTags({ tags: ['prod', 42, null, 'dev', { obj: true }] })).toEqual([
      'prod',
      'dev',
    ])
  })

  it('returns a valid string array unchanged', () => {
    expect(parseTags({ tags: ['prod', 'dev', 'infra'] })).toEqual([
      'prod',
      'dev',
      'infra',
    ])
  })
})

// ---------------------------------------------------------------------------
// Kebab button behaviour
// ---------------------------------------------------------------------------

describe('kebab button', () => {
  it('renders a button with aria-label "Actions"', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    expect(screen.getByRole('button', { name: 'Actions' })).toBeInTheDocument()
  })

  it('click opens the action menu', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
  })

  it('second click closes the menu', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    const btn = screen.getByRole('button', { name: 'Actions' })
    fireEvent.click(btn)
    fireEvent.click(btn)
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('Escape closes the menu', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('click outside closes the menu', () => {
    render(
      <div>
        <div data-testid="outside">outside</div>
        <RowActionMenu stewardId="stw-1" />
      </div>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.mouseDown(screen.getByTestId('outside'))
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })

  it('click stops propagation — does not reach parent onClick', () => {
    const parentClick = vi.fn()
    render(
      <div onClick={parentClick}>
        <RowActionMenu stewardId="stw-1" />
      </div>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(parentClick).not.toHaveBeenCalled()
  })

  it('menu shows "Edit tags" item', () => {
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByRole('menuitem', { name: 'Edit tags' })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Tag editor
// ---------------------------------------------------------------------------

describe('tag editor', () => {
  it('clicking "Edit tags" shows the tag editor with a text input', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))
    expect(screen.getByRole('textbox', { name: 'New tag' })).toBeInTheDocument()
  })

  it('fetches current tags from GET /stewards/:id/tags when the editor opens', async () => {
    mockTagsOk(['prod'])
    render(<RowActionMenu stewardId="stw-42" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    expect(await screen.findByText('prod')).toBeInTheDocument()

    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw-42/tags')
    expect((fetchMock.mock.calls[0]?.[1]?.method ?? 'GET').toUpperCase()).toBe('GET')
  })

  it('encodes special characters in the steward ID', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw/sp ec" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const url = String(fetchMock.mock.calls[0]?.[0])
    expect(url).toBe('/api/v1/stewards/stw%2Fsp%20ec/tags')
  })

  it('renders existing tags as removable chips', async () => {
    mockTagsOk(['prod', 'dev'])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    expect(await screen.findByText('prod')).toBeInTheDocument()
    expect(screen.getByText('dev')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove tag prod' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove tag dev' })).toBeInTheDocument()
  })

  it('shows "No tags" when the list is empty', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    expect(await screen.findByText('No tags')).toBeInTheDocument()
  })

  it('removing a tag calls DELETE and reflects the updated list', async () => {
    mockTagsSeq({ status: 200, tags: ['prod'] }, { status: 200, tags: [] })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag prod' }))

    await waitFor(() => expect(screen.getByText('No tags')).toBeInTheDocument())

    const delCall = fetchMock.mock.calls.find(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'DELETE',
    )
    expect(delCall).toBeDefined()
    const body = JSON.parse(String(delCall?.[1]?.body)) as { tags: string[] }
    expect(body.tags).toContain('prod')
  })

  it('shows an error alert when remove fails with non-200 status', async () => {
    mockTagsSeq({ status: 200, tags: ['prod'] }, { status: 422 })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag prod' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('422')
    // Tag still shown — the list was not updated after the failed remove.
    expect(screen.getByText('prod')).toBeInTheDocument()
  })

  it('shows an error alert when remove fails with a network error', async () => {
    fetchMock
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { tags: ['prod'] }, timestamp: '' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockRejectedValueOnce(new Error('network down'))

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag prod' }))

    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })

  it('adding a tag calls POST and reflects the updated list', async () => {
    mockTagsSeq({ status: 200, tags: [] }, { status: 200, tags: ['dev'] })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByText('No tags')

    fireEvent.change(screen.getByRole('textbox', { name: 'New tag' }), {
      target: { value: 'dev' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    await waitFor(() => expect(screen.getByText('dev')).toBeInTheDocument())

    const postCall = fetchMock.mock.calls.find(
      (c) => (c[1]?.method ?? '').toUpperCase() === 'POST',
    )
    expect(postCall).toBeDefined()
    const body = JSON.parse(String(postCall?.[1]?.body)) as { tags: string[] }
    expect(body.tags).toContain('dev')
  })

  it('pressing Enter in the input adds a tag', async () => {
    mockTagsSeq({ status: 200, tags: [] }, { status: 200, tags: ['qa'] })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByText('No tags')

    const input = screen.getByRole('textbox', { name: 'New tag' })
    fireEvent.change(input, { target: { value: 'qa' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    await waitFor(() => expect(screen.getByText('qa')).toBeInTheDocument())
  })

  it('shows an error alert when the tag fetch fails (non-200 status)', async () => {
    mockTagsSeq({ status: 503 })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('503')
  })

  it('shows an error alert when add fails (non-200 status)', async () => {
    mockTagsSeq({ status: 200, tags: [] }, { status: 400 })

    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByText('No tags')
    fireEvent.change(screen.getByRole('textbox', { name: 'New tag' }), {
      target: { value: 'INVALID' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('400')
  })

  it('back button returns to the menu from the tag editor', async () => {
    mockTagsOk([])
    render(<RowActionMenu stewardId="stw-1" />)
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Edit tags' }))

    await screen.findByRole('textbox', { name: 'New tag' })

    fireEvent.click(screen.getByRole('button', { name: 'Back to menu' }))

    expect(screen.getByRole('menuitem', { name: 'Edit tags' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
  })
})
