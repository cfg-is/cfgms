// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ScriptPrivilegePanel test suite (Issue #5447): scope parsing, binding rows,
 * and the exact PUT body. Presence-tap flows are covered in ScriptsView.test.tsx.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { AuthProvider } from '../auth/AuthContext.tsx'
import ScriptPrivilegePanel, { parseScopes } from './ScriptPrivilegePanel.tsx'
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

const script: ScriptMetadata = {
  id: 'script-1',
  name: '<b>Patch</b>',
  description: '',
  version: null,
  author: '',
  tags: [],
  category: '',
  platform: [],
  shell: 'bash',
  parameters: [],
  created_at: '',
  updated_at: '',
  idempotent: false,
}

function renderPanel() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <ScriptPrivilegePanel script={script} />
      </AuthProvider>
    </MemoryRouter>,
  )
}

describe('parseScopes', () => {
  it('trims lines and drops blanks', () => {
    expect(parseScopes(' a:b \n\n c:d\n')).toEqual(['a:b', 'c:d'])
  })
})

describe('ScriptPrivilegePanel', () => {
  it('renders the script name as text, not HTML', () => {
    renderPanel()
    expect(screen.getByText('Privilege for <b>Patch</b>')).toBeInTheDocument()
  })

  it('drops blank and removed binding rows from the PUT body', async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ data: {}, timestamp: 'x' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderPanel()
    const add = screen.getByTestId('privilege-add-binding-btn')
    fireEvent.click(add)
    fireEvent.click(add)
    fireEvent.click(add)
    fireEvent.change(screen.getByLabelText('Binding parameter 1'), { target: { value: 'keep' } })
    fireEvent.change(screen.getByLabelText('Binding platform 1'), { target: { value: 'windows' } })
    fireEvent.change(screen.getByLabelText('Binding parameter 3'), { target: { value: 'gone' } })
    fireEvent.click(screen.getByLabelText('Remove binding 3'))
    fireEvent.click(screen.getByTestId('privilege-save-btn'))

    await waitFor(() => expect(screen.getByTestId('privilege-saved')).toBeInTheDocument())
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body))).toEqual({
      required_api_scope: [],
      param_platform_bindings: { keep: 'windows' },
    })
  })
})
