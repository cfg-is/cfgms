// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import GlobalSearch from './GlobalSearch.tsx'

describe('GlobalSearch', () => {
  it('renders a search input with selector-syntax placeholder', () => {
    render(<GlobalSearch value="" onChange={() => {}} />)
    expect(
      screen.getByPlaceholderText(/search fleet/i),
    ).toBeInTheDocument()
  })

  it('shows inline selector syntax hint text', () => {
    render(<GlobalSearch value="" onChange={() => {}} />)
    const hint = screen.getByTestId('search-syntax-hint')
    expect(hint).toBeInTheDocument()
    // Hint must reference the core selector keys.
    expect(hint.textContent).toContain('id:')
    expect(hint.textContent).toContain('name:')
    expect(hint.textContent).toContain('os:')
    expect(hint.textContent).toContain('tag:')
    expect(hint.textContent).toContain('dna.')
  })

  it('is a controlled input that reports changes via onChange only', () => {
    const onChange = vi.fn()
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    try {
      render(<GlobalSearch value="" onChange={onChange} />)
      fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'acme' } })
      expect(onChange).toHaveBeenCalledWith('acme')
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('reflects the controlled value prop', () => {
    render(<GlobalSearch value="acme" onChange={() => {}} />)
    expect(screen.getByRole('searchbox')).toHaveValue('acme')
  })
})
