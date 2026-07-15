// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import GlobalSearch from './GlobalSearch.tsx'

describe('GlobalSearch', () => {
  it('renders a search input with the mockup placeholder copy', () => {
    render(<GlobalSearch value="" onChange={() => {}} />)
    expect(
      screen.getByPlaceholderText(/filter stewards by name, user, ip, company/i),
    ).toBeInTheDocument()
  })

  it('is a controlled input that reports changes without calling any API', () => {
    const onChange = vi.fn()
    render(<GlobalSearch value="" onChange={onChange} />)
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'acme' } })
    expect(onChange).toHaveBeenCalledWith('acme')
  })

  it('reflects the controlled value prop', () => {
    render(<GlobalSearch value="acme" onChange={() => {}} />)
    expect(screen.getByRole('searchbox')).toHaveValue('acme')
  })
})
