// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import SelectorInput from './SelectorInput.tsx'

describe('SelectorInput', () => {
  it('renders the grammar hint wired to the input via a per-instance id', () => {
    render(
      <SelectorInput
        value=""
        onChange={() => {}}
        placeholder="name:web*"
        hintId="test-hint"
        hintTestId="test-hint-span"
      />,
    )
    const input = screen.getByRole('textbox')
    expect(input).toHaveAttribute('aria-describedby', 'test-hint')
    const hint = screen.getByTestId('test-hint-span')
    expect(hint).toHaveAttribute('id', 'test-hint')
  })

  it('emits the raw input value on change', () => {
    const onChange = vi.fn()
    render(
      <SelectorInput
        value=""
        onChange={onChange}
        placeholder="name:web*"
        hintId="h"
        ariaLabel="Selector"
      />,
    )
    fireEvent.change(screen.getByRole('textbox', { name: /selector/i }), {
      target: { value: 'os:linux' },
    })
    expect(onChange).toHaveBeenCalledWith('os:linux')
  })

  it('honors an overridden role so it can be a searchbox in the shell chrome', () => {
    render(
      <SelectorInput
        value=""
        onChange={() => {}}
        placeholder="Search fleet"
        hintId="h"
        role="searchbox"
      />,
    )
    expect(screen.getByRole('searchbox')).toBeInTheDocument()
  })

  it('applies an optional className to the input', () => {
    render(
      <SelectorInput
        value=""
        onChange={() => {}}
        placeholder="p"
        hintId="h"
        ariaLabel="Selector"
        className="wide"
      />,
    )
    expect(screen.getByRole('textbox', { name: /selector/i })).toHaveClass('wide')
  })
})
