// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import AlertCenter from './AlertCenter.tsx'

describe('AlertCenter', () => {
  it('renders a bell button with no badge when there are no alerts', () => {
    render(<AlertCenter />)
    const button = screen.getByRole('button', { name: /notifications/i })
    expect(button).toBeInTheDocument()
    expect(screen.queryByTestId('alert-badge')).not.toBeInTheDocument()
  })

  it('opens a popover showing the designed empty state', () => {
    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    expect(screen.getByText(/no notifications/i)).toBeInTheDocument()
  })

  it('closes on Escape', () => {
    render(<AlertCenter />)
    fireEvent.click(screen.getByRole('button', { name: /notifications/i }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
