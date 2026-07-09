// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import App from './App.tsx'

describe('App', () => {
  it('renders the placeholder heading', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'CFGMS' })).toBeInTheDocument()
  })
})
