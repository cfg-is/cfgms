// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * ErrorCard unit tests (Story #2945): error-class classification and
 * copy selection.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import ErrorCard from './ErrorCard.tsx'

afterEach(() => cleanup())

describe('ErrorCard — structure', () => {
  it('has role="alert"', () => {
    render(<ErrorCard heading="Couldn't load data" detail="network error" onRetry={() => {}} />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('renders the heading', () => {
    render(<ErrorCard heading="Couldn't load widgets" detail="network error" onRetry={() => {}} />)
    expect(screen.getByRole('heading', { name: /couldn't load widgets/i })).toBeInTheDocument()
  })

  it('renders the detail string', () => {
    render(<ErrorCard heading="Couldn't load data" detail="GET /api/v1/foo — 503" onRetry={() => {}} />)
    expect(screen.getByText(/GET \/api\/v1\/foo — 503/)).toBeInTheDocument()
  })

  it('calls onRetry when the Retry button is clicked', () => {
    const onRetry = vi.fn()
    render(<ErrorCard heading="Couldn't load data" detail="network error" onRetry={onRetry} />)
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalledOnce()
  })
})

describe('ErrorCard — error classification', () => {
  it('shows connectivity copy for a plain network failure (no HTTP status)', () => {
    render(<ErrorCard heading="Couldn't load data" detail="GET /api/v1/foo — request failed" onRetry={() => {}} />)
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })

  it('shows connectivity copy when error carries no HTTP status code', () => {
    render(<ErrorCard heading="Couldn't load data" detail="unexpected response shape" onRetry={() => {}} />)
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })

  it('shows server-error copy for a 500 response — not connectivity', () => {
    render(<ErrorCard heading="Couldn't load data" detail="GET /api/v1/foo — 500" onRetry={() => {}} />)
    expect(screen.queryByText(/check your connection/i)).toBeNull()
    expect(screen.getByText(/server.*error|returned an error/i)).toBeInTheDocument()
  })

  it('shows server-error copy for a 503 response', () => {
    render(<ErrorCard heading="Couldn't load data" detail="GET /api/v1/foo — 503" onRetry={() => {}} />)
    expect(screen.queryByText(/check your connection/i)).toBeNull()
    expect(screen.getByText(/server.*error|returned an error/i)).toBeInTheDocument()
  })

  it('shows server-error copy for a 502 response', () => {
    render(<ErrorCard heading="Couldn't load data" detail="GET /api/v1/foo — 502" onRetry={() => {}} />)
    expect(screen.queryByText(/check your connection/i)).toBeNull()
  })

  it('shows connectivity copy for a 4xx response (client error treated as connectivity in this schema)', () => {
    render(<ErrorCard heading="Couldn't load data" detail="GET /api/v1/foo — 404" onRetry={() => {}} />)
    expect(screen.getByText(/check your connection/i)).toBeInTheDocument()
  })
})
