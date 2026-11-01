// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it } from 'vitest'
import { render, screen, act } from '@testing-library/react'
import {
  TenantScopeProvider,
  useTenantScope,
  isScopeMatch,
} from './TenantScopeContext.tsx'

describe('isScopeMatch (path-separator-aware prefix matching)', () => {
  it('matches a path against itself', () => {
    expect(isScopeMatch('root/msp-a', 'root/msp-a')).toBe(true)
  })

  it('matches a true descendant (separator boundary respected)', () => {
    expect(isScopeMatch('root/msp-a/client-1', 'root/msp-a')).toBe(true)
  })

  it('does not match a sibling with a shared string prefix', () => {
    // The exact boundary case named in the story: "tenant-a" must not match "tenant-abc".
    expect(isScopeMatch('tenant-abc', 'tenant-a')).toBe(false)
  })

  it('does not match an unrelated path', () => {
    expect(isScopeMatch('root/msp-b', 'root/msp-a')).toBe(false)
  })

  it('does not match an ancestor against a descendant scope', () => {
    expect(isScopeMatch('root', 'root/msp-a')).toBe(false)
  })
})

function Probe() {
  const { scope, observedPaths, setScope, registerObservedPath } = useTenantScope()
  return (
    <div>
      <span data-testid="scope">{scope}</span>
      <span data-testid="paths">{observedPaths.join(',')}</span>
      <button type="button" onClick={() => setScope('root/msp-a/client-1')}>
        select
      </button>
      <button type="button" onClick={() => registerObservedPath('root/msp-a/client-1')}>
        observe
      </button>
      <button type="button" onClick={() => registerObservedPath('root/msp-a')}>
        observe-dup
      </button>
    </div>
  )
}

describe('TenantScopeProvider', () => {
  it('initializes scope to the provided root path', () => {
    render(
      <TenantScopeProvider rootPath="root/msp-a">
        <Probe />
      </TenantScopeProvider>,
    )
    expect(screen.getByTestId('scope').textContent).toBe('root/msp-a')
    expect(screen.getByTestId('paths').textContent).toBe('root/msp-a')
  })

  it('registers newly observed descendant paths exactly once', () => {
    render(
      <TenantScopeProvider rootPath="root/msp-a">
        <Probe />
      </TenantScopeProvider>,
    )
    act(() => screen.getByText('observe').click())
    act(() => screen.getByText('observe-dup').click())
    act(() => screen.getByText('observe').click())
    expect(screen.getByTestId('paths').textContent).toBe('root/msp-a,root/msp-a/client-1')
  })

  it('updates the selected scope via setScope', () => {
    render(
      <TenantScopeProvider rootPath="root/msp-a">
        <Probe />
      </TenantScopeProvider>,
    )
    act(() => screen.getByText('select').click())
    expect(screen.getByTestId('scope').textContent).toBe('root/msp-a/client-1')
  })

  it('throws when useTenantScope is used outside the provider', () => {
    function Bare() {
      useTenantScope()
      return null
    }
    expect(() => render(<Bare />)).toThrow(/TenantScopeProvider/)
  })
})
