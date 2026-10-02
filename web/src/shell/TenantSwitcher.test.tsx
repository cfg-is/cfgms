// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it } from 'vitest'
import { useEffect } from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { TenantScopeProvider, useTenantScope } from './TenantScopeContext.tsx'
import TenantSwitcher from './TenantSwitcher.tsx'

function Harness() {
  const { registerObservedPath } = useTenantScope()
  useEffect(() => {
    registerObservedPath('root/msp-a/client-1')
  }, [registerObservedPath])
  return <TenantSwitcher />
}

describe('TenantSwitcher', () => {
  it('shows the current scope path', () => {
    render(
      <TenantScopeProvider rootPath="root/msp-a">
        <TenantSwitcher />
      </TenantScopeProvider>,
    )
    expect(screen.getByRole('button', { name: /root\/msp-a/ })).toBeInTheDocument()
  })

  it('opens a menu listing observed scopes and selects one', () => {
    render(
      <TenantScopeProvider rootPath="root/msp-a">
        <Harness />
      </TenantScopeProvider>,
    )
    fireEvent.click(screen.getByRole('button', { name: /root\/msp-a/ }))
    const option = screen.getByRole('menuitem', { name: /root\/msp-a\/client-1/ })
    fireEvent.click(option)
    expect(screen.getByRole('button', { name: /root\/msp-a\/client-1/ })).toBeInTheDocument()
  })

  it('renders the "root" label when the scope is empty (root-scoped account, Issue #2919)', () => {
    // A root-scoped account seeds TenantScopeProvider with rootPath="" (empty
    // scope). The switcher must fall back to the literal 'root' label rather than
    // rendering an empty <b> — this is the only branch that exercises
    // `displayLeaf = leaf || 'root'` for an empty leaf.
    render(
      <TenantScopeProvider rootPath="">
        <TenantSwitcher />
      </TenantScopeProvider>,
    )
    const button = screen.getByRole('button', { name: /root/i })
    expect(button).toBeInTheDocument()
    expect(button.querySelector('b')?.textContent).toBe('root')
  })

  it('closes the menu on Escape', () => {
    render(
      <TenantScopeProvider rootPath="root/msp-a">
        <TenantSwitcher />
      </TenantScopeProvider>,
    )
    fireEvent.click(screen.getByRole('button', { name: /root\/msp-a/ }))
    expect(screen.getByRole('menu')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('menu')).not.toBeInTheDocument()
  })
})
