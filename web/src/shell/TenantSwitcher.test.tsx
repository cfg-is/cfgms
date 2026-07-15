// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

import { describe, expect, it } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { TenantScopeProvider, useTenantScope } from './TenantScopeContext.tsx'
import TenantSwitcher from './TenantSwitcher.tsx'

function Harness() {
  const { registerObservedPath } = useTenantScope()
  registerObservedPath('root/msp-a/client-1')
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
