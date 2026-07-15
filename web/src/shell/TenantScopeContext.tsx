// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant scope (Story #2496) — a DISPLAY CONVENIENCE, not a security
 * boundary (security A8.1). Server-side tenant scoping on every API call
 * is the only enforcement; this context only decides what a technician
 * sees in the switcher and gives later views (fleet overview, #2497) a
 * shared "current scope" to filter by.
 *
 * There is no list-tenants API (see story Out of Scope) — selectable scopes
 * are the principal's own root path plus whatever descendant paths a later
 * view has actually observed in its data (registerObservedPath), matching
 * CLAUDE.md's recursive root/msp-a/client-1 path model.
 */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type TenantPath = string

/**
 * Path-separator-aware prefix match, mirroring the server-side ancestor
 * check in handlers_stewards.go: candidate equals scope, or candidate is a
 * descendant of scope at a "/" boundary — "tenant-a" must never match
 * "tenant-abc".
 */
export function isScopeMatch(candidate: TenantPath, scope: TenantPath): boolean {
  return candidate === scope || candidate.startsWith(`${scope}/`)
}

export interface TenantScopeValue {
  /** The currently selected scope. */
  scope: TenantPath
  /** Selectable scopes: the principal's root path + observed descendants. */
  observedPaths: TenantPath[]
  setScope: (path: TenantPath) => void
  /** Later views (e.g. fleet overview) report paths they've actually seen. */
  registerObservedPath: (path: TenantPath) => void
}

const TenantScopeContext = createContext<TenantScopeValue | null>(null)

export function TenantScopeProvider({
  rootPath,
  children,
}: {
  rootPath: TenantPath
  children: ReactNode
}) {
  const [scope, setScope] = useState<TenantPath>(rootPath)
  const [observedPaths, setObservedPaths] = useState<TenantPath[]>([rootPath])

  const registerObservedPath = useCallback((path: TenantPath) => {
    setObservedPaths((prev) => (prev.includes(path) ? prev : [...prev, path]))
  }, [])

  const value = useMemo(
    () => ({ scope, observedPaths, setScope, registerObservedPath }),
    [scope, observedPaths, registerObservedPath],
  )

  return (
    <TenantScopeContext.Provider value={value}>{children}</TenantScopeContext.Provider>
  )
}

export function useTenantScope(): TenantScopeValue {
  const value = useContext(TenantScopeContext)
  if (value === null) {
    throw new Error('useTenantScope must be used within a TenantScopeProvider')
  }
  return value
}
