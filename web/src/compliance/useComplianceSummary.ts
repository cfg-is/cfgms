// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Compliance summary data hook (Story #3272): fetches
 * GET /api/v1/compliance/summary via the existing apiFetch wrapper.
 *
 * Tenant scope: when the tenant switcher is narrowed (scope !== rootPath),
 * the selected path is passed as ?tenant_id= so the server filters the
 * by_tenant breakdown accordingly. At root scope with no selection, the param
 * is omitted and the server returns the full cross-tenant table.
 *
 * Response shape matches ComplianceSummaryResponse in
 * features/controller/api/handlers_compliance.go (lines 69-87).
 */
import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../api/client.ts'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'

export interface TenantComplianceStatus {
  tenant_id: string
  tenant_name: string
  total_devices: number
  compliant_devices: number
  warning_devices: number
  critical_devices: number
  breached_devices: number
}

export interface ComplianceSummaryData {
  total_devices: number
  compliant_devices: number
  warning_devices: number
  critical_devices: number
  breached_devices: number
  by_tenant: TenantComplianceStatus[]
  generated_at: string
}

export interface UseComplianceSummaryResult {
  data: ComplianceSummaryData | null
  loading: boolean
  /** User-presentable failure line, e.g. "GET /api/v1/compliance/summary — 503". */
  error: string | null
  retry: () => void
}

function parseTenantStatus(v: unknown): TenantComplianceStatus | null {
  if (typeof v !== 'object' || v === null) return null
  const r = v as Record<string, unknown>
  if (typeof r.tenant_id !== 'string') return null
  return {
    tenant_id: r.tenant_id,
    tenant_name: typeof r.tenant_name === 'string' ? r.tenant_name : r.tenant_id,
    total_devices: typeof r.total_devices === 'number' ? r.total_devices : 0,
    compliant_devices: typeof r.compliant_devices === 'number' ? r.compliant_devices : 0,
    warning_devices: typeof r.warning_devices === 'number' ? r.warning_devices : 0,
    critical_devices: typeof r.critical_devices === 'number' ? r.critical_devices : 0,
    breached_devices: typeof r.breached_devices === 'number' ? r.breached_devices : 0,
  }
}

function parseComplianceSummary(body: unknown): ComplianceSummaryData {
  if (typeof body !== 'object' || body === null) {
    throw new Error('unexpected compliance summary response shape')
  }
  const r = body as Record<string, unknown>
  const byTenant: TenantComplianceStatus[] = []
  if (Array.isArray(r.by_tenant)) {
    for (const entry of r.by_tenant) {
      const t = parseTenantStatus(entry)
      if (t !== null) byTenant.push(t)
    }
  }
  return {
    total_devices: typeof r.total_devices === 'number' ? r.total_devices : 0,
    compliant_devices: typeof r.compliant_devices === 'number' ? r.compliant_devices : 0,
    warning_devices: typeof r.warning_devices === 'number' ? r.warning_devices : 0,
    critical_devices: typeof r.critical_devices === 'number' ? r.critical_devices : 0,
    breached_devices: typeof r.breached_devices === 'number' ? r.breached_devices : 0,
    by_tenant: byTenant,
    generated_at: typeof r.generated_at === 'string' ? r.generated_at : '',
  }
}

interface FetchState {
  key: string
  data?: ComplianceSummaryData
  error?: string
}

export function useComplianceSummary(): UseComplianceSummaryResult {
  const { scope, rootPath } = useTenantScope()
  const [attempt, setAttempt] = useState(0)
  const [state, setState] = useState<FetchState | null>(null)

  const retry = useCallback(() => setAttempt((n) => n + 1), [])

  const tenantId = scope !== rootPath ? scope : ''
  const key = `${tenantId}:${attempt}`

  useEffect(() => {
    let cancelled = false
    const params = new URLSearchParams()
    if (tenantId !== '') {
      params.set('tenant_id', tenantId)
    }
    const qs = params.size > 0 ? `?${params.toString()}` : ''
    const url = `/api/v1/compliance/summary${qs}`

    apiFetch(url)
      .then(async (r) => {
        if (!r.ok) {
          throw new Error(`GET /api/v1/compliance/summary — ${r.status}`)
        }
        return parseComplianceSummary((await r.json()) as unknown)
      })
      .then((data) => {
        if (cancelled) return
        setState({ key, data })
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setState({
          key,
          error:
            cause instanceof Error && cause.message
              ? cause.message
              : 'GET /api/v1/compliance/summary — request failed',
        })
      })

    return () => {
      cancelled = true
    }
  }, [key, tenantId])

  const current = state?.key === key ? state : null
  return {
    data: current?.data ?? null,
    loading: current === null,
    error: current?.error ?? null,
    retry,
  }
}
