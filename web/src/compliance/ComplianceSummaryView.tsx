// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Compliance summary view (Story #3272) — fleet-wide drift posture from
 * GET /api/v1/compliance/summary.
 *
 * Four data states: Loading (skeleton), Error (notice + retry), Empty
 * (zero devices), Ready (hero + stat tiles + sortable per-tenant table).
 *
 * Labelling: this screen measures observed drift from DNA snapshot history,
 * NOT convergence verdicts. A steward that never reports is NOT counted as
 * clean. The hero note makes this limitation explicit (founder ruling).
 *
 * Palette: state pills use --state-ok/warn/crit/neutral tokens; no hardcoded
 * colour values.
 */

import { useState } from 'react'
import { useComplianceSummary } from './useComplianceSummary.ts'
import type { TenantComplianceStatus } from './useComplianceSummary.ts'
import './ComplianceSummaryView.css'

// ── Icons ──────────────────────────────────────────────────────────────────

function CritIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.8v4" />
      <path d="M8 11.2v.05" />
    </svg>
  )
}

function OkIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.1"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 8.5l3.2 3.2L13 5" />
    </svg>
  )
}

// ── Sort state ─────────────────────────────────────────────────────────────

type SortKey = keyof Pick<
  TenantComplianceStatus,
  | 'tenant_id'
  | 'total_devices'
  | 'compliant_devices'
  | 'warning_devices'
  | 'critical_devices'
  | 'breached_devices'
>

interface SortState {
  key: SortKey
  direction: 1 | -1
}

function sortRows(rows: TenantComplianceStatus[], sort: SortState): TenantComplianceStatus[] {
  return [...rows].sort((a, b) => {
    const av = a[sort.key]
    const bv = b[sort.key]
    if (typeof av === 'string' && typeof bv === 'string') {
      return sort.direction * av.localeCompare(bv)
    }
    return sort.direction * ((av as number) - (bv as number))
  })
}

// ── Column header with sort affordance ────────────────────────────────────

function SortableTh({
  label,
  sortKey,
  sort,
  onSort,
  align = 'left',
}: {
  label: string
  sortKey: SortKey
  sort: SortState
  onSort: (key: SortKey) => void
  align?: 'left' | 'right'
}) {
  const active = sort.key === sortKey
  const indicator = active ? (sort.direction === 1 ? ' ↑' : ' ↓') : ''
  return (
    <th
      className={`cs-th${align === 'right' ? ' cs-th-num' : ''}`}
      aria-sort={active ? (sort.direction === 1 ? 'ascending' : 'descending') : 'none'}
      data-testid={`sort-${sortKey}`}
      onClick={() => onSort(sortKey)}
      style={{ cursor: 'pointer', userSelect: 'none' }}
    >
      {label}
      {indicator && <span className="cs-sort-ind" aria-hidden="true">{indicator}</span>}
    </th>
  )
}

// ── Page header ────────────────────────────────────────────────────────────

function PageHeader() {
  return (
    <div className="cs-header">
      <div>
        <h1>Compliance</h1>
        <p>Observed drift across the fleet, from DNA snapshot history.</p>
      </div>
    </div>
  )
}

// ── Main view ──────────────────────────────────────────────────────────────

export default function ComplianceSummaryView() {
  const { data, loading, error, retry } = useComplianceSummary()
  const [sort, setSort] = useState<SortState>({ key: 'total_devices', direction: -1 })

  function handleSort(key: SortKey) {
    setSort((prev) =>
      prev.key === key
        ? { key, direction: prev.direction === 1 ? -1 : 1 }
        : { key, direction: -1 },
    )
  }

  // Loading
  if (loading) {
    return (
      <div className="cs-content" data-testid="compliance-loading">
        <PageHeader />
        <div className="cs-kpis">
          {[0, 1, 2, 3, 4].map((i) => (
            <div className="cs-tile" key={i} aria-hidden="true">
              <span className="cs-skel" style={{ height: '11px', width: '60%' }} />
              <span className="cs-skel" style={{ height: '26px', width: '45%', marginTop: '6px' }} />
            </div>
          ))}
        </div>
        <div className="cs-panel" aria-hidden="true">
          <span className="cs-skel" style={{ height: '13px', width: '200px', display: 'block' }} />
          {[0, 1, 2, 3].map((i) => (
            <span
              key={i}
              className="cs-skel"
              style={{ height: '34px', marginTop: '10px', display: 'block' }}
            />
          ))}
        </div>
      </div>
    )
  }

  // Error
  if (error !== null) {
    return (
      <div className="cs-content">
        <PageHeader />
        <div className="cs-notice err" role="alert">
          <CritIcon />
          <div className="cs-notice-body">
            <b>Could not load the compliance summary.</b>
            <p className="cs-notice-sub">
              The controller returned an error. No compliance figure is shown rather than a stale
              or partial one.
            </p>
            <p className="cs-notice-sub">{error}</p>
            <button type="button" className="cs-btn" onClick={retry}>
              Retry
            </button>
          </div>
        </div>
      </div>
    )
  }

  // Empty
  if (!data || data.total_devices === 0) {
    return (
      <div className="cs-content">
        <PageHeader />
        <div className="cs-notice" data-testid="compliance-empty">
          <p>No devices in scope.</p>
          <p className="cs-notice-np">
            No stewards are enrolled in this scope. Enrol a steward to see drift posture.
          </p>
        </div>
      </div>
    )
  }

  // Ready
  const pct = ((data.compliant_devices / data.total_devices) * 100).toFixed(1)
  const sorted = sortRows(data.by_tenant, sort)

  return (
    <div className="cs-content" data-testid="compliance-ready">
      <PageHeader />

      {/* Hero */}
      <div className="cs-panel">
        <div className="cs-hero-wrap">
          <div>
            <span className="cs-hero-label">No drift observed</span>
            <div className="cs-hero" data-testid="compliance-hero-pct">
              {pct}%
            </div>
          </div>
          <div className="cs-hero-side">
            <span className="cs-pill ok" data-testid="compliance-hero-pill">
              <OkIcon />
              {data.compliant_devices.toLocaleString()} of {data.total_devices.toLocaleString()}{' '}
              devices
            </span>
          </div>
          <p className="cs-hero-note">
            Computed by comparing consecutive DNA snapshots. This measures{' '}
            <b>observed change</b>, not a convergence verdict — a steward that never reports is
            not counted as clean.
          </p>
        </div>
      </div>

      {/* KPI tiles */}
      <div className="cs-kpis" data-testid="compliance-kpi-tiles">
        <div className="cs-tile" data-testid="kpi-total">
          <span className="cs-tile-label">Total devices</span>
          <div className="cs-tile-row">
            <span className="cs-tile-value">{data.total_devices.toLocaleString()}</span>
          </div>
        </div>

        <div className="cs-tile" data-testid="kpi-compliant">
          <span className="cs-tile-label">No drift observed</span>
          <div className="cs-tile-row">
            <span className="cs-tile-value">{data.compliant_devices.toLocaleString()}</span>
          </div>
          <span className="cs-tile-sub">unchanged since last snapshot</span>
        </div>

        <div className="cs-tile" data-testid="kpi-warning">
          <span className="cs-tile-label">Drift observed</span>
          <div className="cs-tile-row">
            <span className="cs-tile-value cs-val-warn">{data.warning_devices.toLocaleString()}</span>
          </div>
          <span className="cs-tile-sub">attributes changed</span>
        </div>

        <div className="cs-tile" data-testid="kpi-critical">
          <span className="cs-tile-label">Critical drift</span>
          <div className="cs-tile-row">
            <span className="cs-tile-value cs-val-crit">{data.critical_devices.toLocaleString()}</span>
          </div>
          <span className="cs-tile-sub">critical-severity change</span>
        </div>

        <div className="cs-tile" data-testid="kpi-breached">
          <span className="cs-tile-label">Breached</span>
          <div className="cs-tile-row">
            <span className="cs-tile-value cs-val-neutral">{data.breached_devices.toLocaleString()}</span>
          </div>
          <span className="cs-tile-sub">past policy deadline</span>
        </div>
      </div>

      {/* Per-tenant breakdown */}
      <div className="cs-panel">
        <div className="cs-table-head">
          <div>
            <h2>By tenant</h2>
            <p className="cs-panel-sub">Drift mix per tenant</p>
          </div>
          <div className="cs-legend">
            <span className="cs-legend-key">
              <span className="cs-swatch ok" />
              No drift
            </span>
            <span className="cs-legend-key">
              <span className="cs-swatch warn" />
              Drift
            </span>
            <span className="cs-legend-key">
              <span className="cs-swatch crit" />
              Critical
            </span>
            <span className="cs-legend-key">
              <span className="cs-swatch neutral" />
              Breached
            </span>
          </div>
        </div>

        {sorted.length === 0 ? (
          <div className="cs-notice" data-testid="tenant-table-empty">
            <p>No tenant breakdown available.</p>
          </div>
        ) : (
          <table className="cs-tbl" data-testid="tenant-table">
            <thead>
              <tr>
                <SortableTh label="Tenant" sortKey="tenant_id" sort={sort} onSort={handleSort} />
                <SortableTh
                  label="Devices"
                  sortKey="total_devices"
                  sort={sort}
                  onSort={handleSort}
                  align="right"
                />
                <SortableTh
                  label="No drift"
                  sortKey="compliant_devices"
                  sort={sort}
                  onSort={handleSort}
                  align="right"
                />
                <SortableTh
                  label="Drift"
                  sortKey="warning_devices"
                  sort={sort}
                  onSort={handleSort}
                  align="right"
                />
                <SortableTh
                  label="Critical"
                  sortKey="critical_devices"
                  sort={sort}
                  onSort={handleSort}
                  align="right"
                />
                <SortableTh
                  label="Breached"
                  sortKey="breached_devices"
                  sort={sort}
                  onSort={handleSort}
                  align="right"
                />
              </tr>
            </thead>
            <tbody>
              {sorted.map((tenant) => (
                <tr key={tenant.tenant_id} data-testid="tenant-row">
                  <td className="cs-td-tenant">{tenant.tenant_id}</td>
                  <td className="cs-td-num">{tenant.total_devices}</td>
                  <td className="cs-td-num">{tenant.compliant_devices}</td>
                  <td className="cs-td-num">{tenant.warning_devices}</td>
                  <td className="cs-td-num">{tenant.critical_devices}</td>
                  <td className="cs-td-num">{tenant.breached_devices}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
