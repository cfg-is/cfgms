// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Billing report screen (Issue #4650, ADR-025 Amendment 6 A6.1, A6.3).
 *
 * One screen over two endpoints that return the same shape. A caller whose
 * tenant scope is the root (empty rootPath) sees every MSP with its clients
 * under opaque labels; any other caller sees its own subtree with real client
 * names and the standing-disclosure note.
 *
 * Opaque labels are shown as plain text only — never a link, button, route
 * parameter, data-* attribute, URL or storage value. The expander toggles an
 * MSP row and is keyed by the MSP id, which is the tenant the root operator
 * already administers (an MSP name is not hidden from root).
 */
import { useState } from 'react'
import { useTenantScope } from '../shell/TenantScopeContext.tsx'
import { useBillingReport } from './useBillingReport.ts'
import type { BillingMetrics, RootMsp, TenantBillingReport } from './useBillingReport.ts'
import '../reports/ReportsDashboardView.css'
import './BillingReportView.css'

const PAGE_TITLE = 'Billing'
const DISCLOSURE = 'Root can see these same figures for your organization.'

function Tile({ label, value, sub }: { label: string; value: number; sub: string }) {
  return (
    <div className="rdb-tile">
      <span className="rdb-tile-label">{label}</span>
      <div className="rdb-tile-row">
        <span className="rdb-tile-value">{value}</span>
      </div>
      <span className="rdb-tile-sub">{sub}</span>
    </div>
  )
}

function CountGroup({ title, items }: { title: string; items: { name: string; count: number }[] }) {
  return (
    <div className="bill-metric-group">
      <h3>{title}</h3>
      <ul className="bill-metrics">
        {items.map((i) => (
          <li className="bill-chip" key={i.name}>
            {i.name}: {i.count}
          </li>
        ))}
      </ul>
    </div>
  )
}

function Metrics({ metrics }: { metrics: BillingMetrics }) {
  return (
    <section aria-label="Metrics">
      <CountGroup
        title="Status"
        items={[
          { name: 'Online', count: metrics.online },
          { name: 'Offline', count: metrics.offline },
          { name: 'Pending', count: metrics.pending },
        ]}
      />
      <CountGroup title="By platform" items={metrics.byPlatform} />
      {metrics.byVersion.length > 0 && <CountGroup title="By version" items={metrics.byVersion} />}
    </section>
  )
}

function Header() {
  return (
    <div className="rdb-header">
      <div>
        <h1>{PAGE_TITLE}</h1>
      </div>
    </div>
  )
}

function RootTable({ msps }: { msps: RootMsp[] }) {
  const [open, setOpen] = useState<Set<number>>(new Set())
  const toggle = (i: number) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (!next.delete(i)) next.add(i)
      return next
    })
  return (
    <div className="rdb-panel">
      <table className="bill-tbl">
        <thead>
          <tr>
            <th>MSP</th>
            <th className="num">Techs</th>
            <th className="num">Endpoints</th>
            <th className="num">Clients</th>
          </tr>
        </thead>
        <tbody>
          {msps.map((msp, i) => {
            const expanded = open.has(i)
            return [
              <tr key={`msp-${i}`}>
                <td>
                  <button
                    type="button"
                    className="bill-expander"
                    aria-expanded={expanded}
                    onClick={() => toggle(i)}
                  >
                    <span className="bill-chev" aria-hidden="true">▸</span>
                    {msp.name}
                  </button>
                </td>
                <td className="num">{msp.techCount}</td>
                <td className="num">{msp.endpointCount}</td>
                <td className="num">{msp.clientCount}</td>
              </tr>,
              ...(expanded
                ? [
                    <tr className="bill-detail" key={`metrics-${i}`}>
                      <td colSpan={4}>
                        <Metrics metrics={msp.metrics} />
                      </td>
                    </tr>,
                    ...msp.clients.map((c, j) => (
                      <tr className="bill-client" key={`client-${i}-${j}`}>
                        <td>Client {c.label}</td>
                        <td className="num">{c.techCount}</td>
                        <td className="num">{c.endpointCount}</td>
                        <td />
                      </tr>
                    )),
                  ]
                : []),
            ]
          })}
        </tbody>
      </table>
    </div>
  )
}

function RootView({ msps }: { msps: RootMsp[] }) {
  if (msps.length === 0) {
    return (
      <div className="rdb-content" data-testid="billing-empty">
        <Header />
        <div className="rdb-notice">
          <p>No MSPs to report.</p>
        </div>
      </div>
    )
  }
  const endpoints = msps.reduce((n, m) => n + m.endpointCount, 0)
  const techs = msps.reduce((n, m) => n + m.techCount, 0)
  return (
    <div className="rdb-content" data-testid="billing-root">
      <Header />
      <div className="rdb-kpis">
        <Tile label="MSPs" value={msps.length} sub="under root" />
        <Tile label="Total endpoints" value={endpoints} sub="across all MSPs" />
        <Tile label="Total techs" value={techs} sub="across all MSPs" />
      </div>
      <RootTable msps={msps} />
    </div>
  )
}

function TenantView({ report }: { report: TenantBillingReport }) {
  return (
    <div className="rdb-content" data-testid="billing-tenant">
      <Header />
      <p className="bill-disclosure" data-testid="billing-disclosure">{DISCLOSURE}</p>
      <div className="rdb-kpis">
        <Tile label="Clients" value={report.clientCount} sub="in your subtree" />
        <Tile label="Total endpoints" value={report.endpointCount} sub="in your subtree" />
        <Tile label="Total techs" value={report.techCount} sub="in your subtree" />
      </div>
      <div className="rdb-panel">
        <Metrics metrics={report.metrics} />
      </div>
      {report.clients.length === 0 ? (
        <div className="rdb-notice" data-testid="billing-empty">
          <p>No clients in this organization.</p>
        </div>
      ) : (
        <div className="rdb-panel">
          <table className="bill-tbl">
            <thead>
              <tr>
                <th>Client</th>
                <th className="num">Techs</th>
                <th className="num">Endpoints</th>
              </tr>
            </thead>
            <tbody>
              {report.clients.map((c, i) => (
                <tr key={`${c.id}-${i}`}>
                  <td>{c.name}</td>
                  <td className="num">{c.techCount}</td>
                  <td className="num">{c.endpointCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function BillingReportView() {
  const { rootPath } = useTenantScope()
  const root = rootPath === ''
  const { data, loading, error, retry } = useBillingReport(root, rootPath)

  if (loading) {
    return (
      <div className="rdb-content" data-testid="billing-loading">
        <Header />
        <div className="rdb-kpis">
          {[0, 1, 2].map((i) => (
            <div className="rdb-tile" key={i} aria-hidden="true">
              <span className="rdb-skel" style={{ height: '11px', width: '60%' }} />
              <span className="rdb-skel" style={{ height: '26px', width: '45%', marginTop: '6px' }} />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (error !== null) {
    return (
      <div className="rdb-content">
        <Header />
        <div className="rdb-notice err" role="alert">
          <div className="rdb-notice-body">
            <b>Could not load the billing report.</b>
            <p className="rdb-notice-sub">{error}</p>
            <button type="button" className="rdb-btn" onClick={retry}>
              Retry
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (data?.kind === 'root') return <RootView msps={data.msps} />
  if (data?.kind === 'tenant') return <TenantView report={data.report} />
  return null
}
