// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * CaseBar (Story #3608) — the sticky top bar of the cockpit shell.
 *
 * Displays the case number (ID), the primary asset (extracted from the first
 * eid pin), the tenant path (tenant_id rendered as "root / msp-a / client-1"),
 * and a status pill. Status maps to design-system semantic state tokens:
 *   open   → warn  (active, needs attention)
 *   closed → ok    (resolved)
 *
 * There is no separate "case number" integer in the Story 4 response — the ID
 * field is used directly. The asset EID label is the last segment of the first
 * eid pin's EID string (e.g. "eid:root/msp-a/client-1/sql-primary" → "sql-primary").
 * If no eid pin exists, the asset label is omitted.
 */
import type { Case } from './caseTypes.ts'
import type { Pin } from './evidenceTypes.ts'

interface CaseBarProps {
  caseData: Case
}

function extractAsset(pins: Pin[]): string | null {
  const eidPin = pins.find((p) => p.ref.kind === 'eid' && p.ref.eid)
  if (!eidPin?.ref.eid) return null
  const parts = eidPin.ref.eid.split('/')
  return parts[parts.length - 1] ?? null
}

function formatTenantPath(tenantId: string): string {
  return tenantId.split('/').join(' / ')
}

function statusPillClass(status: string): string {
  switch (status) {
    case 'open':
      return 'pill pill--warn'
    case 'closed':
      return 'pill pill--ok'
    default:
      return 'pill pill--neu'
  }
}

export default function CaseBar({ caseData }: CaseBarProps) {
  const asset = extractAsset(caseData.pins)
  const tenantPath = formatTenantPath(caseData.tenant_id)

  return (
    <div className="cbar">
      <div className="cid">
        <span className="cid__num">CASE {caseData.id}</span>
        {asset && <span className="cid__asset">{asset}</span>}
        <span className="cid__path">{tenantPath}</span>
      </div>
      <span className={statusPillClass(caseData.status)}>
        <span className="pill__dot" aria-hidden="true" />
        {caseData.status === 'open' ? 'Open' : caseData.status === 'closed' ? 'Closed' : caseData.status}
      </span>
    </div>
  )
}
