// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Tenant admin tree view (Issue #3131, ADR-025, ADR-027).
 *
 * Renders the tenant hierarchy from the flat GET /api/v1/tenants response.
 * Tree structure is built client-side from parent_id relationships.
 *
 * ADR-025: a root-scoped session (Principal.rootScope === true) with no
 * visible tenant children beyond the root tenant renders a boundary/empty
 * state — the API already silently omits tenants for which the caller lacks
 * an active grant or break-glass crossing, so a sparse tree here means the
 * boundary is enforced.
 *
 * ADR-027:
 * - Suspend cascades to the entire subtree; the label changes to
 *   "Suspend subtree" when a tenant has children.
 * - Suspended rows show direct vs. cascade-from-ancestor provenance.
 * - Restoring an ancestor does not lift an independently-suspended
 *   descendant's own suspension (server-enforced; the UI reflects the
 *   updated provenance returned by the API).
 * - Request delete rejects (with a named offending descendant) when the
 *   subtree is not fully suspended.
 * - Hold state shows elapsed/remaining countdown; eligible state shows
 *   the distinct approve action locked for the original requester (dual-
 *   control, config default: on). `pending_deletion.requested_by` is a
 *   server-side principal ID (a web-account UUID or an mTLS certificate CN),
 *   which the browser session never holds — so the lock is driven by the two
 *   signals that ARE in that domain: this session having requested the
 *   deletion, and the controller answering an approval with 403 SAME_APPROVER.
 *   See dualControlLockedIds below.
 *
 * Security A9.1: tenant name/description values render as JSX text nodes
 * only — never via dangerouslySetInnerHTML, consistent with AccountsView.
 */
import { useState, useMemo, useSyncExternalStore } from 'react'
import {
  useTenantList,
  suspendTenant,
  restoreTenant,
  createTenant,
  updateTenant,
  requestTenantDeletion,
  cancelTenantDeletion,
  approveTenantDeletion,
  errCodeSameApprover,
  TenantApiError,
  type TenantInfo,
} from './useTenants.ts'
import { useAuth } from '../auth/AuthContext.tsx'

// ── Tree building ──────────────────────────────────────────────────────────────

interface TreeNode {
  tenant: TenantInfo
  children: TreeNode[]
  depth: number
}

function buildTree(tenants: TenantInfo[]): TreeNode[] {
  const byId = new Map<string, TenantInfo>()
  for (const t of tenants) byId.set(t.id, t)

  const childrenMap = new Map<string, TenantInfo[]>()
  const roots: TenantInfo[] = []

  for (const t of tenants) {
    if (!t.parent_id || !byId.has(t.parent_id)) {
      roots.push(t)
    } else {
      const siblings = childrenMap.get(t.parent_id) ?? []
      siblings.push(t)
      childrenMap.set(t.parent_id, siblings)
    }
  }

  function buildNode(tenant: TenantInfo, depth: number): TreeNode {
    const kids = childrenMap.get(tenant.id) ?? []
    return {
      tenant,
      depth,
      children: kids.map((c) => buildNode(c, depth + 1)),
    }
  }

  return roots.map((r) => buildNode(r, 0))
}

function flattenTree(nodes: TreeNode[]): TreeNode[] {
  const out: TreeNode[] = []
  function walk(node: TreeNode) {
    out.push(node)
    for (const child of node.children) walk(child)
  }
  for (const root of nodes) walk(root)
  return out
}

// ── Suspension helpers ─────────────────────────────────────────────────────────

function isSuspended(t: TenantInfo): boolean {
  return t.status === 'suspended' || t.directly_suspended || t.cascade_suspended_from !== null
}

// ── Hold countdown display ─────────────────────────────────────────────────────

/*
 * Minute-resolution wall clock, modelled as an external store rather than a
 * render-time `Date.now()` (impure render) or a `setState` clock effect
 * (cascading renders). `clockNowMs` only moves on a tick or on subscribe, so the
 * snapshot useSyncExternalStore reads stays stable between notifications.
 */
let clockNowMs = Date.now()
const clockListeners = new Set<() => void>()
let clockTimer: number | null = null

function subscribeToClock(onChange: () => void): () => void {
  // Re-sample on subscribe: the module may have been imported long before this
  // view mounted. useSyncExternalStore re-reads the snapshot after subscribing,
  // so a value that moved here still reaches the first committed render.
  clockNowMs = Date.now()
  clockListeners.add(onChange)
  if (clockTimer === null) {
    clockTimer = window.setInterval(() => {
      clockNowMs = Date.now()
      for (const listener of clockListeners) listener()
    }, 60_000)
  }
  return () => {
    clockListeners.delete(onChange)
    if (clockListeners.size === 0 && clockTimer !== null) {
      window.clearInterval(clockTimer)
      clockTimer = null
    }
  }
}

function clockSnapshot(): number {
  return clockNowMs
}

function formatDuration(ms: number): string {
  if (ms <= 0) return '0m'
  const d = Math.floor(ms / 86400000)
  const h = Math.floor((ms % 86400000) / 3600000)
  const m = Math.floor((ms % 3600000) / 60000)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

// ── Loading skeleton ───────────────────────────────────────────────────────────

function LoadingRows() {
  return (
    <div data-testid="tenants-loading" aria-label="Loading tenants">
      {Array.from({ length: 4 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '35%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '15%' }} />
          <span className="skel" style={{ width: '25%' }} />
        </div>
      ))}
    </div>
  )
}

// ── Error notice ──────────────────────────────────────────────────────────────

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert" data-testid="tenants-error">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load tenants</h3>
      <p>The tenant list request failed. Check your connection and try again.</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry} data-testid="tenants-retry-btn">
        Retry
      </button>
    </div>
  )
}

// ── Boundary empty state (ADR-025) ────────────────────────────────────────────

function BoundaryEmptyState() {
  return (
    <div className="notice empty" data-testid="boundary-empty-state">
      <div className="ic">🔒</div>
      <h3>No default access into MSP tenants</h3>
      <p>
        Per ADR-025, a root-scoped session has no standing visibility into an MSP&apos;s
        subtree. The tenant tree is restricted until an MSP grants support access from
        inside their own tenant, or a time-boxed, justified break-glass session is
        invoked — both are logged and visible to the MSP.
      </p>
      <p style={{ fontSize: '0.875rem', color: 'var(--color-muted)' }}>
        Preferred path: ask the MSP to enable support access from their own tenant.
        Break-glass invocation is a separate, out-of-scope action.
      </p>
    </div>
  )
}

// ── Create form ────────────────────────────────────────────────────────────────

interface CreateFormState {
  name: string
  description: string
  parent_id: string
}

function defaultCreateForm(parentId?: string): CreateFormState {
  return { name: '', description: '', parent_id: parentId ?? '' }
}

function CreateTenantPanel({
  tenants,
  onSaved,
  onClose,
}: {
  tenants: TenantInfo[]
  onSaved: () => void
  onClose: () => void
}) {
  const [form, setForm] = useState<CreateFormState>(defaultCreateForm)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  function set<K extends keyof CreateFormState>(key: K, value: CreateFormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  async function handleSubmit() {
    if (!form.name.trim()) {
      setSaveError('Tenant name is required')
      return
    }
    setSaving(true)
    setSaveError(null)
    try {
      await createTenant({
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        parent_id: form.parent_id.trim() || undefined,
      })
      onSaved()
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Create failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form-panel" data-testid="create-tenant-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Name *</span>
            <input
              type="text"
              aria-label="Tenant name"
              placeholder="client-1"
              value={form.name}
              onChange={(e) => set('name', e.target.value)}
              data-testid="tenant-name-input"
            />
          </div>
          <div className="wf-form-field">
            <span className="wf-form-label">Parent tenant</span>
            <select
              aria-label="Parent tenant"
              value={form.parent_id}
              onChange={(e) => set('parent_id', e.target.value)}
              data-testid="tenant-parent-select"
            >
              <option value="">— none (top level) —</option>
              {tenants
                .filter((t) => t.status !== 'deleted')
                .map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.id})
                  </option>
                ))}
            </select>
          </div>
        </div>
        <div className="wf-form-row">
          <div className="wf-form-field" style={{ flexGrow: 1 }}>
            <span className="wf-form-label">Description</span>
            <input
              type="text"
              aria-label="Description"
              placeholder="Optional description"
              value={form.description}
              onChange={(e) => set('description', e.target.value)}
              data-testid="tenant-description-input"
            />
          </div>
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={() => void handleSubmit()}
            data-testid="tenant-save-btn"
          >
            {saving ? 'Creating…' : 'Create tenant'}
          </button>
          <button type="button" className="wf-btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="tenant-save-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Edit form ──────────────────────────────────────────────────────────────────

function EditTenantPanel({
  tenant,
  onSaved,
  onClose,
}: {
  tenant: TenantInfo
  onSaved: () => void
  onClose: () => void
}) {
  const [name, setName] = useState(tenant.name)
  const [description, setDescription] = useState(tenant.description)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!name.trim()) {
      setSaveError('Tenant name is required')
      return
    }
    setSaving(true)
    setSaveError(null)
    try {
      await updateTenant(tenant.id, { name: name.trim(), description: description.trim() })
      onSaved()
    } catch (cause: unknown) {
      setSaveError(cause instanceof Error && cause.message ? cause.message : 'Update failed')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="wf-form-panel" data-testid="edit-tenant-panel">
      <div className="wf-form">
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">
              Editing <b>{tenant.name}</b>
            </span>
          </div>
        </div>
        <div className="wf-form-row">
          <div className="wf-form-field">
            <span className="wf-form-label">Name *</span>
            <input
              type="text"
              aria-label="Tenant name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="edit-tenant-name-input"
            />
          </div>
          <div className="wf-form-field" style={{ flexGrow: 1 }}>
            <span className="wf-form-label">Description</span>
            <input
              type="text"
              aria-label="Description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="edit-tenant-description-input"
            />
          </div>
        </div>
        <div className="wf-form-actions">
          <button
            type="button"
            className="wf-btn"
            disabled={saving}
            onClick={() => void handleSubmit()}
            data-testid="edit-save-btn"
          >
            {saving ? 'Saving…' : 'Save changes'}
          </button>
          <button type="button" className="wf-btn-secondary" onClick={onClose}>
            Cancel
          </button>
          {saveError && (
            <span className="wf-form-error" data-testid="edit-save-error">
              {saveError}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Tenant row ─────────────────────────────────────────────────────────────────

function TenantRow({
  node,
  dualControlLocked,
  nowMs,
  onSuspend,
  onRestore,
  onRequestDelete,
  onCancelDelete,
  onApproveDelete,
  onEdit,
}: {
  node: TreeNode
  dualControlLocked: boolean
  /** Countdown reference time, read from the shared minute clock by the parent. */
  nowMs: number
  onSuspend: (id: string) => void
  onRestore: (id: string) => void
  onRequestDelete: (id: string) => void
  onCancelDelete: (id: string) => void
  onApproveDelete: (id: string) => void
  onEdit: (tenant: TenantInfo) => void
}) {
  const { tenant, depth, children } = node
  const suspended = isSuspended(tenant)
  const hasPending = !!tenant.pending_deletion
  const del = tenant.pending_deletion

  // Build provenance labels
  const provenanceParts: string[] = []
  if (tenant.directly_suspended) provenanceParts.push('Direct')
  if (tenant.cascade_suspended_from) provenanceParts.push(`Cascade from ${tenant.cascade_suspended_from}`)

  // Hold countdown, measured against the shared clock store (see above) — a
  // render-time Date.now() would make this render impure (react-hooks/purity)
  // and would freeze the countdown until the next refetch.
  const holdMsRemaining = del?.state === 'hold' && del.eligible_at
    ? new Date(del.eligible_at).getTime() - nowMs
    : 0

  const isLastRow = children.length === 0

  return (
    <>
      <tr data-testid="tenant-row" data-tenant-id={tenant.id}>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span
              style={{ width: depth * 18, flexShrink: 0, display: 'inline-block' }}
              aria-hidden="true"
            />
            <div>
              <span className="nm" data-testid="tenant-name">{tenant.name}</span>
              {tenant.id !== tenant.name && (
                <span className="mono2" style={{ marginLeft: 6, fontSize: '0.75rem', color: 'var(--color-muted)' }}>
                  {tenant.id}
                </span>
              )}
            </div>
          </div>
        </td>
        <td>
          {hasPending && del ? (
            <>
              {del.state === 'hold' && (
                <span className="chip" data-testid="delete-hold-badge" style={{ background: 'var(--color-warn-bg)', color: 'var(--color-warn)' }}>
                  Delete: Hold
                </span>
              )}
              {del.state === 'eligible' && (
                <span className="chip" data-testid="delete-eligible-badge" style={{ background: 'var(--color-crit-bg)', color: 'var(--color-crit)' }}>
                  Delete: Eligible
                </span>
              )}
            </>
          ) : suspended ? (
            <div>
              <span className="chip" data-testid="suspended-badge">Suspended</span>
              {provenanceParts.length > 0 && (
                <div style={{ fontSize: '0.7rem', color: 'var(--color-muted)', marginTop: 2 }} data-testid="suspension-provenance">
                  {provenanceParts.join(' + ')}
                </div>
              )}
            </div>
          ) : (
            <span className="chip chip-ok" data-testid="active-badge">Active</span>
          )}
        </td>
        <td onClick={(e) => e.stopPropagation()}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {hasPending && del?.state === 'hold' ? (
              <button
                type="button"
                className="wf-btn-secondary"
                onClick={() => onCancelDelete(tenant.id)}
                data-testid="cancel-delete-btn"
              >
                Cancel delete
              </button>
            ) : hasPending && del?.state === 'eligible' ? (
              <>
                <button
                  type="button"
                  className="wf-btn-danger"
                  onClick={() => onApproveDelete(tenant.id)}
                  disabled={dualControlLocked}
                  title={
                    dualControlLocked
                      ? 'You requested this deletion — a different principal must approve'
                      : undefined
                  }
                  data-testid="approve-delete-btn"
                >
                  Approve deletion
                </button>
                <button
                  type="button"
                  className="wf-btn-secondary"
                  onClick={() => onCancelDelete(tenant.id)}
                  data-testid="deny-delete-btn"
                >
                  Deny
                </button>
              </>
            ) : suspended ? (
              <>
                <button
                  type="button"
                  className="wf-btn-secondary"
                  onClick={() => onRestore(tenant.id)}
                  data-testid="restore-btn"
                >
                  Restore{children.length > 0 ? ' subtree' : ''}
                </button>
                <button
                  type="button"
                  className="wf-btn-secondary"
                  onClick={() => onRequestDelete(tenant.id)}
                  data-testid="request-delete-btn"
                >
                  Request delete
                </button>
              </>
            ) : (
              <button
                type="button"
                className="wf-btn-secondary"
                onClick={() => onSuspend(tenant.id)}
                data-testid="suspend-btn"
              >
                Suspend{children.length > 0 ? ' subtree' : ''}
              </button>
            )}
            <button
              type="button"
              className="wf-btn-secondary"
              onClick={() => onEdit(tenant)}
              data-testid="edit-btn"
            >
              Edit
            </button>
          </div>
        </td>
      </tr>

      {/* Sub-row: hold countdown or eligible detail */}
      {hasPending && del && (
        <tr data-testid="delete-pipeline-subrow" className={isLastRow ? 'lastrow' : ''}>
          <td colSpan={3} style={{ paddingTop: 0 }}>
            <div style={{ padding: '6px 10px 10px', background: 'var(--color-sunk, var(--bg-sunk))', borderRadius: 8, margin: '0 0 4px' }}>
              {del.state === 'hold' && (
                <div data-testid="hold-card" style={{ fontSize: '0.8rem', color: 'var(--color-warn, var(--state-warn))' }}>
                  Deletion requested by <b>{del.requested_by}</b> on{' '}
                  {new Date(del.requested_at).toLocaleDateString()}. Eligible in{' '}
                  <b data-testid="hold-countdown">{formatDuration(holdMsRemaining)}</b>
                </div>
              )}
              {del.state === 'eligible' && (
                <div data-testid="eligible-card" style={{ fontSize: '0.8rem', color: 'var(--color-crit, var(--state-crit))' }}>
                  Hold period elapsed — ready for terminal delete. Requested by{' '}
                  <b>{del.requested_by}</b> on{' '}
                  {new Date(del.requested_at).toLocaleDateString()}.
                  {dualControlLocked ? (
                    <span style={{ marginLeft: 8, color: 'var(--color-muted)' }} data-testid="dual-control-lock-notice">
                      (You requested this — a different principal must approve.)
                    </span>
                  ) : (
                    <span style={{ marginLeft: 8, color: 'var(--color-muted)' }} data-testid="dual-control-hint">
                      (Dual control: the approver must differ from the requester.)
                    </span>
                  )}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Main view ──────────────────────────────────────────────────────────────────

export default function TenantAdminView() {
  const { principal } = useAuth()
  const { tenants, loading, error, retry } = useTenantList()
  const [showCreate, setShowCreate] = useState(false)
  const [editingTenant, setEditingTenant] = useState<TenantInfo | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionInProgress, setActionInProgress] = useState<string | null>(null)
  // Subtree roots whose deletion this operator may not approve (ADR-027
  // Decision 4). Two in-domain signals populate it — requesting the deletion
  // from this session, and the controller refusing an approval with 403
  // SAME_APPROVER. Comparing `requested_by` (a server principal ID) against
  // `principal.username` would be a cross-domain comparison that never matches,
  // leaving the lock permanently disengaged.
  const [dualControlLockedIds, setDualControlLockedIds] = useState<ReadonlySet<string>>(
    () => new Set<string>(),
  )
  // Clock for the hold countdowns, re-read every minute so a row approaching
  // eligibility updates without a refetch.
  const nowMs = useSyncExternalStore(subscribeToClock, clockSnapshot)

  const treeNodes = useMemo(() => buildTree(tenants), [tenants])
  const flatNodes = useMemo(() => flattenTree(treeNodes), [treeNodes])

  // ADR-025: root-scoped session without accessible MSP subtrees → boundary state.
  // The API silently omits tenants the root-scoped caller lacks a crossing for,
  // so a list containing only the root (or nothing) signals the boundary.
  const isRootScoped = principal?.rootScope === true
  const hasAccessibleChildren = tenants.some((t) => t.parent_id !== '')
  const showBoundaryState = isRootScoped && !hasAccessibleChildren && !loading && error === null

  function lockDualControl(id: string) {
    setDualControlLockedIds((prev) => {
      if (prev.has(id)) return prev
      const next = new Set(prev)
      next.add(id)
      return next
    })
  }

  function clearDualControlLock(id: string) {
    setDualControlLockedIds((prev) => {
      if (!prev.has(id)) return prev
      const next = new Set(prev)
      next.delete(id)
      return next
    })
  }

  async function handleSuspend(id: string) {
    setActionError(null)
    setActionInProgress(id)
    try {
      await suspendTenant(id)
      retry()
    } catch (cause: unknown) {
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Suspend failed')
    } finally {
      setActionInProgress(null)
    }
  }

  async function handleRestore(id: string) {
    setActionError(null)
    setActionInProgress(id)
    try {
      await restoreTenant(id)
      retry()
    } catch (cause: unknown) {
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Restore failed')
    } finally {
      setActionInProgress(null)
    }
  }

  async function handleRequestDelete(id: string) {
    setActionError(null)
    setActionInProgress(id)
    try {
      await requestTenantDeletion(id)
      // This session is the requester, so the dual-control rule bars it from
      // approving this subtree — lock the approve action before the pipeline
      // ever reaches Eligible.
      lockDualControl(id)
      retry()
    } catch (cause: unknown) {
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Request deletion failed')
    } finally {
      setActionInProgress(null)
    }
  }

  async function handleCancelDelete(id: string) {
    setActionError(null)
    setActionInProgress(id)
    try {
      await cancelTenantDeletion(id)
      // The pipeline entry is gone; a future request may come from anyone.
      clearDualControlLock(id)
      retry()
    } catch (cause: unknown) {
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Cancel deletion failed')
    } finally {
      setActionInProgress(null)
    }
  }

  async function handleApproveDelete(id: string) {
    setActionError(null)
    setActionInProgress(id)
    try {
      await approveTenantDeletion(id)
      retry()
    } catch (cause: unknown) {
      // The controller is the authority on dual control: a SAME_APPROVER
      // refusal means this session requested the deletion (in an earlier
      // session, typically — the hold period spans days), so lock the action
      // and show the notice instead of offering a button that can only fail.
      if (cause instanceof TenantApiError && cause.code === errCodeSameApprover) {
        lockDualControl(id)
      }
      setActionError(cause instanceof Error && cause.message ? cause.message : 'Approve deletion failed')
    } finally {
      setActionInProgress(null)
    }
  }

  function handleCreateSaved() {
    setShowCreate(false)
    retry()
  }

  function handleEditSaved() {
    setEditingTenant(null)
    retry()
  }

  return (
    <>
      <div className="htitle">
        <h1>Tenants</h1>
        <p>Tenant hierarchy, cascade suspension, and the delete pipeline.</p>
      </div>

      <section className="panel">
        <div className="ptool">
          {!showBoundaryState && (
            <button
              type="button"
              className={showCreate ? 'wf-btn' : 'wf-btn-secondary'}
              onClick={() => {
                setEditingTenant(null)
                setShowCreate((v) => !v)
              }}
              data-testid="toggle-create-btn"
            >
              {showCreate ? 'Close' : '+ New tenant'}
            </button>
          )}
          {!loading && error === null && !showBoundaryState && (
            <span className="cnt" data-testid="tenant-count">
              {tenants.length} tenant{tenants.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {showCreate && (
          <CreateTenantPanel
            tenants={tenants}
            onSaved={handleCreateSaved}
            onClose={() => setShowCreate(false)}
          />
        )}

        {editingTenant !== null && (
          <EditTenantPanel
            key={editingTenant.id}
            tenant={editingTenant}
            onSaved={handleEditSaved}
            onClose={() => setEditingTenant(null)}
          />
        )}

        {actionError && (
          <div className="wf-form-error" style={{ padding: '8px 14px' }} role="alert" data-testid="action-error">
            {actionError}
          </div>
        )}

        {actionInProgress !== null && (
          <div style={{ padding: '6px 14px', color: 'var(--color-muted)', fontSize: '0.85rem' }} data-testid="action-in-progress">
            Working…
          </div>
        )}

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorNotice detail={error} onRetry={retry} />
        ) : showBoundaryState ? (
          <BoundaryEmptyState />
        ) : tenants.length === 0 ? (
          <div className="notice empty" data-testid="tenants-empty">
            <div className="ic">◍</div>
            <h3>No tenants found</h3>
            <p>No tenants have been created yet. Use New tenant to get started.</p>
          </div>
        ) : (
          <table className="tbl" data-testid="tenants-table">
            <thead>
              <tr>
                <th>Tenant</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {flatNodes.map((node) => (
                <TenantRow
                  key={node.tenant.id}
                  node={node}
                  dualControlLocked={dualControlLockedIds.has(node.tenant.id)}
                  nowMs={nowMs}
                  onSuspend={handleSuspend}
                  onRestore={handleRestore}
                  onRequestDelete={handleRequestDelete}
                  onCancelDelete={handleCancelDelete}
                  onApproveDelete={handleApproveDelete}
                  onEdit={setEditingTenant}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  )
}
