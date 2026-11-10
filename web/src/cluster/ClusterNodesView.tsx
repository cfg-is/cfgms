// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Cluster nodes page (Issue #5462, Epic #5300) — the /cluster route.
 * Lists the controller cluster's nodes (GET /api/v1/ha/nodes) and drains
 * (POST /api/v1/cluster/nodes/{id}/drain) or decommissions
 * (POST .../decommission) one. Layout follows certificates/CertificatesView.tsx:
 * one `tbl` table with per-row buttons and a type-to-confirm modal, here with the
 * node id as the text to type.
 *
 * Both actions take a Strong step-up and a presence tap, handled transparently by
 * the apiFetch interceptor and StepUpModal; this view never sees or sends a
 * presence token.
 *
 * Status: the nodes endpoint reports health, not membership state, so the Status
 * pill reflects what this session did to a node (Active until drained, then
 * Draining, then Decommissioned). The server stays the authority: it answers 409 to
 * an out-of-order action and the view shows its reason.
 *
 * Local node: the node serving this console (GET /api/v1/ha/status) is tagged.
 * When the server refuses an action on it with 403, both of its actions render
 * disabled with the server's reason, so the console is not left offering an action
 * the controller will not take.
 *
 * Security A9.1: all wire values render as JSX text, never as HTML.
 */
import { useState } from 'react'
import ErrorCard from '../shell/ErrorCard.tsx'
import {
  ClusterActionError,
  decommissionClusterNode,
  drainClusterNode,
  useClusterNodes,
  type ClusterNode,
  type NodeHealth,
} from './useClusterNodes.ts'

type Lifecycle = 'draining' | 'decommissioned'

const healthPill: Record<NodeHealth, string> = {
  healthy: 'ok',
  degraded: 'warn',
  failed: 'crit',
  offline: 'crit',
  unknown: 'neutral',
}

const lifecyclePill: Record<Lifecycle | 'active', { cls: string; label: string }> = {
  active: { cls: 'ok', label: 'Active' },
  draining: { cls: 'warn', label: 'Draining' },
  decommissioned: { cls: 'neutral', label: 'Decommissioned' },
}

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function isRefusal(cause: unknown): boolean {
  return cause instanceof ClusterActionError && cause.status === 403
}

function NodeRow({
  node,
  isLocal,
  lifecycle,
  refusal,
  busy,
  error,
  onDrain,
  onDecommission,
}: {
  node: ClusterNode
  isLocal: boolean
  lifecycle: Lifecycle | undefined
  refusal: string | undefined
  busy: boolean
  error: string | undefined
  onDrain: () => void
  onDecommission: () => void
}) {
  const status = lifecyclePill[lifecycle ?? 'active']
  const locked = refusal !== undefined
  return (
    <>
      <tr data-testid="node-row">
        <td>
          <span className="mono2" data-testid="node-id">{node.id}</span>
          {isLocal && (
            <>
              {' '}
              <span className="pill neutral" data-testid="node-local-tag">This node</span>
            </>
          )}
        </td>
        <td className="mono2" data-testid="node-address">{node.address || '—'}</td>
        <td data-testid="node-role">{node.role}</td>
        <td data-testid="node-health">
          <span className={`pill ${healthPill[node.health]}`}>
            <span className="dot" />
            {node.health}
          </span>
        </td>
        <td data-testid="node-status">
          <span className={`pill ${status.cls}`}>
            <span className="dot" />
            {status.label}
          </span>
        </td>
        <td>
          <button
            type="button"
            className="wf-btn-sm"
            disabled={busy || locked || lifecycle !== undefined}
            title={refusal}
            onClick={onDrain}
            data-testid={`node-drain-btn-${node.id}`}
          >
            {busy ? 'Working…' : 'Drain'}
          </button>{' '}
          <button
            type="button"
            className="wf-btn-sm-danger"
            disabled={busy || locked || lifecycle === 'decommissioned'}
            title={refusal}
            onClick={onDecommission}
            data-testid={`node-decommission-btn-${node.id}`}
          >
            Decommission
          </button>
          {locked && (
            <div className="mut" data-testid={`node-refusal-${node.id}`}>
              {refusal}
            </div>
          )}
        </td>
      </tr>
      {error !== undefined && (
        <tr data-testid="node-error-row">
          <td colSpan={6}>
            <span className="wf-form-error" role="alert" data-testid={`node-action-error-${node.id}`}>
              {error}
            </span>
          </td>
        </tr>
      )}
    </>
  )
}

function DecommissionModal({
  node,
  isLocal,
  busy,
  error,
  onCancel,
  onConfirm,
}: {
  node: ClusterNode
  isLocal: boolean
  busy: boolean
  error: string | null
  onCancel: () => void
  onConfirm: () => void
}) {
  const [typed, setTyped] = useState('')
  return (
    <div
      className="wf-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="decommission-title"
      data-testid="decommission-overlay"
    >
      <div className="wf-modal">
        <h3 id="decommission-title">Decommission node?</h3>
        <p>
          This removes <b>{node.id}</b> from the cluster once its steward sessions have drained. The node must
          already be draining.
        </p>
        {isLocal && (
          <p className="notice-warn" data-testid="decommission-local-warning">
            This is the node serving this console.
          </p>
        )}
        <p>
          Type <b>{node.id}</b> to confirm.
        </p>
        <div className="wf-form-field">
          <input
            type="text"
            aria-label={`Type ${node.id} to confirm`}
            placeholder={node.id}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            data-testid="decommission-confirm-input"
            style={{ width: '100%' }}
          />
        </div>
        {error !== null && (
          <p className="wf-form-error" role="alert" data-testid="decommission-error">
            {error}
          </p>
        )}
        <div className="wf-modal-actions">
          <button type="button" className="wf-btn-secondary" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className="wf-btn-danger"
            disabled={busy || typed !== node.id}
            onClick={onConfirm}
            data-testid="decommission-confirm-btn"
          >
            {busy ? 'Decommissioning…' : 'Decommission node'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function ClusterNodesView() {
  const { nodes, localNodeId, loading, error, retry } = useClusterNodes()
  const [lifecycle, setLifecycle] = useState<Record<string, Lifecycle>>({})
  const [refusals, setRefusals] = useState<Record<string, string>>({})
  const [actionErrors, setActionErrors] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [decommissioning, setDecommissioning] = useState<ClusterNode | null>(null)
  const [modalError, setModalError] = useState<string | null>(null)

  function clearActionError(id: string) {
    setActionErrors((prev) => Object.fromEntries(Object.entries(prev).filter(([key]) => key !== id)))
  }

  // A 403 on the local node locks that node's actions; anything else is reported
  // and the action stays available. Returns the message to show.
  function recordFailure(node: ClusterNode, cause: unknown, fallback: string): { locked: boolean; message: string } {
    const message = errorText(cause, fallback)
    const locked = node.id === localNodeId && isRefusal(cause)
    if (locked) setRefusals((prev) => ({ ...prev, [node.id]: message }))
    return { locked, message }
  }

  async function drain(node: ClusterNode) {
    setBusy(node.id)
    clearActionError(node.id)
    try {
      await drainClusterNode(node.id)
      setLifecycle((prev) => ({ ...prev, [node.id]: 'draining' }))
      retry()
    } catch (cause: unknown) {
      const { locked, message } = recordFailure(node, cause, 'Drain failed')
      if (!locked) setActionErrors((prev) => ({ ...prev, [node.id]: message }))
    } finally {
      setBusy(null)
    }
  }

  async function decommission(node: ClusterNode) {
    setBusy(node.id)
    setModalError(null)
    try {
      await decommissionClusterNode(node.id)
      setLifecycle((prev) => ({ ...prev, [node.id]: 'decommissioned' }))
      setDecommissioning(null)
      retry()
    } catch (cause: unknown) {
      const { locked, message } = recordFailure(node, cause, 'Decommission failed')
      if (locked) setDecommissioning(null)
      else setModalError(message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <div className="htitle">
        <h1>Cluster nodes</h1>
        <p>Controller cluster nodes. Drain a node to stop new steward connections, then decommission it.</p>
      </div>

      {loading ? (
        <div data-testid="nodes-loading" aria-label="Loading cluster nodes">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '40%' }} />
              <span className="skel" style={{ width: '20%' }} />
            </div>
          ))}
        </div>
      ) : error !== null ? (
        <ErrorCard heading="Couldn't load cluster nodes" detail={error} onRetry={retry} />
      ) : nodes.length === 0 ? (
        <div className="notice empty" data-testid="nodes-empty">
          <div className="ic">◍</div>
          <h3>No cluster nodes</h3>
          <p>Nodes that join this controller cluster will appear here.</p>
        </div>
      ) : (
        <section className="panel">
          <table className="tbl" data-testid="nodes-table">
            <thead>
              <tr>
                <th>Node ID</th>
                <th>Address</th>
                <th>Role</th>
                <th>Health</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((node) => (
                <NodeRow
                  key={node.id}
                  node={node}
                  isLocal={node.id === localNodeId}
                  lifecycle={lifecycle[node.id]}
                  refusal={refusals[node.id]}
                  busy={busy === node.id}
                  error={actionErrors[node.id]}
                  onDrain={() => void drain(node)}
                  onDecommission={() => {
                    setModalError(null)
                    setDecommissioning(node)
                  }}
                />
              ))}
            </tbody>
          </table>
        </section>
      )}

      {decommissioning !== null && (
        <DecommissionModal
          node={decommissioning}
          isLocal={decommissioning.id === localNodeId}
          busy={busy === decommissioning.id}
          error={modalError}
          onCancel={() => setDecommissioning(null)}
          onConfirm={() => void decommission(decommissioning)}
        />
      )}
    </>
  )
}
