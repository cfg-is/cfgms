// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Config list view (Story #2730) — the /config route entry point.
 * Fetches GET /api/v1/configs (list of per-steward configs), renders a table,
 * and exposes the Push panel and per-steward Config Editor.
 *
 * Security A9.1: config field values (steward_id, tenant_id, etc.) originate
 * from the controller and may contain attacker-controlled data. Every value
 * reaches the DOM as a JSX text node — never dangerouslySetInnerHTML.
 */
import { type FormEvent, useState } from 'react'
import {
  useConfigList,
  useStewardHostnameMap,
  useConfigDeployments,
  type ConfigSummary,
} from './useConfigs.ts'
import ConfigEditor from './ConfigEditor.tsx'
import PushPanel from './PushPanel.tsx'
import './Config.css'

function LoadingRows() {
  return (
    <div data-testid="config-loading" aria-label="Loading configurations">
      {Array.from({ length: 5 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '70%' }} />
          <span className="skel" style={{ width: '55%' }} />
          <span className="skel" style={{ width: '45%' }} />
          <span className="skel" style={{ width: '65%' }} />
          <span className="skel" style={{ width: '40%' }} />
        </div>
      ))}
    </div>
  )
}

function ErrorNotice({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return (
    <div className="notice err" role="alert">
      <div className="ic">!</div>
      <h3>Couldn&apos;t load configurations</h3>
      <p>The config list request failed. Check your connection and try again.</p>
      <span className="mono2 detail">{detail}</span>
      <button type="button" className="btn" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

function ConfigEmpty() {
  return (
    <div className="notice empty" data-testid="config-empty">
      <div className="ic">◍</div>
      <h3>No configurations found</h3>
      <p>
        No steward configurations have been stored yet. Push a config to a steward
        to get started.
      </p>
    </div>
  )
}

function ConfigRow({
  config,
  displayName,
  selected,
  showingDeployments,
  onClick,
  onViewDeployments,
}: {
  config: ConfigSummary
  displayName: string
  selected: boolean
  showingDeployments: boolean
  onClick: () => void
  onViewDeployments: () => void
}) {
  return (
    <tr
      className={selected ? 'selected' : ''}
      onClick={onClick}
      data-testid="config-row"
    >
      <td>
        <span className="nm">{displayName}</span>
      </td>
      <td>
        <span className="mono2">{String(config.version)}</span>
      </td>
      <td>
        <span className="mono2">{config.updated_at}</span>
      </td>
      <td>
        <span className="mono2">{config.tenant_id}</span>
      </td>
      <td>
        <span className="mut">{config.source || '—'}</span>
      </td>
      <td className="c-spacer">
        <button
          type="button"
          className={showingDeployments ? 'cfg-btn' : 'cfg-btn-secondary'}
          onClick={(e) => {
            e.stopPropagation()
            onViewDeployments()
          }}
          data-testid="view-deployments-btn"
          aria-label={`View deployments for ${displayName}`}
        >
          Deployments
        </button>
      </td>
    </tr>
  )
}

function deploymentStatusTone(status: string): string {
  switch (status) {
    case 'applied':
      return 'ok'
    case 'failed':
      return 'crit'
    case 'pending':
      return 'warn'
    default:
      return 'neutral'
  }
}

export default function ConfigListView() {
  const { configs, loading, error, retry } = useConfigList()
  const hostnameMap = useStewardHostnameMap()
  const [selectedStewardId, setSelectedStewardId] = useState<string | null>(null)
  const [showPushPanel, setShowPushPanel] = useState(false)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [createInputValue, setCreateInputValue] = useState('')
  const [deploymentConfigId, setDeploymentConfigId] = useState<string | null>(null)

  const {
    deployments,
    loading: deploymentsLoading,
    error: deploymentsError,
    serviceUnavailable: deploymentsUnavailable,
    retry: retryDeployments,
  } = useConfigDeployments(deploymentConfigId)

  function handleRowClick(stewardId: string) {
    setShowCreateForm(false)
    setSelectedStewardId((prev) => (prev === stewardId ? null : stewardId))
  }

  function handleViewDeployments(stewardId: string) {
    setDeploymentConfigId((prev) => (prev === stewardId ? null : stewardId))
  }

  function handleEditorClose() {
    setSelectedStewardId(null)
  }

  function handleToggleCreate() {
    setShowCreateForm((v) => !v)
    if (!showCreateForm) {
      setSelectedStewardId(null)
    }
  }

  function handleCreateSubmit(e: FormEvent) {
    e.preventDefault()
    const id = createInputValue.trim()
    if (!id) return
    setSelectedStewardId(id)
    setShowCreateForm(false)
    setCreateInputValue('')
  }

  return (
    <>
      <div className="htitle">
        <h1>Configuration</h1>
        <p>Browse steward configurations, push changes fleet-wide, and roll back.</p>
      </div>

      <section className="panel">
        <div className="ptool">
          <button
            type="button"
            className={showPushPanel ? 'cfg-btn' : 'cfg-btn-secondary'}
            onClick={() => setShowPushPanel((v) => !v)}
            data-testid="toggle-push-btn"
          >
            {showPushPanel ? 'Close push' : 'Push config'}
          </button>
          <button
            type="button"
            className={showCreateForm ? 'cfg-btn' : 'cfg-btn-secondary'}
            onClick={handleToggleCreate}
            data-testid="toggle-create-btn"
          >
            {showCreateForm ? 'Close' : '+ New config'}
          </button>
          {!loading && error === null && (
            <span className="cnt" data-testid="config-count">
              {configs.length} config{configs.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {showPushPanel && (
          <PushPanel onClose={() => setShowPushPanel(false)} />
        )}

        {showCreateForm && (
          <div className="cfg-push-panel" data-testid="create-config-form">
            <form className="cfg-push-form" onSubmit={handleCreateSubmit}>
              <div className="cfg-push-row">
                <div className="cfg-push-field">
                  <label className="cfg-push-label" htmlFor="create-steward-id">
                    Steward ID
                  </label>
                  <input
                    id="create-steward-id"
                    type="text"
                    value={createInputValue}
                    onChange={(e) => setCreateInputValue(e.target.value)}
                    placeholder="Enter steward ID"
                    data-testid="create-steward-id-input"
                  />
                </div>
                <div className="cfg-push-actions">
                  <button
                    type="submit"
                    className="cfg-btn"
                    disabled={!createInputValue.trim()}
                    data-testid="create-open-btn"
                  >
                    Open editor
                  </button>
                </div>
              </div>
            </form>
          </div>
        )}

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorNotice detail={error} onRetry={retry} />
        ) : configs.length === 0 ? (
          <ConfigEmpty />
        ) : (
          <table className="tbl" data-testid="config-table">
            <thead>
              <tr>
                <th>Steward</th>
                <th>Version</th>
                <th>Updated</th>
                <th>Tenant</th>
                <th>Source</th>
                <th className="c-spacer" aria-hidden="true" />
              </tr>
            </thead>
            <tbody>
              {configs.map((c) => (
                <ConfigRow
                  key={c.steward_id}
                  config={c}
                  displayName={hostnameMap.get(c.steward_id) ?? c.steward_id}
                  selected={selectedStewardId === c.steward_id}
                  showingDeployments={deploymentConfigId === c.steward_id}
                  onClick={() => handleRowClick(c.steward_id)}
                  onViewDeployments={() => handleViewDeployments(c.steward_id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {deploymentConfigId !== null && (
        <section className="panel" data-testid="deployment-panel">
          <div className="ptool">
            <span className="mono2">
              Deployments: {hostnameMap.get(deploymentConfigId) ?? deploymentConfigId}
            </span>
            <button
              type="button"
              className="cfg-btn-secondary"
              style={{ marginLeft: 'auto' }}
              onClick={() => setDeploymentConfigId(null)}
            >
              Close
            </button>
          </div>
          {deploymentsLoading && (
            <p className="mut" style={{ padding: '12px 14px' }}>Loading…</p>
          )}
          {deploymentsError !== null && !deploymentsUnavailable && (
            <div className="notice err" role="alert" style={{ margin: '12px' }}>
              <div className="ic">!</div>
              <p>{deploymentsError}</p>
              <button type="button" className="btn" onClick={retryDeployments}>
                Retry
              </button>
            </div>
          )}
          {deploymentsUnavailable && (
            <p className="mut" style={{ padding: '12px 14px' }}>
              Deployment results unavailable (store not ready).
            </p>
          )}
          {deployments !== null && !deploymentsUnavailable && (
            <>
              {deployments.stewards.length === 0 ? (
                <p className="mut" style={{ padding: '12px 14px' }}>
                  No per-steward deployment records found.
                </p>
              ) : (
                <table className="tbl" data-testid="deployment-steward-table">
                  <thead>
                    <tr>
                      <th>Steward</th>
                      <th>Status</th>
                      <th>Last Updated</th>
                      <th className="c-spacer" aria-hidden="true" />
                    </tr>
                  </thead>
                  <tbody>
                    {deployments.stewards.map((s) => (
                      <tr key={s.steward_id} data-testid="deployment-steward-row">
                        <td><span className="mono2">{s.steward_id}</span></td>
                        <td>
                          <span className={`pill ${deploymentStatusTone(s.status)}`}>
                            <span className="dot" />
                            {s.status}
                          </span>
                        </td>
                        <td><span className="mono2">{s.last_updated}</span></td>
                        <td className="c-spacer" />
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </section>
      )}

      {selectedStewardId !== null && (
        <ConfigEditor
          stewardId={selectedStewardId}
          onClose={handleEditorClose}
        />
      )}
    </>
  )
}
