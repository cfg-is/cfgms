// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Scripts view (Issue #2988) — the /scripts route entry point.
 * Fetches GET /api/v1/scripts, renders a library table, and opens RunPanel
 * when an operator selects a script row.
 *
 * Security A9.1: script names and descriptions are untrusted-origin data.
 * Every value reaches the DOM as a JSX text node — never dangerouslySetInnerHTML.
 */
import { useState } from 'react'
import { useScriptList, type ScriptMetadata } from './useScripts.ts'
import RunPanel from './RunPanel.tsx'
import RunsView from './RunsView.tsx'
import ErrorCard from '../shell/ErrorCard.tsx'

function LoadingRows() {
  return (
    <div data-testid="scripts-loading" aria-label="Loading scripts">
      {Array.from({ length: 4 }, (_, i) => (
        <div className="skrow" key={i}>
          <span className="skel" style={{ width: '45%' }} />
          <span className="skel" style={{ width: '20%' }} />
          <span className="skel" style={{ width: '55%' }} />
        </div>
      ))}
    </div>
  )
}

function ScriptsEmpty() {
  return (
    <div className="notice empty" data-testid="scripts-empty">
      <div className="ic">◍</div>
      <h3>No scripts in the library</h3>
      <p>The script library is empty. Add scripts via the controller CLI.</p>
    </div>
  )
}

function scriptVersionLabel(script: ScriptMetadata): string {
  const v = script.version
  if (!v) return '—'
  return `${v.major}.${v.minor}.${v.patch}${v.prerelease ? `-${v.prerelease}` : ''}`
}

function ScriptRow({
  script,
  selected,
  onClick,
}: {
  script: ScriptMetadata
  selected: boolean
  onClick: () => void
}) {
  return (
    <tr
      className={selected ? 'selected' : ''}
      onClick={onClick}
      data-testid="script-row"
    >
      <td>
        <span className="nm">{script.name}</span>
      </td>
      <td>
        <span className="mono2">{scriptVersionLabel(script)}</span>
      </td>
      <td>
        <span className="mut">{script.description || '—'}</span>
      </td>
      <td>
        <span className="mono2">{script.shell || '—'}</span>
      </td>
      <td className="c-spacer" />
    </tr>
  )
}

export default function ScriptsView() {
  const { scripts, loading, error, retry } = useScriptList()
  const [selectedScript, setSelectedScript] = useState<ScriptMetadata | null>(null)
  const [showHistory, setShowHistory] = useState(false)

  function handleRowClick(script: ScriptMetadata) {
    setSelectedScript((prev) => (prev?.id === script.id ? null : script))
    setShowHistory(false)
  }

  return (
    <>
      <div className="htitle">
        <h1>Scripts</h1>
        <p>Browse the script library and run scripts against stewards or fleet selections.</p>
      </div>

      <section className="panel">
        <div className="ptool">
          <button
            type="button"
            className={showHistory ? 'wf-btn' : 'wf-btn-secondary'}
            onClick={() => {
              setShowHistory((v) => !v)
              setSelectedScript(null)
            }}
            data-testid="toggle-history-btn"
          >
            {showHistory ? 'Close history' : 'Run history'}
          </button>
          {!loading && error === null && (
            <span className="cnt" data-testid="script-count">
              {scripts.length} script{scripts.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {showHistory && <RunsView />}

        {loading ? (
          <LoadingRows />
        ) : error !== null ? (
          <ErrorCard heading="Couldn't load scripts" detail={error} onRetry={retry} />
        ) : scripts.length === 0 ? (
          <ScriptsEmpty />
        ) : (
          <table className="tbl" data-testid="scripts-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Version</th>
                <th>Description</th>
                <th>Shell</th>
                <th className="c-spacer" aria-hidden="true" />
              </tr>
            </thead>
            <tbody>
              {scripts.map((s) => (
                <ScriptRow
                  key={s.id}
                  script={s}
                  selected={selectedScript?.id === s.id}
                  onClick={() => handleRowClick(s)}
                />
              ))}
            </tbody>
          </table>
        )}
      </section>

      {selectedScript !== null && (
        <RunPanel
          script={selectedScript}
          onClose={() => setSelectedScript(null)}
        />
      )}
    </>
  )
}
