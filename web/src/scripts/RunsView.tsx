// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Run/job history view (Issue #2988).
 * Consumes GET /api/v1/runs (script-library-backed runs) and GET /api/v1/jobs
 * (batch jobs) from the list endpoints added in Issue #2987.
 *
 * Security A9.1: run IDs, script refs, job IDs, selectors, and status strings
 * are untrusted-origin data — rendered as JSX text nodes only, never
 * dangerouslySetInnerHTML.
 */
import { useRunList, useJobList } from './useScripts.ts'
import ErrorCard from '../shell/ErrorCard.tsx'

function statusTone(status: string): string {
  switch (status) {
    case 'completed':
    case 'rolled_back':
      return 'ok'
    case 'failed':
    case 'cancelled':
      return 'crit'
    case 'running':
    case 'pending':
    case 'paused':
      return 'warn'
    default:
      return 'neutral'
  }
}

export default function RunsView() {
  const {
    runs,
    loading: runsLoading,
    error: runsError,
    retry: retryRuns,
  } = useRunList()
  const {
    jobs,
    loading: jobsLoading,
    error: jobsError,
    retry: retryJobs,
  } = useJobList()

  return (
    <div data-testid="runs-view">
      <h3>Script runs</h3>

      {runsLoading ? (
        <div data-testid="runs-loading" aria-label="Loading runs">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '50%' }} />
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '40%' }} />
            </div>
          ))}
        </div>
      ) : runsError !== null ? (
        <ErrorCard
          heading="Couldn't load runs"
          detail={runsError}
          onRetry={retryRuns}
        />
      ) : runs.length === 0 ? (
        <div className="notice empty" data-testid="runs-empty">
          <div className="ic">◍</div>
          <p>No script runs found.</p>
        </div>
      ) : (
        <table className="tbl" data-testid="runs-table">
          <thead>
            <tr>
              <th>Run ID</th>
              <th>Script</th>
              <th>Status</th>
              <th>Jobs</th>
              <th>Created</th>
              <th className="c-spacer" aria-hidden="true" />
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.run_id} data-testid="run-row">
                <td>
                  <span className="mono2">{r.run_id}</span>
                </td>
                <td>
                  <span className="nm">{r.script_ref || '—'}</span>
                </td>
                <td>
                  <span className={`pill ${statusTone(r.status)}`}>
                    <span className="dot" />
                    {r.status}
                  </span>
                </td>
                <td>
                  <span className="mono2">
                    {r.completed_jobs}/{r.job_count}
                    {r.failed_jobs > 0 ? ` (${r.failed_jobs} failed)` : ''}
                  </span>
                </td>
                <td>
                  <span className="mono2">{r.created_at}</span>
                </td>
                <td className="c-spacer" />
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3>Batch jobs</h3>

      {jobsLoading ? (
        <div data-testid="jobs-loading" aria-label="Loading jobs">
          {Array.from({ length: 3 }, (_, i) => (
            <div className="skrow" key={i}>
              <span className="skel" style={{ width: '50%' }} />
              <span className="skel" style={{ width: '30%' }} />
              <span className="skel" style={{ width: '40%' }} />
            </div>
          ))}
        </div>
      ) : jobsError !== null ? (
        <ErrorCard
          heading="Couldn't load batch jobs"
          detail={jobsError}
          onRetry={retryJobs}
        />
      ) : jobs.length === 0 ? (
        <div className="notice empty" data-testid="jobs-empty">
          <div className="ic">◍</div>
          <p>No batch jobs found.</p>
        </div>
      ) : (
        <table className="tbl" data-testid="jobs-table">
          <thead>
            <tr>
              <th>Job ID</th>
              <th>Selector</th>
              <th>Status</th>
              <th>Targets</th>
              <th>Created</th>
              <th className="c-spacer" aria-hidden="true" />
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id} data-testid="job-row">
                <td>
                  <span className="mono2">{j.id}</span>
                </td>
                <td>
                  <span className="nm">{j.selector || '—'}</span>
                </td>
                <td>
                  <span className={`pill ${statusTone(j.status)}`}>
                    <span className="dot" />
                    {j.status}
                  </span>
                </td>
                <td>
                  <span className="mono2">{j.targets.length}</span>
                </td>
                <td>
                  <span className="mono2">{j.created_at}</span>
                </td>
                <td className="c-spacer" />
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
