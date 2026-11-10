// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Hyper-V profiles page (Issue #5461, Epic #5300) — the /hyperv/profiles route, built
 * to docs/design/mockups/hyperv-profiles.html. Lists unattend profiles (names only),
 * shows the selected profile's template, creates a profile and deletes one. Profiles
 * cannot be edited — the API has no update call — and the page says so.
 *
 * A profile template runs as root (Linux) or SYSTEM (Windows) on the first boot of
 * every new VM whose source names it, so create is three steps: Write, then "Review
 * what runs as root" (the whole template as numbered text, placeholders and secret
 * references listed, enrollment in its own box, Create disabled until the admin ticks
 * "I read the whole template"), then the passkey tap.
 *
 * Create and delete need a Strong step-up and a presence tap. The apiFetch interceptor
 * and StepUpModal do the tap and retry the request with X-Presence-Token, so this view
 * never builds that header. A cancelled tap creates or deletes nothing.
 *
 * Security A9.1: the template and every other wire value render as JSX text, never as
 * HTML; the {{ … }} highlighting wraps text runs in spans and nothing is parsed.
 */
import { useState } from 'react'
import {
  ProfileApiError,
  answerFormatsFor,
  maxTemplateBytes,
  runsAs,
  templateLines,
  templatePlaceholders,
  useProfile,
  useProfiles,
  type OsFamily,
  type Profile,
  type ProfileEnroll,
} from './useProfiles.ts'

const namePattern = /^[a-zA-Z0-9_-]{1,64}$/

/** Server codes that mean the submitted profile itself was rejected (fix it on the write step). */
const rejectionCodes = new Set(['INVALID_NAME', 'INVALID_ANSWER_FORMAT', 'INVALID_TEMPLATE', 'PROFILE_TOO_LARGE'])

// Page-specific styles on the design tokens (docs/design/web-ui-design-tokens.css),
// mirrored from the mockup. Emitted as a <style> element, which the SPA CSP allows
// (style-src-elem), so the route carries its own layout.
const profilesStyles = `
.hvp-split{display:grid;grid-template-columns:minmax(0,1fr);gap:var(--space-4);align-items:start;}
@media (min-width:1024px){.hvp-split.two{grid-template-columns:minmax(260px,330px) minmax(0,1fr);}}
.hvp-acts{display:flex;gap:8px;align-items:center;}
.hvp-panel{background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden;}
.hvp-phead{display:flex;align-items:center;gap:9px;padding:12px 16px;border-bottom:1px solid var(--border);}
.hvp-phead h2{margin:0;font-size:var(--text-md);font-weight:700;}
.hvp-phead .cnt{margin-left:auto;font-size:var(--text-sm);color:var(--text-faint);font-variant-numeric:tabular-nums;}
.hvp-pbody{padding:14px 16px;}
.hvp-mono{font-family:var(--font-mono);}
.hvp-btn,.hvp-btn-sec,.hvp-btn-danger,.hvp-btn-soft{appearance:none;font:inherit;font-size:var(--text-sm);font-weight:600;border-radius:var(--radius);cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;gap:7px;}
.hvp-btn{border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);padding:7px 14px;}
.hvp-btn-sec{border:1px solid var(--border);background:var(--bg-surface);color:var(--text-secondary);padding:7px 13px;}
.hvp-btn-danger{border:1px solid var(--state-crit);background:var(--state-crit);color:var(--bg-surface);font-weight:700;padding:7px 14px;}
.hvp-btn-soft{border:1px solid var(--state-crit);background:var(--state-crit-bg);color:var(--state-crit);font-size:11px;padding:5px 11px;border-radius:var(--radius-sm);}
.hvp-btn:disabled,.hvp-btn-danger:disabled,.hvp-btn-sec:disabled,.hvp-btn-soft:disabled{opacity:.45;cursor:not-allowed;}
.hvp-sm{font-size:11px;padding:5px 11px;border-radius:var(--radius-sm);}
.hvp-panel button:focus-visible,.hvp-panel select:focus-visible,.hvp-panel textarea:focus-visible,.hvp-panel input:focus-visible{outline:2px solid var(--accent);outline-offset:2px;}
.hvp-pill{display:inline-flex;align-items:center;padding:3px 9px;border-radius:var(--radius-pill);font-size:11px;font-weight:700;white-space:nowrap;}
.hvp-pill.neutral{background:var(--state-neutral-bg);color:var(--state-neutral);}
.hvp-pill.warn{background:var(--state-warn-bg);color:var(--state-warn);}
.hvp-pill.acc{background:var(--tint-blue);color:var(--accent);}
.hvp-tbl{width:100%;border-collapse:collapse;font-size:13px;}
.hvp-tbl th{text-align:left;font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--text-faint);font-weight:600;padding:9px 14px;border-bottom:1px solid var(--border);}
.hvp-tbl td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top;}
.hvp-tbl tbody tr:last-child > td{border-bottom:0;}
.hvp-tbl tr.sel > td{background:var(--tint-blue);}
.hvp-pick{appearance:none;border:0;background:transparent;color:inherit;font:inherit;text-align:left;padding:0;cursor:pointer;display:block;width:100%;}
.hvp-pname{display:block;font-family:var(--font-mono);font-weight:600;font-size:12.5px;overflow-wrap:anywhere;}
.hvp-tbl tr.sel .hvp-pname{color:var(--accent);}
.hvp-pref{display:block;font-family:var(--font-mono);font-size:11px;color:var(--text-faint);margin-top:2px;overflow-wrap:anywhere;}
.hvp-c-act{text-align:right;width:1%;white-space:nowrap;}
.hvp-tbl tr.confirm > td{background:var(--bg-sunk);padding:0;}
.hvp-confirm-in{padding:12px 14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.hvp-confirm-in .t{flex:1 1 100%;font-size:12.5px;color:var(--state-crit);}
.hvp-confirm-in .s{display:block;color:var(--text-secondary);font-size:11.5px;margin-top:4px;}
.hvp-confirm-in .gap{flex:1;}
.hvp-skrow{padding:13px 14px;display:flex;flex-direction:column;gap:6px;border-bottom:1px solid var(--border);}
.hvp-empty{display:flex;flex-direction:column;align-items:center;text-align:center;gap:8px;padding:34px 20px;}
.hvp-empty h3{margin:0;font-size:var(--text-md);}
.hvp-empty p{margin:0;color:var(--text-secondary);font-size:12.5px;max-width:440px;}
.hvp-errcard{display:flex;align-items:center;gap:12px;padding:16px;flex-wrap:wrap;}
.hvp-errcard .t{flex:1;min-width:200px;}
.hvp-errcard .t b{display:block;color:var(--state-crit);}
.hvp-errcard .t span{display:block;color:var(--text-secondary);font-size:12.5px;overflow-wrap:anywhere;}
.hvp-pickprompt{padding:44px 20px;text-align:center;color:var(--text-faint);font-size:12.5px;}
.hvp-dhead{display:flex;align-items:flex-start;gap:10px;padding:14px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;}
.hvp-dhead .nm{flex:1;min-width:200px;}
.hvp-dhead h2{margin:0;font-family:var(--font-mono);font-size:var(--text-lg);font-weight:700;overflow-wrap:anywhere;}
.hvp-pills{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;}
.hvp-facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 14px;margin:0;font-size:12.5px;}
.hvp-facts dt{font-size:var(--text-xs);letter-spacing:var(--tracking-label);text-transform:uppercase;color:var(--text-faint);font-weight:600;padding-top:2px;}
.hvp-facts dd{margin:0;overflow-wrap:anywhere;}
.hvp-facts dd.m{font-family:var(--font-mono);font-size:12px;}
.hvp-dbody{padding:14px 16px;display:flex;flex-direction:column;gap:14px;}
.hvp-sect{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;}
.hvp-sect h3{margin:0;font-size:var(--text-md);font-weight:700;}
.hvp-sect .sub{color:var(--text-faint);font-size:var(--text-sm);}
.hvp-sect .cnt{margin-left:auto;font-size:var(--text-sm);color:var(--text-faint);font-variant-numeric:tabular-nums;}
.hvp-hint{font-size:var(--text-sm);color:var(--text-faint);margin:0;}
.hvp-hint b{color:var(--text-secondary);font-weight:600;}
.hvp-enroll{border:1px solid var(--accent);background:var(--tint-blue);border-radius:var(--radius);padding:12px 14px;display:flex;flex-direction:column;gap:9px;}
.hvp-enroll .eh{display:flex;align-items:center;gap:8px;font-weight:700;font-size:13px;color:var(--text-primary);}
.hvp-enroll .eh .hvp-pill{margin-left:auto;}
.hvp-enroll.off{border-color:var(--state-warn);background:var(--state-warn-bg);}
.hvp-tpl{background:var(--bg-sunk);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--font-mono);font-size:12px;line-height:1.55;padding:10px 0;color:var(--text-primary);}
.hvp-ln{display:grid;grid-template-columns:3.4em minmax(0,1fr);padding-right:12px;}
.hvp-ln .n{color:var(--text-faint);text-align:right;padding-right:12px;user-select:none;font-variant-numeric:tabular-nums;}
.hvp-ln .c{white-space:pre-wrap;overflow-wrap:anywhere;min-height:1.55em;padding-left:4ch;text-indent:-4ch;}
.hvp-tk{background:var(--tint-blue);color:var(--accent);border-radius:3px;box-shadow:0 0 0 1px var(--border);}
.hvp-tk.sec{background:var(--state-warn-bg);color:var(--state-warn);}
.hvp-steps{display:flex;gap:6px;align-items:center;flex-wrap:wrap;font-size:var(--text-sm);color:var(--text-faint);padding:12px 16px;border-bottom:1px solid var(--border);}
.hvp-steps .st{display:inline-flex;align-items:center;gap:7px;font-weight:600;}
.hvp-steps .st i{font-style:normal;width:20px;height:20px;border-radius:50%;border:1px solid var(--border);display:grid;place-items:center;font-size:11px;background:var(--bg-surface);}
.hvp-steps .st.now{color:var(--text-primary);}
.hvp-steps .st.now i{background:var(--accent);color:var(--accent-ink);border-color:var(--accent);}
.hvp-steps .st.done{color:var(--text-secondary);}
.hvp-steps .st.done i{background:var(--state-ok-bg);color:var(--state-ok);border-color:var(--state-ok);}
.hvp-steps .bar{width:22px;height:1px;background:var(--border);}
.hvp-steps .x{margin-left:auto;}
.hvp-form{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;}
.hvp-row3{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;}
@media (min-width:1024px){.hvp-row3{grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) minmax(0,1.2fr);}}
.hvp-field{display:flex;flex-direction:column;gap:5px;min-width:0;}
.hvp-lbl{font-size:var(--text-xs);letter-spacing:var(--tracking-label);text-transform:uppercase;color:var(--text-faint);font-weight:600;}
.hvp-req{color:var(--state-crit);}
.hvp-field select,.hvp-field textarea,.hvp-field input[type=text]{width:100%;background:var(--bg-surface);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--radius);padding:8px 11px;font:inherit;font-size:var(--text-base);}
.hvp-field input.m,.hvp-field textarea.m{font-family:var(--font-mono);font-size:12.5px;}
.hvp-field textarea{resize:vertical;min-height:340px;line-height:1.55;white-space:pre;overflow:auto;tab-size:2;}
.hvp-field.bad select,.hvp-field.bad textarea,.hvp-field.bad input{border-color:var(--state-crit);}
.hvp-seg{display:inline-flex;background:var(--bg-sunk);border:1px solid var(--border);border-radius:var(--radius);padding:2px;width:100%;}
.hvp-seg button{flex:1;appearance:none;border:0;background:transparent;color:var(--text-secondary);font:inherit;font-size:var(--text-sm);font-weight:600;padding:7px 0;border-radius:var(--radius-sm);cursor:pointer;}
.hvp-seg button[aria-pressed="true"]{background:var(--bg-surface);color:var(--text-primary);box-shadow:0 0 0 1px var(--border);}
.hvp-fmeta{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline;justify-content:space-between;}
.hvp-enf{border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px 14px;margin:0;display:flex;flex-direction:column;gap:12px;min-width:0;}
.hvp-enf legend{padding:0 6px;font-size:var(--text-sm);font-weight:700;color:var(--text-primary);}
.hvp-fbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:12px 16px;border-top:1px solid var(--border);background:var(--bg-primary);}
.hvp-fbar .sp{flex:1;}
.hvp-msg{display:flex;flex-direction:column;gap:4px;padding:9px 12px;border-radius:var(--radius);font-size:12.5px;line-height:1.45;}
.hvp-msg.crit{background:var(--state-crit-bg);color:var(--state-crit);border:1px solid var(--state-crit);}
.hvp-msg.warn{background:var(--state-warn-bg);color:var(--state-warn);border:1px solid var(--state-warn);}
.hvp-msg.ok{background:var(--state-ok-bg);color:var(--state-ok);border:1px solid var(--state-ok);}
.hvp-msg .srv{font-family:var(--font-mono);font-size:11.5px;color:var(--text-primary);overflow-wrap:anywhere;}
.hvp-rv{display:grid;grid-template-columns:minmax(0,1fr);gap:14px;padding:14px 16px;}
@media (min-width:1024px){.hvp-rv{grid-template-columns:minmax(0,1fr) 330px;align-items:start;}.hvp-rv .warn{grid-column:1 / -1;}}
.hvp-rv-side{display:flex;flex-direction:column;gap:12px;}
.hvp-rv-tpl{display:flex;flex-direction:column;gap:8px;min-width:0;}
.hvp-card{border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;display:flex;flex-direction:column;gap:10px;}
.hvp-card h4{margin:0;font-size:var(--text-xs);letter-spacing:var(--tracking-label);text-transform:uppercase;color:var(--text-faint);font-weight:600;}
.hvp-vars{display:flex;flex-direction:column;gap:6px;margin:0;padding:0;list-style:none;}
.hvp-vars li{display:flex;flex-direction:column;align-items:flex-start;gap:3px;font-size:12px;}
.hvp-vars code{font-family:var(--font-mono);font-size:11.5px;background:var(--tint-blue);color:var(--accent);padding:1px 6px;border-radius:var(--radius-sm);overflow-wrap:anywhere;}
.hvp-vars li.sec code{background:var(--state-warn-bg);color:var(--state-warn);}
.hvp-vars span{color:var(--text-secondary);}
.hvp-ack{display:flex;flex-direction:column;gap:10px;border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;background:var(--bg-primary);}
.hvp-chk{display:flex;gap:9px;align-items:flex-start;font-size:12.5px;cursor:pointer;}
.hvp-chk input{margin:2px 0 0;width:15px;height:15px;accent-color:var(--accent);flex:none;}
.hvp-ackbtns{display:flex;gap:8px;flex-wrap:wrap;}
.hvp-ackbtns button{flex:1;justify-content:center;}
`

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback
}

function sizeLabel(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`
}

function templateMeta(template: string): string {
  return `${templateLines(template).length} lines · ${sizeLabel(new TextEncoder().encode(template).length)}`
}

/** One text run per piece; `{{ … }}` runs are wrapped in a span, never parsed. */
function LineText({ line }: { line: string }) {
  return (
    <>
      {line.split(/(\{\{.*?\}\})/g).map((part, i) =>
        i % 2 === 1 ? (
          <span key={i} className={/^\{\{\s*secret\s/.test(part) ? 'hvp-tk sec' : 'hvp-tk'}>
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </>
  )
}

function TemplateText({ template, testId }: { template: string; testId: string }) {
  return (
    <div className="hvp-tpl" role="region" aria-label="Template text" data-testid={testId}>
      {templateLines(template).map((line, i) => (
        <div className="hvp-ln" key={i} data-testid="hvp-ln">
          <span className="n">{i + 1}</span>
          <span className="c">
            <LineText line={line} />
          </span>
        </div>
      ))}
    </div>
  )
}

function enrollIsOn(enroll: ProfileEnroll): boolean {
  return (
    enroll.registration_token_secret_key !== '' || enroll.bundle_url !== '' || enroll.correlation_label !== ''
  )
}

function EnrollBox({ enroll, tenant }: { enroll: ProfileEnroll; tenant: string }) {
  if (!enrollIsOn(enroll)) {
    return (
      <div className="hvp-enroll off" data-testid="hvp-enroll">
        <div className="eh">
          Enrollment: off<span className="hvp-pill warn">Not set</span>
        </div>
        <p className="hvp-hint">
          VMs built from this profile do not join CFGMS unless the template does it itself.
        </p>
      </div>
    )
  }
  return (
    <div className="hvp-enroll" data-testid="hvp-enroll">
      <div className="eh">
        Enrollment: joins {tenant || 'this tenant'}
        <span className="hvp-pill acc">On</span>
      </div>
      <dl className="hvp-facts">
        <dt>Token key</dt>
        <dd className="m">{enroll.registration_token_secret_key || '—'}</dd>
        <dt>Bundle URL</dt>
        <dd className="m">{enroll.bundle_url || '—'}</dd>
        <dt>Label</dt>
        <dd className="m">{enroll.correlation_label || '—'}</dd>
      </dl>
      <p className="hvp-hint">
        Only the key name is stored. The token itself is put on the VM when it is created and removed after it
        joins.
      </p>
    </div>
  )
}

function ProfileDetail({ name, tenant, onDelete }: { name: string; tenant: string; onDelete: () => void }) {
  const { profile, loading, error, retry } = useProfile(name)
  return (
    <div className="hvp-panel" data-testid="hvp-detail">
      <div className="hvp-dhead">
        <div className="nm">
          <h2 data-testid="hvp-detail-name">{name}</h2>
          <span className="hvp-pref">profile://{name}</span>
          {profile !== null && (
            <div className="hvp-pills">
              <span className="hvp-pill neutral" data-testid="hvp-detail-os">
                {profile.os_family}
              </span>
              <span className="hvp-pill neutral" data-testid="hvp-detail-format">
                {profile.answer_format}
              </span>
              <span className="hvp-pill warn" data-testid="hvp-detail-runs-as">
                runs as {runsAs(profile.os_family)}
              </span>
            </div>
          )}
        </div>
        <button type="button" className="hvp-btn-soft" onClick={onDelete} data-testid="hvp-detail-delete">
          Delete
        </button>
      </div>
      {loading ? (
        <div className="hvp-dbody" data-testid="hvp-detail-loading" aria-label="Loading profile">
          <span className="skel" style={{ width: '40%' }} />
          <span className="skel" style={{ width: '90%' }} />
          <span className="skel" style={{ width: '70%' }} />
        </div>
      ) : error !== null || profile === null ? (
        <div className="hvp-errcard" role="alert" data-testid="hvp-detail-error">
          <div className="t">
            <b>Could not load this profile.</b>
            <span>{error ?? 'The controller sent an unreadable profile.'}</span>
          </div>
          <button type="button" className="hvp-btn-sec" onClick={retry}>
            Try again
          </button>
        </div>
      ) : (
        <div className="hvp-dbody">
          <EnrollBox enroll={profile.enroll} tenant={tenant} />
          <div className="hvp-sect">
            <h3>Template</h3>
            <span className="sub">
              Shown exactly as stored. Runs on first boot of each new VM that names this profile.
            </span>
            <span className="cnt">{templateMeta(profile.template)}</span>
          </div>
          <TemplateText template={profile.template} testId="hvp-template" />
          <p className="hvp-hint" data-testid="hvp-no-edit">
            Profiles cannot be edited. To change one, create a new profile, point the VM source at it, then delete
            the old one.
          </p>
        </div>
      )}
    </div>
  )
}

interface Draft {
  name: string
  os: OsFamily
  format: string
  template: string
  key: string
  url: string
  label: string
}

const emptyDraft: Draft = {
  name: '',
  os: 'linux',
  format: 'cloud-init',
  template: '',
  key: '',
  url: '',
  label: '',
}

function draftToProfile(d: Draft): Profile {
  return {
    name: d.name.trim(),
    os_family: d.os,
    answer_format: d.format,
    template: d.template,
    enroll: {
      registration_token_secret_key: d.key.trim(),
      bundle_url: d.url.trim(),
      correlation_label: d.label.trim(),
    },
  }
}

interface FormError {
  /** Set for a rejection by the controller: the code and its message. */
  server?: { code: string; message: string }
  /** Set for a check the page made itself. */
  text?: string
}

function Steps({ now, onCancel }: { now: 'write' | 'review' | 'tap'; onCancel?: () => void }) {
  const order = ['write', 'review', 'tap'] as const
  const idx = order.indexOf(now)
  const labels = ['Write', 'Review what runs as root', 'Confirm with passkey']
  return (
    <div className="hvp-steps" aria-label="Create steps">
      {labels.map((label, i) => (
        <span key={label} style={{ display: 'contents' }}>
          {i > 0 && <span className="bar" />}
          <span
            className={`st ${i < idx ? 'done' : i === idx ? 'now' : ''}`}
            aria-current={i === idx ? 'step' : undefined}
          >
            <i>{i < idx ? '✓' : i + 1}</i>
            {label}
          </span>
        </span>
      ))}
      {onCancel !== undefined && (
        <button type="button" className="hvp-btn-sec hvp-sm x" onClick={onCancel} data-testid="hvp-cancel-btn">
          Cancel
        </button>
      )}
    </div>
  )
}

function WriteStep({
  draft,
  tenant,
  error,
  onChange,
  onCancel,
  onReview,
}: {
  draft: Draft
  tenant: string
  error: FormError | null
  onChange: (patch: Partial<Draft>) => void
  onCancel: () => void
  onReview: () => void
}) {
  const formats = answerFormatsFor(draft.os)
  const formatHint = formats.find(([f]) => f === draft.format)?.[1] ?? formats[0]?.[1] ?? ''
  const bytes = new TextEncoder().encode(draft.template).length
  const bad = error !== null && error.server?.code === 'INVALID_TEMPLATE'
  return (
    <div className="hvp-panel" data-testid="hvp-create">
      <Steps now="write" onCancel={onCancel} />
      <form
        className="hvp-pbody hvp-form"
        onSubmit={(e) => {
          e.preventDefault()
          onReview()
        }}
      >
        {error !== null && (
          <div className="hvp-msg crit" role="alert" data-testid="hvp-form-error">
            {error.server !== undefined ? (
              <>
                <span>
                  <b>Not created. Nothing was saved.</b> The controller could not accept this profile. Fix it and
                  review again.
                </span>
                <span className="srv">
                  {error.server.code} · {error.server.message}
                </span>
              </>
            ) : (
              <span>{error.text}</span>
            )}
          </div>
        )}
        <div className="hvp-row3">
          <div className="hvp-field">
            <label className="hvp-lbl" htmlFor="hvp-name">
              Name <span className="hvp-req">*</span>
            </label>
            <input
              id="hvp-name"
              type="text"
              className="m"
              spellCheck={false}
              value={draft.name}
              onChange={(e) => onChange({ name: e.target.value })}
              data-testid="hvp-name"
            />
            <span className="hvp-hint">
              Letters, digits, <b>-</b> and <b>_</b>, up to 64. VM sources use{' '}
              <span className="hvp-mono">profile://{draft.name.trim() || '<name>'}</span>.
            </span>
          </div>
          <div className="hvp-field">
            <span className="hvp-lbl">
              OS family <span className="hvp-req">*</span>
            </span>
            <div className="hvp-seg" role="group" aria-label="OS family">
              {(['linux', 'windows'] as const).map((os) => (
                <button
                  key={os}
                  type="button"
                  aria-pressed={draft.os === os}
                  onClick={() => onChange({ os, format: answerFormatsFor(os)[0]?.[0] ?? '' })}
                  data-testid={`hvp-os-${os}`}
                >
                  {os}
                </button>
              ))}
            </div>
            <span className="hvp-hint">
              Runs as <b data-testid="hvp-runs-as">{runsAs(draft.os)}</b> on first boot.
            </span>
          </div>
          <div className="hvp-field">
            <label className="hvp-lbl" htmlFor="hvp-format">
              Answer format <span className="hvp-req">*</span>
            </label>
            <select
              id="hvp-format"
              value={draft.format}
              onChange={(e) => onChange({ format: e.target.value })}
              data-testid="hvp-format"
            >
              {formats.map(([f]) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <span className="hvp-hint">{formatHint}</span>
          </div>
        </div>
        <div className={bad ? 'hvp-field bad' : 'hvp-field'}>
          <div className="hvp-fmeta">
            <label className="hvp-lbl" htmlFor="hvp-template-input">
              Template <span className="hvp-req">*</span>
            </label>
            <span className="hvp-hint">
              {templateMeta(draft.template)} of {maxTemplateBytes / 1024} KB
              {bytes > maxTemplateBytes ? ' — too large' : ''}
            </span>
          </div>
          <textarea
            id="hvp-template-input"
            className="m"
            spellCheck={false}
            value={draft.template}
            onChange={(e) => onChange({ template: e.target.value })}
            aria-describedby="hvp-template-hint"
            data-testid="hvp-template-input"
          />
          <span className="hvp-hint" id="hvp-template-hint">
            Filled in when each VM is created: <span className="hvp-mono">{'{{ .VMName }}'}</span>{' '}
            <span className="hvp-mono">{'{{ .CorrelationID }}'}</span>{' '}
            <span className="hvp-mono">{'{{ .EnrollTokenFile }}'}</span>{' '}
            <span className="hvp-mono">{'{{ .CAFingerprint }}'}</span>{' '}
            <span className="hvp-mono">{'{{ .BundleURL }}'}</span>. Secrets:{' '}
            <span className="hvp-mono">{'{{ secret "key" }}'}</span> reads the value from the secret store; never
            paste a password here.
          </span>
        </div>
        <fieldset className="hvp-enf">
          <legend>Enrollment — how the new VM joins CFGMS{tenant ? ` (${tenant})` : ''}</legend>
          <div className="hvp-row3">
            <div className="hvp-field">
              <label className="hvp-lbl" htmlFor="hvp-enroll-key">
                Token secret key
              </label>
              <input
                id="hvp-enroll-key"
                type="text"
                className="m"
                spellCheck={false}
                value={draft.key}
                onChange={(e) => onChange({ key: e.target.value })}
                data-testid="hvp-enroll-key"
              />
              <span className="hvp-hint">The secret store key name, not the token.</span>
            </div>
            <div className="hvp-field">
              <label className="hvp-lbl" htmlFor="hvp-enroll-url">
                Bundle URL
              </label>
              <input
                id="hvp-enroll-url"
                type="text"
                className="m"
                spellCheck={false}
                value={draft.url}
                onChange={(e) => onChange({ url: e.target.value })}
                data-testid="hvp-enroll-url"
              />
              <span className="hvp-hint">
                Fills <span className="hvp-mono">{'{{ .BundleURL }}'}</span>.
              </span>
            </div>
            <div className="hvp-field">
              <label className="hvp-lbl" htmlFor="hvp-enroll-label">
                Correlation label
              </label>
              <input
                id="hvp-enroll-label"
                type="text"
                className="m"
                spellCheck={false}
                value={draft.label}
                onChange={(e) => onChange({ label: e.target.value })}
                data-testid="hvp-enroll-label"
              />
              <span className="hvp-hint">Ties the VM to its build request.</span>
            </div>
          </div>
          <span className="hvp-hint">Leave all three empty if VMs from this profile should not join CFGMS.</span>
        </fieldset>
        <div className="hvp-fbar" style={{ margin: '0 -16px -14px' }}>
          <span className="hvp-hint">Nothing is saved until you confirm on the next step.</span>
          <span className="sp" />
          <button type="button" className="hvp-btn-sec" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="hvp-btn" data-testid="hvp-review-btn">
            Review template
          </button>
        </div>
      </form>
    </div>
  )
}

function ReviewStep({
  profile,
  tenant,
  creating,
  error,
  onBack,
  onCreate,
}: {
  profile: Profile
  tenant: string
  creating: boolean
  error: string | null
  onBack: () => void
  onCreate: () => void
}) {
  const [ack, setAck] = useState(false)
  const placeholders = templatePlaceholders(profile.template)
  const runs = runsAs(profile.os_family)
  return (
    <div className="hvp-panel" data-testid="hvp-review">
      <Steps now={creating ? 'tap' : 'review'} />
      <div className="hvp-rv">
        <div className="hvp-msg warn" role="note">
          <span>
            <b>
              This text runs as {runs} on first boot.
            </b>{' '}
            Every new VM whose source names <span className="hvp-mono">profile://{profile.name}</span> runs it with
            full control of the machine. Read all of it before you create the profile.
          </span>
        </div>

        <div className="hvp-rv-tpl">
          <div className="hvp-sect">
            <h3>Template</h3>
            <span className="sub">Exactly what will be stored. Highlighted parts are filled in per VM.</span>
            <span className="cnt">{templateMeta(profile.template)}</span>
          </div>
          <TemplateText template={profile.template} testId="hvp-review-template" />
        </div>

        <div className="hvp-rv-side">
          <div className="hvp-card">
            <h4>Profile</h4>
            <dl className="hvp-facts">
              <dt>Name</dt>
              <dd className="m">{profile.name}</dd>
              <dt>Tenant</dt>
              <dd className="m">{tenant || '—'}</dd>
              <dt>OS family</dt>
              <dd className="m">{profile.os_family}</dd>
              <dt>Format</dt>
              <dd className="m">{profile.answer_format}</dd>
              <dt>Runs as</dt>
              <dd>
                <b>{runs}</b>, on first boot
              </dd>
            </dl>
          </div>
          <EnrollBox enroll={profile.enroll} tenant={tenant} />
          <div className="hvp-card">
            <h4>Filled in when each VM is created</h4>
            {placeholders.length === 0 ? (
              <p className="hvp-hint">No placeholders. The template is used as written.</p>
            ) : (
              <ul className="hvp-vars" data-testid="hvp-vars">
                {placeholders.map((p) => (
                  <li
                    key={p.expr}
                    className={p.secret ? 'sec' : undefined}
                    data-testid={p.secret ? 'hvp-var-secret' : 'hvp-var'}
                  >
                    <code>{p.expr}</code>
                    <span>
                      {p.secret
                        ? 'Read from the secret store when the VM is created. Not stored in the profile.'
                        : 'Per-VM value'}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="hvp-ack">
            <label className="hvp-chk">
              <input
                type="checkbox"
                checked={ack}
                onChange={(e) => setAck(e.target.checked)}
                data-testid="hvp-ack"
              />
              <span>
                I read the whole template. It is what should run as {runs} on new VMs in{' '}
                <b className="hvp-mono">{tenant || 'this tenant'}</b>.
              </span>
            </label>
            {error !== null && (
              <div className="hvp-msg crit" role="alert" data-testid="hvp-review-error">
                <span>
                  <b>Not created.</b> {error}
                </span>
              </div>
            )}
            <div className="hvp-ackbtns">
              <button type="button" className="hvp-btn-sec" onClick={onBack} disabled={creating} data-testid="hvp-back-btn">
                Back to edit
              </button>
              <button
                type="button"
                className="hvp-btn"
                disabled={!ack || creating}
                onClick={onCreate}
                data-testid="hvp-create-btn"
              >
                {creating ? 'Waiting for passkey…' : 'Create — tap passkey'}
              </button>
            </div>
            <span className="hvp-hint">Creating is recorded in the audit log under your name.</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function ProfilesView() {
  const { tenant, names, loading, error, errorCode, retry, create, remove } = useProfiles()
  const [mode, setMode] = useState<'browse' | 'write' | 'review'>('browse')
  const [draft, setDraft] = useState<Draft>(emptyDraft)
  const [formError, setFormError] = useState<FormError | null>(null)
  const [reviewError, setReviewError] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [status, setStatus] = useState<string | null>(null)

  const tenantLabel = tenant || 'this tenant'
  const tenantRequired = errorCode === 'TENANT_REQUIRED'

  function patchDraft(patch: Partial<Draft>) {
    setDraft((d) => ({ ...d, ...patch }))
  }

  function openCreate() {
    setStatus(null)
    setFormError(null)
    setReviewError(null)
    setDraft(emptyDraft)
    setMode('write')
  }

  function closeCreate() {
    setMode('browse')
    setFormError(null)
    setReviewError(null)
  }

  function toReview() {
    const name = draft.name.trim()
    let problem: string | null = null
    if (!namePattern.test(name)) {
      problem = 'Name: letters, digits, - and _, up to 64 characters.'
    } else if (names.includes(name)) {
      problem = `A profile named ${name} already exists. Profiles cannot be edited: choose a new name, then delete the old one.`
    } else if (draft.template.trim() === '') {
      problem = 'Template is required.'
    } else if (new TextEncoder().encode(draft.template).length > maxTemplateBytes) {
      problem = `Template is over ${maxTemplateBytes / 1024} KB.`
    }
    if (problem !== null) {
      setFormError({ text: problem })
      return
    }
    setFormError(null)
    setReviewError(null)
    setMode('review')
  }

  async function handleCreate() {
    setCreating(true)
    setReviewError(null)
    try {
      const created = await create(draftToProfile(draft))
      setStatus(`Profile ${created.name} created.`)
      setSelected(created.name)
      setConfirming(null)
      setDraft(emptyDraft)
      setMode('browse')
      retry()
    } catch (cause: unknown) {
      if (cause instanceof ProfileApiError && rejectionCodes.has(cause.code)) {
        setFormError({ server: { code: cause.code, message: cause.message } })
        setMode('write')
      } else {
        setReviewError(errorText(cause, 'The create request failed.'))
      }
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(name: string) {
    setDeleting(true)
    setDeleteError(null)
    try {
      await remove(name)
      setConfirming(null)
      if (selected === name) setSelected(null)
      setStatus(`Profile ${name} deleted.`)
      retry()
    } catch (cause: unknown) {
      setDeleteError(errorText(cause, 'Delete failed'))
    } finally {
      setDeleting(false)
    }
  }

  function askDelete(name: string) {
    setDeleteError(null)
    setStatus(null)
    setConfirming(name)
  }

  const showHeaderNew = mode === 'browse' && !loading && !tenantRequired && !(error === null && names.length === 0)

  return (
    <>
      <style>{profilesStyles}</style>
      <div className="htitle">
        <div>
          <h1>Hyper-V profiles</h1>
          <p>
            Unattended install files for new Hyper-V VMs in <b className="hvp-mono">{tenantLabel}</b>. A VM source
            names one as <span className="hvp-mono">profile://&lt;name&gt;</span>. The template runs as root (Linux)
            or SYSTEM (Windows) when each new VM first boots.
          </p>
        </div>
        {showHeaderNew && (
          <div className="hvp-acts">
            <button type="button" className="hvp-btn" onClick={openCreate} data-testid="hvp-new-btn">
              + New profile
            </button>
          </div>
        )}
      </div>

      {status !== null && mode === 'browse' && (
        <div className="hvp-msg ok" role="status" data-testid="hvp-status">
          {status}
        </div>
      )}

      {mode === 'write' && (
        <WriteStep
          draft={draft}
          tenant={tenant}
          error={formError}
          onChange={patchDraft}
          onCancel={closeCreate}
          onReview={toReview}
        />
      )}

      {mode === 'review' && (
        <ReviewStep
          profile={draftToProfile(draft)}
          tenant={tenant}
          creating={creating}
          error={reviewError}
          onBack={() => setMode('write')}
          onCreate={() => void handleCreate()}
        />
      )}

      {mode === 'browse' && (
        <div className={error === null && names.length > 0 ? 'hvp-split two' : 'hvp-split'}>
          <div className="hvp-panel">
            <div className="hvp-phead">
              <h2>Profiles</h2>
              {!loading && error === null && names.length > 0 && (
                <span className="cnt" data-testid="hvp-count">
                  {names.length}
                </span>
              )}
            </div>
            {loading ? (
              <div data-testid="hvp-loading" aria-label="Loading profiles">
                {Array.from({ length: 3 }, (_, i) => (
                  <div className="hvp-skrow" key={i}>
                    <span className="skel" style={{ width: '45%' }} />
                    <span className="skel" style={{ width: '65%', height: 9 }} />
                  </div>
                ))}
              </div>
            ) : error !== null ? (
              <div className="hvp-errcard" role="alert" data-testid="hvp-error">
                <div className="t">
                  <b>Could not load profiles.</b>
                  {tenantRequired ? (
                    <span>Choose a tenant in the tenant switcher first. {error}</span>
                  ) : (
                    <span>The controller did not answer. No profile has changed. {error}</span>
                  )}
                </div>
                <button type="button" className="hvp-btn-sec" onClick={retry} data-testid="hvp-retry">
                  Try again
                </button>
              </div>
            ) : names.length === 0 ? (
              <div className="hvp-empty" data-testid="hvp-empty">
                <h3>No profiles in {tenantLabel}</h3>
                <p>
                  Add a profile when new VMs in this tenant need their own install and first-boot steps. A VM source
                  then names it as <span className="hvp-mono">profile://&lt;name&gt;</span>.
                </p>
                <button type="button" className="hvp-btn" onClick={openCreate} data-testid="hvp-new-btn">
                  + New profile
                </button>
              </div>
            ) : (
              <table className="hvp-tbl" data-testid="hvp-list">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {names.map((name) => (
                    <ProfileRow
                      key={name}
                      name={name}
                      selected={selected === name}
                      confirming={confirming === name}
                      busy={deleting}
                      error={confirming === name ? deleteError : null}
                      onPick={() => setSelected(name)}
                      onAskDelete={() => askDelete(name)}
                      onKeep={() => setConfirming(null)}
                      onConfirm={() => void handleDelete(name)}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {error === null && names.length > 0 &&
            (selected !== null && names.includes(selected) ? (
              <ProfileDetail
                key={selected}
                name={selected}
                tenant={tenant}
                onDelete={() => askDelete(selected)}
              />
            ) : (
              <div className="hvp-panel">
                <div className="hvp-pickprompt" data-testid="hvp-pick-prompt">
                  Select a profile to see its template.
                </div>
              </div>
            ))}
        </div>
      )}
    </>
  )
}

function ProfileRow({
  name,
  selected,
  confirming,
  busy,
  error,
  onPick,
  onAskDelete,
  onKeep,
  onConfirm,
}: {
  name: string
  selected: boolean
  confirming: boolean
  busy: boolean
  error: string | null
  onPick: () => void
  onAskDelete: () => void
  onKeep: () => void
  onConfirm: () => void
}) {
  return (
    <>
      <tr className={selected ? 'sel' : undefined} data-testid="hvp-row">
        <td>
          <button
            type="button"
            className="hvp-pick"
            onClick={onPick}
            aria-pressed={selected}
            data-testid={`hvp-pick-${name}`}
          >
            <span className="hvp-pname">{name}</span>
            <span className="hvp-pref">profile://{name}</span>
          </button>
        </td>
        <td className="hvp-c-act">
          {!confirming && (
            <button
              type="button"
              className="hvp-btn-soft"
              onClick={onAskDelete}
              data-testid={`hvp-delete-${name}`}
              aria-label={`Delete ${name}`}
            >
              Delete
            </button>
          )}
        </td>
      </tr>
      {confirming && (
        <tr className="confirm">
          <td colSpan={2}>
            <div className="hvp-confirm-in" data-testid="hvp-confirm">
              <span className="t">
                <b>Delete {name}?</b> VMs already built from it are not changed. A VM source that still names{' '}
                <span className="hvp-mono">profile://{name}</span> cannot build new VMs until it names another
                profile.
                <span className="s">You confirm with your passkey. Recorded in the audit log.</span>
              </span>
              <span className="gap" />
              <button
                type="button"
                className="hvp-btn-sec hvp-sm"
                disabled={busy}
                onClick={onKeep}
                data-testid="hvp-keep"
              >
                Keep
              </button>
              <button
                type="button"
                className="hvp-btn-danger hvp-sm"
                disabled={busy}
                onClick={onConfirm}
                data-testid="hvp-confirm-delete"
              >
                {busy ? 'Deleting…' : 'Delete — tap passkey'}
              </button>
              {error !== null && (
                <span className="hvp-msg crit" role="alert" data-testid="hvp-delete-error" style={{ flex: '1 1 100%' }}>
                  {error}
                </span>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
