// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Login screen (Story #2495) — canonical design:
 * docs/design/mockups/login.html; identity per
 * docs/design/web-ui-design-system.md §5.1 (terminal-window card — the one
 * place the Ubuntu-Mono terminal accent is spent).
 *
 * States (mockup): signin (default), loading, invalid, expired. The `mfa`
 * state is a designed seam built later — deliberately not implemented here.
 */
import { useState, type FormEvent } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import './Login.css'

export default function Login() {
  const { status, login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)

  // Mockup entry states: fresh visit (signin) vs 401-triggered (expired).
  const showExpired = status === 'expired' && !submitting
  const showInvalid = status === 'invalid' && !submitting

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitting) return
    setSubmitting(true)
    try {
      const ok = await login(username, password)
      if (ok) {
        // The guard swaps this screen out; clear the secret regardless.
        setPassword('')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-stage">
      <div className="login-win">
        <div className="login-titlebar">
          <span className="login-title mono">cfgms · secure session</span>
        </div>

        <form className="login-body" onSubmit={handleSubmit}>
          <div className="login-wordmark">
            <b>CFGMS</b>
            <span>config management</span>
          </div>
          <p className="login-lead">Sign in to the controller</p>

          {showExpired && (
            <div className="login-expired" role="alert">
              <span className="mono" aria-hidden="true">
                ⚠
              </span>
              <span>Your session expired. Sign in again to continue.</span>
            </div>
          )}

          <div className="login-field">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              name="username"
              type="text"
              autoComplete="username"
              autoFocus
              className={showInvalid ? 'is-invalid' : undefined}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="login-field">
            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              name="password"
              type="password"
              autoComplete="current-password"
              className={showInvalid ? 'is-invalid' : undefined}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {showInvalid && (
            <div className="login-err" role="alert">
              <span className="login-err-dot" aria-hidden="true" />
              Invalid username or password.
            </div>
          )}

          <button className="login-signin" type="submit" disabled={submitting}>
            {submitting && <span className="login-spin" aria-hidden="true" />}
            <span className="login-signin-txt">Sign in</span>
          </button>

          <div className="login-foot">
            <a
              href="https://github.com/cfg-is/cfgms/blob/main/docs/README.md"
              rel="noreferrer"
              target="_blank"
            >
              Trouble signing in?
            </a>
            <span className="mono">© 2026 cfg.is</span>
          </div>
        </form>
      </div>
    </div>
  )
}
