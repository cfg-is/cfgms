// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

/*
 * Login screen (Story #2993) — passkey-only rebuild (ADR-021 Amendment 1).
 * Design: docs/design/mockups/login.html (passkey-only login · usernameless-first hybrid).
 *
 * States (mockup): signin (default), waiting (ceremony in progress), invalid (no passkey), expired.
 *
 * "Remember Username" persists the optional username prefill to localStorage
 * (cfgms.login.username — a display preference, not auth data per A7.2).
 */
import { useState } from 'react'
import { useAuth } from '../auth/AuthContext.tsx'
import './Login.css'

export default function Login() {
  const { status, login } = useAuth()
  const [username, setUsername] = useState(
    () => localStorage.getItem('cfgms.login.username') ?? '',
  )
  const [rememberUsername, setRememberUsername] = useState(true)
  const [submitting, setSubmitting] = useState(false)

  const showExpired = status === 'expired' && !submitting
  const showInvalid = status === 'invalid' && !submitting

  async function handleSignIn() {
    if (submitting) return
    if (rememberUsername) {
      localStorage.setItem('cfgms.login.username', username)
    } else {
      localStorage.removeItem('cfgms.login.username')
    }
    setSubmitting(true)
    try {
      await login(username || undefined)
    } finally {
      setSubmitting(false)
    }
  }

  // Waiting state: ceremony is in progress (navigator.credentials.get pending).
  if (submitting) {
    return (
      <div className="login-stage">
        <div className="login-win">
          <div className="login-titlebar">
            <span className="login-title mono">cfgms · secure session</span>
          </div>
          <div className="login-body">
            <div className="login-wordmark">
              <b>CFGMS</b>
              <span>config management</span>
            </div>
            <div className="login-waiting">
              <div className="login-waiting-icon" aria-hidden="true">
                {/* Lucide "key" icon (ISC) */}
                <svg
                  width="26"
                  height="26"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.9"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <circle cx="7.5" cy="15.5" r="5.5" />
                  <path d="m21 2-9.6 9.6" />
                  <path d="m15.5 7.5 3 3L22 7l-3-3" />
                </svg>
              </div>
              <h3 className="login-waiting-heading">Waiting for your passkey</h3>
              <p className="login-waiting-desc">
                Confirm on your security key or device to finish signing in.
              </p>
              <button
                type="button"
                className="login-waiting-cancel"
                onClick={() => setSubmitting(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="login-stage">
      <div className="login-win">
        <div className="login-titlebar">
          <span className="login-title mono">cfgms · secure session</span>
        </div>

        <div className="login-body">
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
              <span>Your session expired. Sign in again with your passkey to continue.</span>
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
              placeholder="Username (Optional)"
              className={showInvalid ? 'is-invalid' : undefined}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void handleSignIn()
              }}
            />
          </div>

          <label className={`login-remember${rememberUsername ? ' login-remember--on' : ''}`}>
            <span className="login-remember-cbx" aria-hidden="true">
              {rememberUsername && (
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
                  <path
                    d="M5 12.5l4.2 4.2L19 7"
                    stroke="currentColor"
                    strokeWidth="2.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              )}
            </span>
            <input
              type="checkbox"
              className="login-remember-input"
              checked={rememberUsername}
              onChange={(e) => setRememberUsername(e.target.checked)}
            />
            Remember Username
          </label>

          {showInvalid && (
            <div className="login-err" role="alert">
              <span className="login-err-dot" aria-hidden="true" />
              No passkey matched. Check the username, or use the key that holds this account.
            </div>
          )}

          <button
            className="login-signin"
            type="button"
            onClick={() => void handleSignIn()}
          >
            {/* Lucide "key" icon (ISC) */}
            <svg
              width="17"
              height="17"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <circle cx="7.5" cy="15.5" r="5.5" />
              <path d="m21 2-9.6 9.6" />
              <path d="m15.5 7.5 3 3L22 7l-3-3" />
            </svg>
            <span className="login-signin-txt">Sign in with a passkey</span>
          </button>

          <p className="login-helper">
            Your passkey never leaves your device. No password to phish.
          </p>

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
        </div>
      </div>
    </div>
  )
}
