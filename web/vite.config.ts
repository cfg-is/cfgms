// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Single-source design tokens (founder-owned, consumed read-only).
// The alias is the ONLY binding to the token file — web/ must never carry a
// forked copy of token values. See web/README.md ("Design tokens").
const designTokens = fileURLToPath(
  new URL('../docs/design/web-ui-design-tokens.css', import.meta.url),
)

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@design-tokens': designTokens,
    },
  },
  build: {
    // Build into dist/app/, not dist/, so the build never rewrites the tracked
    // dist/index.html placeholder. web/.gitignore excludes dist/* wholesale, so
    // built output stays untracked and concurrent web branches stop conflicting
    // on a content-hashed entry point (Issue #3043). The controller serves
    // dist/app when present and refuses to route "/" when only the placeholder
    // is embedded — see features/controller/api/spa.go.
    outDir: 'dist/app',
  },
  server: {
    fs: {
      // The token file lives outside web/ (repo docs/design/); allow the dev
      // server to serve it in addition to the app root.
      allow: ['.', designTokens],
    },
    proxy: {
      // Dev-only proxy to a locally running controller REST API
      // (default listen addr 0.0.0.0:9080, TLS via auto-generated CA).
      // `secure: false` accepts the controller's self-signed dev certificate
      // and is a DEV-ONLY setting — production serves the app from the
      // controller itself, so no proxy exists there. See web/README.md.
      '/api': {
        target: 'https://localhost:9080',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})
