// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Frontend SAST gate (Story #2488, Epic #2344). All security rules run at
// ERROR severity — `npm run lint` FAILS on any violation. This gate is
// load-bearing for the login screen (#2495) and fleet-overview (#2497/#2498)
// stories: HTML-injection sinks are banned outright.
import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'
import security from 'eslint-plugin-security'

// eslint-plugin-security ships its recommended set at "warn" severity; CFGMS
// runs the entire set at "error" so security findings fail the lint gate.
const securityRulesAtError = Object.fromEntries(
  Object.keys(security.configs.recommended.rules).map((rule) => [
    rule,
    'error',
  ]),
)

// HTML-injection sink bans (error severity). React escapes rendered values by
// default; every construct below bypasses that protection.
const htmlSinkBans = {
  'react/no-danger': 'error',
  'react/no-danger-with-children': 'error',
  'no-restricted-properties': [
    'error',
    {
      property: 'innerHTML',
      message: 'HTML-injection sink. Render through React instead.',
    },
    {
      property: 'outerHTML',
      message: 'HTML-injection sink. Render through React instead.',
    },
    {
      property: 'insertAdjacentHTML',
      message: 'HTML-injection sink. Render through React instead.',
    },
    {
      property: 'dangerouslySetInnerHTML',
      message: 'Banned HTML-injection sink. Render through React instead.',
    },
    {
      object: 'document',
      property: 'write',
      message: 'HTML-injection sink. Render through React instead.',
    },
    {
      object: 'document',
      property: 'writeln',
      message: 'HTML-injection sink. Render through React instead.',
    },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'dangerouslySetInnerHTML is banned (HTML-injection sink).',
    },
  ],
  // Runtime code composition is banned repo-wide (CLAUDE.md banned patterns).
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
}

export default tseslint.config(
  { ignores: ['dist/', 'coverage/', 'node_modules/'] },
  // Application and tooling TypeScript (src/, vite.config.ts).
  {
    files: ['**/*.{ts,tsx}'],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    plugins: {
      react,
      'react-hooks': reactHooks,
      security,
    },
    languageOptions: {
      globals: { ...globals.browser },
    },
    settings: {
      react: { version: 'detect' },
    },
    rules: {
      ...react.configs.flat.recommended.rules,
      ...react.configs.flat['jsx-runtime'].rules,
      ...reactHooks.configs['recommended-latest'].rules,
      ...securityRulesAtError,
      ...htmlSinkBans,
    },
  },
  // This config file itself.
  {
    files: ['**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
)
