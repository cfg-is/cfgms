// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// Testing Library's automatic DOM cleanup only registers itself when test
// globals are injected; this project keeps vitest globals off, so register
// it explicitly — otherwise every render() accumulates in one document.
afterEach(() => {
  cleanup()
})

// vitest's jsdom environment on Node 26 exposes no window.localStorage /
// window.sessionStorage (Node's experimental storage global shadows jsdom's
// and is unavailable without --localstorage-file). Provision a spec-shaped
// in-memory Storage so the security A7.2 tests can assert that app code,
// which COULD call the API, never writes to it.
class MemoryStorage implements Storage {
  #data = new Map<string, string>()

  get length(): number {
    return this.#data.size
  }

  clear(): void {
    this.#data.clear()
  }

  getItem(key: string): string | null {
    return this.#data.get(key) ?? null
  }

  key(index: number): string | null {
    return [...this.#data.keys()].at(index) ?? null
  }

  removeItem(key: string): void {
    this.#data.delete(key)
  }

  setItem(key: string, value: string): void {
    this.#data.set(String(key), String(value))
  }
}

if (typeof window !== 'undefined' && window.localStorage === undefined) {
  Object.defineProperty(window, 'localStorage', { value: new MemoryStorage() })
  Object.defineProperty(window, 'sessionStorage', {
    value: new MemoryStorage(),
  })
}
