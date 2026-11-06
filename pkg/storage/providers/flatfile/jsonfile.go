// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/pkg/atomicfile"
)

// loadJSONSlice reads and parses a single-file JSON array store. A missing
// file yields a nil slice. what names the file in error messages, e.g.
// "nonce" produces "flatfile: failed to read nonce file: ...".
//
// atomicfile.ReadFile retries Windows ERROR_SHARING_VIOLATION from a
// concurrent writer's in-flight rename; on POSIX it is a direct read.
func loadJSONSlice[T any](path, what string) ([]T, error) {
	raw, err := atomicfile.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read %s file: %w", what, err)
	}
	var items []T
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse %s file: %w", what, err)
	}
	return items, nil
}

// loadJSONMap reads and parses a single-file JSON object store keyed by
// string. A missing or empty file yields an empty, non-nil map. what names
// the file in error messages as for loadJSONSlice.
func loadJSONMap[T any](path, what string) (map[string]T, error) {
	raw, err := atomicfile.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]T{}, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read %s file: %w", what, err)
	}
	entries := map[string]T{}
	if len(raw) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse %s file: %w", what, err)
	}
	return entries, nil
}

// saveJSONSlice atomically writes items as an indented JSON array. A nil
// slice is written as [] so a later load sees an empty store rather than
// null. what names the payload in error messages, e.g. "nonce entries".
func saveJSONSlice[T any](path string, items []T, what string) error {
	if items == nil {
		items = []T{}
	}
	return saveJSONIndented(path, items, what)
}

// saveJSONMap atomically writes entries as an indented JSON object. what
// names the payload in error messages as for saveJSONSlice.
func saveJSONMap[T any](path string, entries map[string]T, what string) error {
	return saveJSONIndented(path, entries, what)
}

func saveJSONIndented(path string, v any, what string) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal %s: %w", what, err)
	}
	return writeAtomic(path, raw)
}

// ensureStoreDir creates <root>/<subdir> for a single-file store. label names
// the directory in the error message, e.g. "routing" produces
// "flatfile: failed to create routing directory: ...".
func ensureStoreDir(root, subdir, label string) error {
	if err := os.MkdirAll(filepath.Join(root, subdir), dirMode); err != nil {
		return fmt.Errorf("flatfile: failed to create %s directory: %w", label, err)
	}
	return nil
}
