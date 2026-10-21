// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package patch

import (
	"fmt"
	"strconv"
	"strings"
)

// decideKBInclusion decides whether an update carrying the KB article IDs
// kbIDs passes the include and exclude lists. readErr is the error from
// reading those IDs, if any. It fails closed: an update whose IDs could not
// be read is excluded, an update is excluded when any of its IDs is in
// exclude, and when include is non-empty an update is included only when at
// least one of its IDs is in include (so an update with no ID is excluded).
// With both lists empty every readable update is included. A non-empty reason
// says why the update was excluded. IDs compare case-insensitively.
func decideKBInclusion(kbIDs []string, readErr error, include, exclude []string) (bool, string) {
	if readErr != nil {
		return false, fmt.Sprintf("KB article IDs could not be read: %v", readErr)
	}
	for _, id := range kbIDs {
		if containsKB(exclude, id) {
			return false, fmt.Sprintf("%s is in exclude_patches", id)
		}
	}
	if len(include) == 0 {
		return true, ""
	}
	if len(kbIDs) == 0 {
		return false, "update has no KB article ID and include_patches is set"
	}
	for _, id := range kbIDs {
		if containsKB(include, id) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("none of %s is in include_patches", strings.Join(kbIDs, ", "))
}

// containsKB reports whether list holds id, ignoring case. List entries are
// normalised with kbArticleID first, so "5012345" and "KB5012345" both match.
func containsKB(list []string, id string) bool {
	for _, entry := range list {
		if strings.EqualFold(kbArticleID(entry), id) {
			return true
		}
	}
	return false
}

// patchListFromConfig reads the include_patches or exclude_patches value of a
// config map. A list of strings is returned as is; integer entries (YAML
// "- 5012345") become their decimal string. Any other value or entry type is
// an ErrInvalidConfig error rather than a dropped entry. A missing value is an
// empty list.
func patchListFromConfig(field string, value interface{}) ([]string, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case []string:
		return v, nil
	case []interface{}:
		list := make([]string, 0, len(v))
		for i, entry := range v {
			switch e := entry.(type) {
			case string:
				list = append(list, e)
			case int:
				list = append(list, strconv.Itoa(e))
			case int64:
				list = append(list, strconv.FormatInt(e, 10))
			case uint64:
				list = append(list, strconv.FormatUint(e, 10))
			default:
				return nil, fmt.Errorf("%w: %s entry %d must be a KB article ID", ErrInvalidConfig, field, i)
			}
		}
		return list, nil
	default:
		return nil, fmt.Errorf("%w: %s must be a list of KB article IDs", ErrInvalidConfig, field)
	}
}

// kbArticleID formats a KB article number as reported by Windows Update
// ("5012345") as the ID the include and exclude lists use ("KB5012345").
func kbArticleID(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && strings.EqualFold(raw[:2], "KB") {
		return "KB" + raw[2:]
	}
	return "KB" + raw
}
