// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package patch

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecideKBInclusion_ExcludedKBInSecondPositionIsExcluded(t *testing.T) {
	include, reason := decideKBInclusion([]string{"KB5000001", "KB5000002"}, nil, nil, []string{"KB5000002"})

	assert.False(t, include, "an excluded KB in any position must exclude the update")
	assert.Contains(t, reason, "KB5000002")
}

func TestDecideKBInclusion_ReadErrorIsExcluded(t *testing.T) {
	include, reason := decideKBInclusion(nil, errors.New("Item(1) failed"), nil, nil)

	assert.False(t, include, "an update whose KB IDs cannot be read must be excluded")
	assert.Contains(t, reason, "could not be read")
}

func TestDecideKBInclusion_ReadErrorIsExcludedEvenWithIncludedKB(t *testing.T) {
	include, _ := decideKBInclusion([]string{"KB5000001"}, errors.New("Item(1) failed"), []string{"KB5000001"}, nil)

	assert.False(t, include)
}

func TestDecideKBInclusion_EmptyKBListWithIncludeListIsExcluded(t *testing.T) {
	include, reason := decideKBInclusion(nil, nil, []string{"KB5000001"}, nil)

	assert.False(t, include, "an update with no KB ID cannot match an include list")
	assert.NotEmpty(t, reason)
}

func TestDecideKBInclusion_IncludedKBInLaterPositionIsIncluded(t *testing.T) {
	include, reason := decideKBInclusion([]string{"KB5000001", "KB5000002", "KB5000003"}, nil, []string{"KB5000003"}, nil)

	assert.True(t, include, "an included KB in any position must include the update")
	assert.Empty(t, reason)
}

func TestDecideKBInclusion_IncludeListWithoutMatchIsExcluded(t *testing.T) {
	include, reason := decideKBInclusion([]string{"KB5000001", "KB5000002"}, nil, []string{"KB5999999"}, nil)

	assert.False(t, include)
	assert.Contains(t, reason, "include_patches")
}

func TestDecideKBInclusion_ExcludeWinsOverInclude(t *testing.T) {
	include, _ := decideKBInclusion([]string{"KB5000001", "KB5000002"}, nil, []string{"KB5000001"}, []string{"KB5000002"})

	assert.False(t, include)
}

func TestDecideKBInclusion_EmptyListsKeepDefaults(t *testing.T) {
	include, reason := decideKBInclusion(nil, nil, nil, nil)
	assert.True(t, include, "with no lists an update with no KB ID is still included")
	assert.Empty(t, reason)

	include, reason = decideKBInclusion([]string{"KB5000001"}, nil, nil, nil)
	assert.True(t, include, "with no lists a readable update is included")
	assert.Empty(t, reason)
}

func TestDecideKBInclusion_MatchIgnoresCase(t *testing.T) {
	include, _ := decideKBInclusion([]string{"KB5000001"}, nil, nil, []string{"kb5000001"})

	assert.False(t, include)
}

func TestDecideKBInclusion_BareNumberListEntriesMatch(t *testing.T) {
	include, _ := decideKBInclusion([]string{"KB5000001", "KB5000002"}, nil, nil, []string{"5000002"})
	assert.False(t, include, "an exclude entry without the KB prefix must still exclude")

	include, _ = decideKBInclusion([]string{"KB5000001"}, nil, []string{"5000001"}, nil)
	assert.True(t, include, "an include entry without the KB prefix must still include")
}

func TestPatchListFromConfig(t *testing.T) {
	list, err := patchListFromConfig("exclude_patches", []interface{}{"KB5000001", 5000002, int64(5000003), uint64(5000004)})
	assert.NoError(t, err)
	assert.Equal(t, []string{"KB5000001", "5000002", "5000003", "5000004"}, list)

	list, err = patchListFromConfig("exclude_patches", nil)
	assert.NoError(t, err)
	assert.Empty(t, list)

	_, err = patchListFromConfig("exclude_patches", []interface{}{"KB5000001", 1.5})
	assert.ErrorIs(t, err, ErrInvalidConfig, "an unreadable entry must not be dropped")

	_, err = patchListFromConfig("exclude_patches", "KB5000001")
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestKBArticleID(t *testing.T) {
	assert.Equal(t, "KB5012345", kbArticleID("5012345"))
	assert.Equal(t, "KB5012345", kbArticleID(" 5012345 "))
	assert.Equal(t, "KB5012345", kbArticleID("KB5012345"))
	assert.Equal(t, "KB5012345", kbArticleID("kb5012345"))
}
