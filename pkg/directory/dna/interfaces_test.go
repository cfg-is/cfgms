// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConvertProtobufToTime_Nil(t *testing.T) {
	result := convertProtobufToTime(nil)
	assert.Nil(t, result)
}

func TestConvertProtobufToTime_ZeroTimestamp(t *testing.T) {
	zero := &timestamppb.Timestamp{}
	result := convertProtobufToTime(zero)
	require.NotNil(t, result)
	assert.Equal(t, zero.AsTime(), *result)
}

func TestConvertProtobufToTime_RealTimestamp(t *testing.T) {
	someTime := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	ts := timestamppb.New(someTime)
	result := convertProtobufToTime(ts)
	require.NotNil(t, result)
	assert.Equal(t, someTime, *result)
}
