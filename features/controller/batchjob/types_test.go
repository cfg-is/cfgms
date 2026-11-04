// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestBatchJobStatusConstants(t *testing.T) {
	assert.Equal(t, business.BatchJobStatus("pending"), business.BatchJobStatusPending)
	assert.Equal(t, business.BatchJobStatus("running"), business.BatchJobStatusRunning)
	assert.Equal(t, business.BatchJobStatus("paused"), business.BatchJobStatusPaused)
	assert.Equal(t, business.BatchJobStatus("completed"), business.BatchJobStatusCompleted)
	assert.Equal(t, business.BatchJobStatus("failed"), business.BatchJobStatusFailed)
	assert.Equal(t, business.BatchJobStatus("rolled_back"), business.BatchJobStatusRolledBack)
}

func TestBatchStepStatusConstants(t *testing.T) {
	assert.Equal(t, business.BatchStepStatus("pending"), business.BatchStepStatusPending)
	assert.Equal(t, business.BatchStepStatus("running"), business.BatchStepStatusRunning)
	assert.Equal(t, business.BatchStepStatus("completed"), business.BatchStepStatusCompleted)
	assert.Equal(t, business.BatchStepStatus("failed"), business.BatchStepStatusFailed)
	assert.Equal(t, business.BatchStepStatus("rolled_back"), business.BatchStepStatusRolledBack)
}

func TestBatchStepZeroValue(t *testing.T) {
	var s business.BatchStep
	assert.Equal(t, 0, s.Index)
	assert.Nil(t, s.StewardIDs)
	assert.Equal(t, business.BatchStepStatus(""), s.Status)
	assert.Nil(t, s.StartedAt)
	assert.Nil(t, s.CompletedAt)
	assert.Nil(t, s.FailedIDs)
	assert.Empty(t, s.RollbackJobID)
}

func TestBatchJobConfigZeroValue(t *testing.T) {
	var c business.BatchJobConfig
	assert.Equal(t, 0, c.BatchSize)
	assert.Empty(t, c.PreviousConfigRef)
}

func TestBatchJobZeroValue(t *testing.T) {
	var j business.BatchJob
	assert.Empty(t, j.ID)
	assert.Empty(t, j.TenantID)
	assert.Empty(t, j.Selector)
	assert.Nil(t, j.Targets)
	assert.Equal(t, business.BatchJobStatus(""), j.Status)
	assert.Nil(t, j.Steps)
	assert.True(t, j.CreatedAt.IsZero())
	assert.True(t, j.UpdatedAt.IsZero())
	assert.Empty(t, j.InitiatedBy)
}

func TestBatchStepFields(t *testing.T) {
	now := time.Now().UTC()
	completed := now.Add(time.Minute)
	s := business.BatchStep{
		Index:         2,
		StewardIDs:    []string{"s-1", "s-2"},
		Status:        business.BatchStepStatusRunning,
		StartedAt:     &now,
		CompletedAt:   &completed,
		FailedIDs:     []string{"s-2"},
		RollbackJobID: "rj-abc",
	}
	assert.Equal(t, 2, s.Index)
	assert.Equal(t, []string{"s-1", "s-2"}, s.StewardIDs)
	assert.Equal(t, business.BatchStepStatusRunning, s.Status)
	assert.Equal(t, &now, s.StartedAt)
	assert.Equal(t, &completed, s.CompletedAt)
	assert.Equal(t, []string{"s-2"}, s.FailedIDs)
	assert.Equal(t, "rj-abc", s.RollbackJobID)
}

func TestBatchJobFields(t *testing.T) {
	now := time.Now().UTC()
	j := business.BatchJob{
		ID:       "job-1",
		TenantID: "tenant-1",
		Selector: "tag:prod",
		Config: business.BatchJobConfig{
			BatchSize:         10,
			PreviousConfigRef: "v1.2",
		},
		Targets:     []string{"s-1", "s-2"},
		Status:      business.BatchJobStatusPending,
		Steps:       []business.BatchStep{{Index: 0, StewardIDs: []string{"s-1"}}},
		CreatedAt:   now,
		UpdatedAt:   now,
		InitiatedBy: "operator@example.com",
	}
	assert.Equal(t, "job-1", j.ID)
	assert.Equal(t, "tenant-1", j.TenantID)
	assert.Equal(t, "tag:prod", j.Selector)
	assert.Equal(t, 10, j.Config.BatchSize)
	assert.Equal(t, "v1.2", j.Config.PreviousConfigRef)
	assert.Equal(t, []string{"s-1", "s-2"}, j.Targets)
	assert.Equal(t, business.BatchJobStatusPending, j.Status)
	assert.Len(t, j.Steps, 1)
	assert.Equal(t, now, j.CreatedAt)
	assert.Equal(t, now, j.UpdatedAt)
	assert.Equal(t, "operator@example.com", j.InitiatedBy)
}
