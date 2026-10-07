// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/controller/batchjob"
)

func TestBatchJobStatusConstants(t *testing.T) {
	assert.Equal(t, batchjob.BatchJobStatus("pending"), batchjob.BatchJobStatusPending)
	assert.Equal(t, batchjob.BatchJobStatus("running"), batchjob.BatchJobStatusRunning)
	assert.Equal(t, batchjob.BatchJobStatus("paused"), batchjob.BatchJobStatusPaused)
	assert.Equal(t, batchjob.BatchJobStatus("completed"), batchjob.BatchJobStatusCompleted)
	assert.Equal(t, batchjob.BatchJobStatus("failed"), batchjob.BatchJobStatusFailed)
	assert.Equal(t, batchjob.BatchJobStatus("rolled_back"), batchjob.BatchJobStatusRolledBack)
}

func TestBatchStepStatusConstants(t *testing.T) {
	assert.Equal(t, batchjob.BatchStepStatus("pending"), batchjob.BatchStepStatusPending)
	assert.Equal(t, batchjob.BatchStepStatus("running"), batchjob.BatchStepStatusRunning)
	assert.Equal(t, batchjob.BatchStepStatus("completed"), batchjob.BatchStepStatusCompleted)
	assert.Equal(t, batchjob.BatchStepStatus("failed"), batchjob.BatchStepStatusFailed)
	assert.Equal(t, batchjob.BatchStepStatus("rolled_back"), batchjob.BatchStepStatusRolledBack)
}

func TestBatchStepZeroValue(t *testing.T) {
	var s batchjob.BatchStep
	assert.Equal(t, 0, s.Index)
	assert.Nil(t, s.StewardIDs)
	assert.Equal(t, batchjob.BatchStepStatus(""), s.Status)
	assert.Nil(t, s.StartedAt)
	assert.Nil(t, s.CompletedAt)
	assert.Nil(t, s.FailedIDs)
	assert.Empty(t, s.RollbackJobID)
}

func TestBatchJobConfigZeroValue(t *testing.T) {
	var c batchjob.BatchJobConfig
	assert.Equal(t, 0, c.BatchSize)
	assert.Empty(t, c.PreviousConfigRef)
}

func TestBatchJobZeroValue(t *testing.T) {
	var j batchjob.BatchJob
	assert.Empty(t, j.ID)
	assert.Empty(t, j.TenantID)
	assert.Empty(t, j.Selector)
	assert.Nil(t, j.Targets)
	assert.Equal(t, batchjob.BatchJobStatus(""), j.Status)
	assert.Nil(t, j.Steps)
	assert.True(t, j.CreatedAt.IsZero())
	assert.True(t, j.UpdatedAt.IsZero())
	assert.Empty(t, j.InitiatedBy)
}

func TestBatchStepFields(t *testing.T) {
	now := time.Now().UTC()
	completed := now.Add(time.Minute)
	s := batchjob.BatchStep{
		Index:         2,
		StewardIDs:    []string{"s-1", "s-2"},
		Status:        batchjob.BatchStepStatusRunning,
		StartedAt:     &now,
		CompletedAt:   &completed,
		FailedIDs:     []string{"s-2"},
		RollbackJobID: "rj-abc",
	}
	assert.Equal(t, 2, s.Index)
	assert.Equal(t, []string{"s-1", "s-2"}, s.StewardIDs)
	assert.Equal(t, batchjob.BatchStepStatusRunning, s.Status)
	assert.Equal(t, &now, s.StartedAt)
	assert.Equal(t, &completed, s.CompletedAt)
	assert.Equal(t, []string{"s-2"}, s.FailedIDs)
	assert.Equal(t, "rj-abc", s.RollbackJobID)
}

func TestBatchJobFields(t *testing.T) {
	now := time.Now().UTC()
	j := batchjob.BatchJob{
		ID:       "job-1",
		TenantID: "tenant-1",
		Selector: "tag:prod",
		Config: batchjob.BatchJobConfig{
			BatchSize:         10,
			PreviousConfigRef: "v1.2",
		},
		Targets:     []string{"s-1", "s-2"},
		Status:      batchjob.BatchJobStatusPending,
		Steps:       []batchjob.BatchStep{{Index: 0, StewardIDs: []string{"s-1"}}},
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
	assert.Equal(t, batchjob.BatchJobStatusPending, j.Status)
	assert.Len(t, j.Steps, 1)
	assert.Equal(t, now, j.CreatedAt)
	assert.Equal(t, now, j.UpdatedAt)
	assert.Equal(t, "operator@example.com", j.InitiatedBy)
}
