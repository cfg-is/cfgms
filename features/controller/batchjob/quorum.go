// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package batchjob

var _ QuorumChecker = (*DnaRoleQuorumChecker)(nil)

// DnaRoleQuorumChecker implements QuorumChecker using the dna.cluster_role
// DNA attribute to guarantee that no batch contains two stewards with the same
// non-empty cluster_role value. This prevents a rolling update from taking
// down an entire Hyper-V cluster or SQL Availability Group simultaneously.
//
// Stateless — construct with NewDnaRoleQuorumChecker().
type DnaRoleQuorumChecker struct{}

// NewDnaRoleQuorumChecker returns a stateless DnaRoleQuorumChecker.
func NewDnaRoleQuorumChecker() *DnaRoleQuorumChecker {
	return &DnaRoleQuorumChecker{}
}

// Partition splits stewards into batches such that no two stewards with the
// same non-empty cluster_role appear in the same batch.
//
// Algorithm:
//  1. Separate stewards by whether they carry a non-empty cluster_role.
//  2. Group role-bearing stewards by their cluster_role value.
//  3. Round-robin across groups one round at a time: pick one steward from
//     each active group per round. If the batch fills before the round
//     completes, flush the full batch (with any queued plain stewards) and
//     continue the current round into a new batch.
//  4. At the end of each round, fill remaining batch slots with plain (no-role)
//     stewards and flush.
//  5. Any leftover plain stewards form additional naively-partitioned batches.
//
// Edge case: a single group with more members than batchSize produces batches
// of exactly one role-bearing steward each (may be smaller than batchSize if
// no plain stewards are available). Empty input returns nil.
func (c *DnaRoleQuorumChecker) Partition(stewards []StewardMeta, batchSize int) [][]string {
	if len(stewards) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = len(stewards)
	}

	// Separate role-bearing stewards into named groups and collect plain stewards.
	// groupOrder preserves deterministic iteration order.
	groups := make(map[string][]string)
	groupOrder := make([]string, 0)
	var plain []string

	for _, s := range stewards {
		role := s.DNAAttributes["cluster_role"]
		if role == "" {
			plain = append(plain, s.ID)
			continue
		}
		if _, exists := groups[role]; !exists {
			groupOrder = append(groupOrder, role)
		}
		groups[role] = append(groups[role], s.ID)
	}

	// No role-bearing stewards — fall back to naive partitioning.
	if len(groupOrder) == 0 {
		return naivePartition(plain, batchSize)
	}

	cursors := make(map[string]int, len(groupOrder))
	plainIdx := 0
	var batches [][]string
	var currentBatch []string

	for {
		madeProgress := false

		// One round: take at most ONE steward from each group.
		for _, role := range groupOrder {
			cur := cursors[role]
			if cur >= len(groups[role]) {
				continue // group exhausted
			}

			// Current batch is full — flush with plain filler, start fresh.
			if len(currentBatch) >= batchSize {
				currentBatch, plainIdx = fillWithPlain(currentBatch, plain, plainIdx, batchSize)
				batches = append(batches, currentBatch)
				currentBatch = nil
			}

			currentBatch = append(currentBatch, groups[role][cur])
			cursors[role] = cur + 1
			madeProgress = true
		}

		if !madeProgress {
			break
		}

		// End of this round: fill remaining slots with plain stewards and flush.
		currentBatch, plainIdx = fillWithPlain(currentBatch, plain, plainIdx, batchSize)
		batches = append(batches, currentBatch)
		currentBatch = nil
	}

	// Emit any remaining plain stewards as additional naive batches.
	for plainIdx < len(plain) {
		size := batchSize
		if size > len(plain)-plainIdx {
			size = len(plain) - plainIdx
		}
		batches = append(batches, plain[plainIdx:plainIdx+size])
		plainIdx += size
	}

	return batches
}

// fillWithPlain appends plain stewards into batch until it reaches batchSize.
// Returns the updated batch and the next unconsumed plain index.
func fillWithPlain(batch, plain []string, plainIdx, batchSize int) ([]string, int) {
	for len(batch) < batchSize && plainIdx < len(plain) {
		batch = append(batch, plain[plainIdx])
		plainIdx++
	}
	return batch, plainIdx
}
