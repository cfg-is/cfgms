// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package dna - Directory Relationships Collection
//
// This file implements relationship collection for directory objects,
// providing comprehensive mapping of directory object relationships
// for enhanced drift detection and dependency tracking.

package dna

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// Batch Collection Methods (continuation of collector.go)

// collectUserBatchDNA collects DNA for a batch of users with concurrency control.
func (c *DefaultDirectoryDNACollector) collectUserBatchDNA(ctx context.Context, users []interfaces.DirectoryUser) ([]*DirectoryDNA, error) {
	startTime := time.Now()

	// Control concurrency
	semaphore := make(chan struct{}, c.config.MaxConcurrency)
	var wg sync.WaitGroup

	results := make(chan *DirectoryDNA, len(users))
	errors := make(chan error, len(users))

	// Process users concurrently
	for _, user := range users {
		wg.Add(1)
		go func(u interfaces.DirectoryUser) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			dna, err := c.CollectUserDNA(ctx, u.ID)
			if err != nil {
				errors <- fmt.Errorf("failed to collect DNA for user %s: %w", u.ID, err)
				return
			}

			results <- dna
		}(user)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Collect results and errors
	var allDNA []*DirectoryDNA
	var allErrors []error

	for results != nil || errors != nil {
		select {
		case dna, ok := <-results:
			if !ok {
				results = nil
			} else {
				allDNA = append(allDNA, dna)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				allErrors = append(allErrors, err)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	duration := time.Since(startTime)
	c.logger.Debug("Completed user batch DNA collection",
		"batch_size", len(users),
		"successful", len(allDNA),
		"errors", len(allErrors),
		"duration", duration)

	// If we have errors but also some results, log errors but return partial results
	if len(allErrors) > 0 {
		c.logger.Warn("User batch collection completed with errors",
			"successful", len(allDNA),
			"errors", len(allErrors))
	}

	return allDNA, nil
}

// collectGroupBatchDNA collects DNA for a batch of groups with concurrency control.
func (c *DefaultDirectoryDNACollector) collectGroupBatchDNA(ctx context.Context, groups []interfaces.DirectoryGroup) ([]*DirectoryDNA, error) {
	startTime := time.Now()

	// Control concurrency
	semaphore := make(chan struct{}, c.config.MaxConcurrency)
	var wg sync.WaitGroup

	results := make(chan *DirectoryDNA, len(groups))
	errors := make(chan error, len(groups))

	// Process groups concurrently
	for _, group := range groups {
		wg.Add(1)
		go func(g interfaces.DirectoryGroup) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			dna, err := c.CollectGroupDNA(ctx, g.ID)
			if err != nil {
				errors <- fmt.Errorf("failed to collect DNA for group %s: %w", g.ID, err)
				return
			}

			results <- dna
		}(group)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Collect results and errors
	var allDNA []*DirectoryDNA
	var allErrors []error

	for results != nil || errors != nil {
		select {
		case dna, ok := <-results:
			if !ok {
				results = nil
			} else {
				allDNA = append(allDNA, dna)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				allErrors = append(allErrors, err)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	duration := time.Since(startTime)
	c.logger.Debug("Completed group batch DNA collection",
		"batch_size", len(groups),
		"successful", len(allDNA),
		"errors", len(allErrors),
		"duration", duration)

	// If we have errors but also some results, log errors but return partial results
	if len(allErrors) > 0 {
		c.logger.Warn("Group batch collection completed with errors",
			"successful", len(allDNA),
			"errors", len(allErrors))
	}

	return allDNA, nil
}

// collectOUBatchDNA collects DNA for a batch of organizational units with concurrency control.
func (c *DefaultDirectoryDNACollector) collectOUBatchDNA(ctx context.Context, ous []interfaces.OrganizationalUnit) ([]*DirectoryDNA, error) {
	startTime := time.Now()

	// Control concurrency
	semaphore := make(chan struct{}, c.config.MaxConcurrency)
	var wg sync.WaitGroup

	results := make(chan *DirectoryDNA, len(ous))
	errors := make(chan error, len(ous))

	// Process OUs concurrently
	for _, ou := range ous {
		wg.Add(1)
		go func(o interfaces.OrganizationalUnit) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			dna, err := c.CollectOUDNA(ctx, o.ID)
			if err != nil {
				errors <- fmt.Errorf("failed to collect DNA for OU %s: %w", o.ID, err)
				return
			}

			results <- dna
		}(ou)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	// Collect results and errors
	var allDNA []*DirectoryDNA
	var allErrors []error

	for results != nil || errors != nil {
		select {
		case dna, ok := <-results:
			if !ok {
				results = nil
			} else {
				allDNA = append(allDNA, dna)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				allErrors = append(allErrors, err)
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	duration := time.Since(startTime)
	c.logger.Debug("Completed OU batch DNA collection",
		"batch_size", len(ous),
		"successful", len(allDNA),
		"errors", len(allErrors),
		"duration", duration)

	// If we have errors but also some results, log errors but return partial results
	if len(allErrors) > 0 {
		c.logger.Warn("OU batch collection completed with errors",
			"successful", len(allDNA),
			"errors", len(allErrors))
	}

	return allDNA, nil
}

// Relationship Collection Methods

// CollectRelationships collects relationships for a specific directory object.
func (c *DefaultDirectoryDNACollector) CollectRelationships(ctx context.Context, objectID string) (*DirectoryRelationships, error) {
	startTime := time.Now()
	c.logger.Debug("Collecting relationships", "object_id", objectID)

	relationships := &DirectoryRelationships{
		ObjectID:    objectID,
		CollectedAt: time.Now(),
		Provider:    c.provider.GetProviderInfo().Name,
		TenantID:    c.config.TenantID,
	}

	// First, try to determine the object type
	objectType, err := c.determineObjectType(ctx, objectID)
	if err != nil {
		return nil, fmt.Errorf("failed to determine object type for %s: %w", objectID, err)
	}

	relationships.ObjectType = objectType

	// Collect relationships based on object type
	switch objectType {
	case interfaces.DirectoryObjectTypeUser:
		err = c.collectUserRelationships(ctx, objectID, relationships)
	case interfaces.DirectoryObjectTypeGroup:
		err = c.collectGroupRelationships(ctx, objectID, relationships)
	case interfaces.DirectoryObjectTypeOU:
		err = c.collectOURelationships(ctx, objectID, relationships)
	default:
		return nil, fmt.Errorf("unsupported object type: %s", objectType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to collect relationships for %s: %w", objectID, err)
	}

	c.logger.Debug("Relationships collected successfully",
		"object_id", objectID,
		"object_type", objectType,
		"member_of_count", len(relationships.MemberOf),
		"members_count", len(relationships.Members),
		"duration", time.Since(startTime))

	return relationships, nil
}

// collectUserRelationships collects relationships for a user object.
func (c *DefaultDirectoryDNACollector) collectUserRelationships(ctx context.Context, userID string, relationships *DirectoryRelationships) error {
	// Get user groups
	groups, err := c.provider.GetUserGroups(ctx, userID)
	if err != nil {
		c.logger.Warn("Failed to get user groups", "user_id", userID, "error", err)
		// Continue with other relationships rather than failing completely
	} else {
		for _, group := range groups {
			relationships.MemberOf = append(relationships.MemberOf, group.ID)
		}
	}

	// Get user details for manager and OU information
	user, err := c.provider.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user details: %w", err)
	}

	// Set manager relationship
	if user.Manager != "" {
		relationships.Manager = user.Manager
	}

	// Set OU relationship
	if user.OU != "" {
		relationships.ParentOU = user.OU
	}

	return nil
}

// collectGroupRelationships collects relationships for a group object.
func (c *DefaultDirectoryDNACollector) collectGroupRelationships(ctx context.Context, groupID string, relationships *DirectoryRelationships) error {
	// Get group members
	members, err := c.provider.GetGroupMembers(ctx, groupID)
	if err != nil {
		c.logger.Warn("Failed to get group members", "group_id", groupID, "error", err)
		// Continue with other relationships rather than failing completely
	} else {
		for _, member := range members {
			relationships.Members = append(relationships.Members, member.ID)
		}
	}

	// Get group details for OU information
	group, err := c.provider.GetGroup(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group details: %w", err)
	}

	// Set OU relationship
	if group.OU != "" {
		relationships.ParentOU = group.OU
	}

	return nil
}

// collectOURelationships collects relationships for an OU object.
func (c *DefaultDirectoryDNACollector) collectOURelationships(ctx context.Context, ouID string, relationships *DirectoryRelationships) error {
	// Get OU details
	ou, err := c.provider.GetOU(ctx, ouID)
	if err != nil {
		return fmt.Errorf("failed to get OU details: %w", err)
	}

	// Set parent OU relationship
	if ou.ParentOU != "" {
		relationships.ParentOU = ou.ParentOU
	}

	// Find child OUs by listing all OUs and filtering
	ouList, err := c.provider.ListOUs(ctx, &interfaces.SearchFilters{
		Limit: 1000, // Reasonable limit for OU hierarchies
	})
	if err != nil {
		c.logger.Warn("Failed to list OUs for hierarchy", "ou_id", ouID, "error", err)
	} else {
		for _, childOU := range ouList.OUs {
			if childOU.ParentOU == ouID {
				relationships.ChildOUs = append(relationships.ChildOUs, childOU.ID)
			}
		}
	}

	// Find users in this OU
	userList, err := c.provider.ListUsers(ctx, &interfaces.SearchFilters{
		OU:    ouID,
		Limit: 1000, // Reasonable limit for users in an OU
	})
	if err != nil {
		c.logger.Warn("Failed to list users in OU", "ou_id", ouID, "error", err)
	} else {
		for _, user := range userList.Users {
			relationships.UsersInOU = append(relationships.UsersInOU, user.ID)
		}
	}

	// Find groups in this OU
	groupList, err := c.provider.ListGroups(ctx, &interfaces.SearchFilters{
		OU:    ouID,
		Limit: 1000, // Reasonable limit for groups in an OU
	})
	if err != nil {
		c.logger.Warn("Failed to list groups in OU", "ou_id", ouID, "error", err)
	} else {
		for _, group := range groupList.Groups {
			relationships.GroupsInOU = append(relationships.GroupsInOU, group.ID)
		}
	}

	return nil
}

// determineObjectType determines the type of a directory object by its ID.
func (c *DefaultDirectoryDNACollector) determineObjectType(ctx context.Context, objectID string) (interfaces.DirectoryObjectType, error) {
	// Try to get as user first
	_, err := c.provider.GetUser(ctx, objectID)
	if err == nil {
		return interfaces.DirectoryObjectTypeUser, nil
	}

	// Try to get as group
	_, err = c.provider.GetGroup(ctx, objectID)
	if err == nil {
		return interfaces.DirectoryObjectTypeGroup, nil
	}

	// Try to get as OU
	_, err = c.provider.GetOU(ctx, objectID)
	if err == nil {
		return interfaces.DirectoryObjectTypeOU, nil
	}

	return "", fmt.Errorf("object %s not found in any directory object type", objectID)
}

// CollectGroupMemberships collects all group membership relationships in the directory.
func (c *DefaultDirectoryDNACollector) CollectGroupMemberships(ctx context.Context) ([]*GroupMembership, error) {
	startTime := time.Now()
	c.logger.Info("Collecting all group memberships")

	allMemberships := make([]*GroupMembership, 0)

	// Get all groups
	groupList, err := c.provider.ListGroups(ctx, &interfaces.SearchFilters{
		Limit: 10000, // Large limit to get all groups
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	// Process each group to get its members
	for _, group := range groupList.Groups {
		members, err := c.provider.GetGroupMembers(ctx, group.ID)
		if err != nil {
			c.logger.Warn("Failed to get members for group", "group_id", group.ID, "error", err)
			continue
		}

		// Create membership records
		for _, member := range members {
			membership := &GroupMembership{
				UserID:     member.ID,
				GroupID:    group.ID,
				MemberType: "direct", // Assume direct membership for now
				Source:     "directory_provider",
				Provider:   c.provider.GetProviderInfo().Name,
				TenantID:   c.config.TenantID,
			}

			// Try to determine when membership was granted (if available)
			// This would be provider-specific and might not be available

			allMemberships = append(allMemberships, membership)
		}
	}

	c.logger.Info("Completed group membership collection",
		"total_groups", len(groupList.Groups),
		"total_memberships", len(allMemberships),
		"duration", time.Since(startTime))

	return allMemberships, nil
}

// CollectOUHierarchy collects the complete organizational unit hierarchy.
func (c *DefaultDirectoryDNACollector) CollectOUHierarchy(ctx context.Context) (*OUHierarchy, error) {
	startTime := time.Now()
	c.logger.Info("Collecting OU hierarchy")

	// Get all OUs
	ouList, err := c.provider.ListOUs(ctx, &interfaces.SearchFilters{
		Limit: 10000, // Large limit to get all OUs
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list OUs: %w", err)
	}

	hierarchy := &OUHierarchy{
		Hierarchy:   make(map[string]*OUNode),
		CollectedAt: time.Now(),
		Provider:    c.provider.GetProviderInfo().Name,
		TenantID:    c.config.TenantID,
		TotalOUs:    len(ouList.OUs),
	}

	// Build OU nodes
	var rootOUs []string
	maxDepth := 0

	for _, ou := range ouList.OUs {
		// Count users and groups in this OU
		userCount, groupCount := c.countObjectsInOU(ctx, ou.ID)

		node := &OUNode{
			OUID:       ou.ID,
			Name:       ou.Name,
			ParentID:   ou.ParentOU,
			UserCount:  userCount,
			GroupCount: groupCount,
		}

		// Track root OUs (those without parents)
		if ou.ParentOU == "" {
			rootOUs = append(rootOUs, ou.ID)
		}

		hierarchy.Hierarchy[ou.ID] = node
	}

	// Build parent-child relationships and calculate depths
	for ouID, node := range hierarchy.Hierarchy {
		if node.ParentID != "" {
			// Add this OU as a child to its parent
			if parent, exists := hierarchy.Hierarchy[node.ParentID]; exists {
				parent.Children = append(parent.Children, ouID)
			}
		}

		// Calculate depth
		depth := c.calculateOUDepth(ouID, hierarchy.Hierarchy, 0)
		node.Depth = depth
		if depth > maxDepth {
			maxDepth = depth
		}
	}

	hierarchy.Depth = maxDepth

	// Set root OU (pick the first one if multiple roots exist)
	if len(rootOUs) > 0 {
		hierarchy.RootOU = rootOUs[0]
	}

	c.logger.Info("Completed OU hierarchy collection",
		"total_ous", len(ouList.OUs),
		"max_depth", maxDepth,
		"root_ous", len(rootOUs),
		"duration", time.Since(startTime))

	return hierarchy, nil
}

// countObjectsInOU counts users and groups in a specific OU.
func (c *DefaultDirectoryDNACollector) countObjectsInOU(ctx context.Context, ouID string) (int, int) {
	// Count users
	userList, err := c.provider.ListUsers(ctx, &interfaces.SearchFilters{
		OU:    ouID,
		Limit: 1, // We only need the count
	})
	userCount := 0
	if err == nil {
		userCount = userList.TotalCount
	}

	// Count groups
	groupList, err := c.provider.ListGroups(ctx, &interfaces.SearchFilters{
		OU:    ouID,
		Limit: 1, // We only need the count
	})
	groupCount := 0
	if err == nil {
		groupCount = groupList.TotalCount
	}

	return userCount, groupCount
}

// calculateOUDepth calculates the depth of an OU in the hierarchy.
func (c *DefaultDirectoryDNACollector) calculateOUDepth(ouID string, hierarchy map[string]*OUNode, currentDepth int) int {
	// Prevent infinite recursion with circular references
	if currentDepth >= 20 {
		c.logger.Warn("Possible circular reference in OU hierarchy", "ou_id", ouID, "depth", currentDepth)
		return 20 // Cap at maximum depth
	}

	node, exists := hierarchy[ouID]
	if !exists {
		return currentDepth
	}

	// If this OU has no parent, it's at the current depth
	if node.ParentID == "" {
		return currentDepth
	}

	// Recursively calculate depth through parent
	return c.calculateOUDepth(node.ParentID, hierarchy, currentDepth+1)
}

// Additional helper methods for relationship management

// GetRelationshipStats returns statistics about collected relationships.
func (c *DefaultDirectoryDNACollector) GetRelationshipStats(ctx context.Context) (*RelationshipStats, error) {
	// This would be called after collecting relationships to provide statistics
	memberships, err := c.CollectGroupMemberships(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect memberships for stats: %w", err)
	}

	hierarchy, err := c.CollectOUHierarchy(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect hierarchy for stats: %w", err)
	}

	stats := &RelationshipStats{
		TotalMemberships: len(memberships),
		TotalOUs:         hierarchy.TotalOUs,
		MaxOUDepth:       hierarchy.Depth,
		CollectedAt:      time.Now(),
		Provider:         c.provider.GetProviderInfo().Name,
	}

	// Calculate additional statistics
	groupMemberCounts := make(map[string]int)
	userGroupCounts := make(map[string]int)

	for _, membership := range memberships {
		groupMemberCounts[membership.GroupID]++
		userGroupCounts[membership.UserID]++
	}

	// Find largest group
	maxMembers := 0
	for _, count := range groupMemberCounts {
		if count > maxMembers {
			maxMembers = count
		}
	}
	stats.LargestGroupSize = maxMembers

	// Calculate average memberships per user
	if len(userGroupCounts) > 0 {
		totalMemberships := 0
		for _, count := range userGroupCounts {
			totalMemberships += count
		}
		stats.AverageMembershipsPerUser = float64(totalMemberships) / float64(len(userGroupCounts))
	}

	return stats, nil
}

// RelationshipStats provides statistics about directory relationships.
type RelationshipStats struct {
	TotalMemberships          int       `json:"total_memberships"`
	TotalOUs                  int       `json:"total_ous"`
	MaxOUDepth                int       `json:"max_ou_depth"`
	LargestGroupSize          int       `json:"largest_group_size"`
	AverageMembershipsPerUser float64   `json:"avg_memberships_per_user"`
	CollectedAt               time.Time `json:"collected_at"`
	Provider                  string    `json:"provider"`
}
