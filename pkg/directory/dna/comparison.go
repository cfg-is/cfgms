// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package dna - Directory Comparison
//
// CompareDirectories diffs the users and groups of two directory providers by
// building comparison DNA records from each side and running them through the
// directory drift detector. It is written against interfaces.DirectoryProvider
// and reads only through ListUsers/ListGroups, paging until the provider
// reports no more results. Provider name resolution is the caller's job; this
// function takes provider instances.
//
// Provider 1 is treated as current and provider 2 as baseline: an object only
// in provider 1 is reported as "create", one only in provider 2 as "delete".
package dna

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// comparisonPageSize is the page size requested from providers while listing.
const comparisonPageSize = 500

// DirectoryComparison is the result of comparing two directories.
type DirectoryComparison struct {
	Provider1        string                     `json:"provider1"`
	Provider2        string                     `json:"provider2"`
	ComparisonTime   time.Time                  `json:"comparison_time"`
	UserDifferences  []ObjectDifference         `json:"user_differences,omitempty"`
	GroupDifferences []ObjectDifference         `json:"group_differences,omitempty"`
	Summary          DirectoryComparisonSummary `json:"summary"`
}

// ObjectDifference represents a difference between directory objects.
type ObjectDifference struct {
	ObjectType interfaces.DirectoryObjectType `json:"object_type"`
	ObjectID   string                         `json:"object_id"`
	Action     string                         `json:"action"` // "create", "update", "delete"
	Field      string                         `json:"field,omitempty"`
	OldValue   string                         `json:"old_value,omitempty"`
	NewValue   string                         `json:"new_value,omitempty"`
}

// DirectoryComparisonSummary provides a summary of directory differences.
type DirectoryComparisonSummary struct {
	TotalDifferences int `json:"total_differences"`
	UsersToCreate    int `json:"users_to_create"`
	UsersToUpdate    int `json:"users_to_update"`
	UsersToDelete    int `json:"users_to_delete"`
	GroupsToCreate   int `json:"groups_to_create"`
	GroupsToUpdate   int `json:"groups_to_update"`
	GroupsToDelete   int `json:"groups_to_delete"`
}

// CompareDirectories compares the users and groups of two providers and returns
// the differences. Only ListUsers and ListGroups are called on the providers.
func CompareDirectories(ctx context.Context, p1, p2 interfaces.DirectoryProvider, logger logging.Logger) (*DirectoryComparison, error) {
	if p1 == nil || p2 == nil {
		return nil, fmt.Errorf("both providers are required")
	}
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	name1 := p1.GetProviderInfo().Name
	name2 := p2.GetProviderInfo().Name

	p1Users, err := listAllUsers(ctx, p1)
	if err != nil {
		return nil, fmt.Errorf("failed to list users from provider '%s': %w", name1, err)
	}
	p2Users, err := listAllUsers(ctx, p2)
	if err != nil {
		return nil, fmt.Errorf("failed to list users from provider '%s': %w", name2, err)
	}
	p1Groups, err := listAllGroups(ctx, p1)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups from provider '%s': %w", name1, err)
	}
	p2Groups, err := listAllGroups(ctx, p2)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups from provider '%s': %w", name2, err)
	}

	detector := NewDirectoryDriftDetector(logger)
	userDrifts, err := detector.DetectBulkDrift(ctx, buildUserDNASet(p1Users), buildUserDNASet(p2Users))
	if err != nil {
		return nil, fmt.Errorf("user comparison failed: %w", err)
	}
	groupDrifts, err := detector.DetectBulkDrift(ctx, buildGroupDNASet(p1Groups), buildGroupDNASet(p2Groups))
	if err != nil {
		return nil, fmt.Errorf("group comparison failed: %w", err)
	}

	comparison := &DirectoryComparison{
		Provider1:        name1,
		Provider2:        name2,
		ComparisonTime:   time.Now(),
		UserDifferences:  driftsToObjectDifferences(userDrifts, interfaces.DirectoryObjectTypeUser),
		GroupDifferences: driftsToObjectDifferences(groupDrifts, interfaces.DirectoryObjectTypeGroup),
		Summary:          buildComparisonSummary(userDrifts, groupDrifts),
	}

	logger.Info("Directory comparison completed",
		"provider1", logging.SanitizeLogValue(name1),
		"provider2", logging.SanitizeLogValue(name2),
		"total_differences", comparison.Summary.TotalDifferences)

	return comparison, nil
}

// listAllUsers pages through ListUsers until the provider reports no more results.
func listAllUsers(ctx context.Context, p interfaces.DirectoryProvider) ([]interfaces.DirectoryUser, error) {
	var users []interfaces.DirectoryUser
	offset := 0
	for {
		list, err := p.ListUsers(ctx, &interfaces.SearchFilters{Limit: comparisonPageSize, Offset: offset})
		if err != nil {
			return nil, err
		}
		if list == nil {
			return users, nil
		}
		users = append(users, list.Users...)
		if !list.HasMore {
			return users, nil
		}
		if len(list.Users) == 0 {
			return nil, fmt.Errorf("provider reported more users at offset %d but returned an empty page", offset)
		}
		offset += len(list.Users)
	}
}

// listAllGroups pages through ListGroups until the provider reports no more results.
func listAllGroups(ctx context.Context, p interfaces.DirectoryProvider) ([]interfaces.DirectoryGroup, error) {
	var groups []interfaces.DirectoryGroup
	offset := 0
	for {
		list, err := p.ListGroups(ctx, &interfaces.SearchFilters{Limit: comparisonPageSize, Offset: offset})
		if err != nil {
			return nil, err
		}
		if list == nil {
			return groups, nil
		}
		groups = append(groups, list.Groups...)
		if !list.HasMore {
			return groups, nil
		}
		if len(list.Groups) == 0 {
			return nil, fmt.Errorf("provider reported more groups at offset %d but returned an empty page", offset)
		}
		offset += len(list.Groups)
	}
}

// buildUserDNASet converts users into DirectoryDNA records keyed by UPN for
// cross-provider comparison. Only stable, semantic attributes are included so that
// provider-specific metadata does not create spurious differences.
func buildUserDNASet(users []interfaces.DirectoryUser) []*DirectoryDNA {
	dnaSet := make([]*DirectoryDNA, 0, len(users))
	for i := range users {
		dnaSet = append(dnaSet, userToComparisonDNA(&users[i]))
	}
	return dnaSet
}

func userToComparisonDNA(u *interfaces.DirectoryUser) *DirectoryDNA {
	key := u.UserPrincipalName
	if key == "" {
		key = u.ID
	}
	attrs := map[string]string{
		"display_name":    u.DisplayName,
		"account_enabled": strconv.FormatBool(u.AccountEnabled),
	}
	if u.SAMAccountName != "" {
		attrs["sam_account_name"] = u.SAMAccountName
	}
	if u.EmailAddress != "" {
		attrs["email_address"] = u.EmailAddress
	}
	if u.Department != "" {
		attrs["department"] = u.Department
	}
	if u.JobTitle != "" {
		attrs["job_title"] = u.JobTitle
	}
	if u.Manager != "" {
		attrs["manager"] = u.Manager
	}
	if len(u.Groups) > 0 {
		attrs["groups"] = strings.Join(u.Groups, ",")
	}
	now := time.Now()
	return &DirectoryDNA{
		ObjectID:    key,
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		ID:          key,
		Attributes:  attrs,
		LastUpdated: &now,
	}
}

// buildGroupDNASet converts groups into DirectoryDNA records keyed by Name.
func buildGroupDNASet(groups []interfaces.DirectoryGroup) []*DirectoryDNA {
	dnaSet := make([]*DirectoryDNA, 0, len(groups))
	for i := range groups {
		dnaSet = append(dnaSet, groupToComparisonDNA(&groups[i]))
	}
	return dnaSet
}

func groupToComparisonDNA(g *interfaces.DirectoryGroup) *DirectoryDNA {
	key := g.Name
	if key == "" {
		key = g.ID
	}
	attrs := map[string]string{
		"display_name": g.DisplayName,
		"group_type":   string(g.GroupType),
		"group_scope":  string(g.GroupScope),
	}
	if g.Description != "" {
		attrs["description"] = g.Description
	}
	if len(g.Members) > 0 {
		attrs["members"] = strings.Join(g.Members, ",")
	}
	now := time.Now()
	return &DirectoryDNA{
		ObjectID:    key,
		ObjectType:  interfaces.DirectoryObjectTypeGroup,
		ID:          key,
		Attributes:  attrs,
		LastUpdated: &now,
	}
}

// driftsToObjectDifferences maps drift results to ObjectDifference entries.
// Creates/deletes produce one entry per object; attribute changes produce one
// entry per changed field.
func driftsToObjectDifferences(drifts []*DirectoryDrift, objectType interfaces.DirectoryObjectType) []ObjectDifference {
	var diffs []ObjectDifference
	for _, drift := range drifts {
		switch drift.DriftType {
		case DirectoryDriftTypeObjectCreation:
			diffs = append(diffs, ObjectDifference{ObjectType: objectType, ObjectID: drift.ObjectID, Action: "create"})
		case DirectoryDriftTypeObjectDeletion:
			diffs = append(diffs, ObjectDifference{ObjectType: objectType, ObjectID: drift.ObjectID, Action: "delete"})
		default:
			for _, change := range drift.Changes {
				oldVal, _ := change.OldValue.(string)
				newVal, _ := change.NewValue.(string)
				diffs = append(diffs, ObjectDifference{
					ObjectType: objectType,
					ObjectID:   drift.ObjectID,
					Action:     "update",
					Field:      change.Field,
					OldValue:   oldVal,
					NewValue:   newVal,
				})
			}
		}
	}
	return diffs
}

// buildComparisonSummary aggregates drift results into per-object counts.
func buildComparisonSummary(userDrifts, groupDrifts []*DirectoryDrift) DirectoryComparisonSummary {
	summary := DirectoryComparisonSummary{}
	for _, drift := range userDrifts {
		switch drift.DriftType {
		case DirectoryDriftTypeObjectCreation:
			summary.UsersToCreate++
		case DirectoryDriftTypeObjectDeletion:
			summary.UsersToDelete++
		default:
			if len(drift.Changes) > 0 {
				summary.UsersToUpdate++
			}
		}
	}
	for _, drift := range groupDrifts {
		switch drift.DriftType {
		case DirectoryDriftTypeObjectCreation:
			summary.GroupsToCreate++
		case DirectoryDriftTypeObjectDeletion:
			summary.GroupsToDelete++
		default:
			if len(drift.Changes) > 0 {
				summary.GroupsToUpdate++
			}
		}
	}
	summary.TotalDifferences = summary.UsersToCreate + summary.UsersToUpdate + summary.UsersToDelete +
		summary.GroupsToCreate + summary.GroupsToUpdate + summary.GroupsToDelete
	return summary
}
