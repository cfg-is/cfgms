// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package types

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDirectoryGroup_ToGraphGroup(t *testing.T) {
	tests := []struct {
		name     string
		group    *DirectoryGroup
		expected *GraphGroup
	}{
		{
			name: "complete group conversion",
			group: &DirectoryGroup{
				ID:              "12345",
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Mail:            "engineering@example.com",
				Created:         func() *time.Time { t := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC); return &t }(),
			},
			expected: &GraphGroup{
				ID:              "12345",
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Mail:            "engineering@example.com",
				CreatedDateTime: "2023-01-01T12:00:00Z",
			},
		},
		{
			name: "minimal group conversion",
			group: &DirectoryGroup{
				ID:              "67890",
				DisplayName:     "Security Group",
				SecurityEnabled: true,
			},
			expected: &GraphGroup{
				ID:              "67890",
				DisplayName:     "Security Group",
				SecurityEnabled: true,
				CreatedDateTime: "",
			},
		},
		{
			name: "distribution group",
			group: &DirectoryGroup{
				ID:              "11111",
				DisplayName:     "Marketing Distribution List",
				Description:     "Marketing team distribution list",
				MailEnabled:     true,
				SecurityEnabled: false,
				MailNickname:    "marketing",
				Mail:            "marketing@example.com",
			},
			expected: &GraphGroup{
				ID:              "11111",
				DisplayName:     "Marketing Distribution List",
				Description:     "Marketing team distribution list",
				MailEnabled:     true,
				SecurityEnabled: false,
				MailNickname:    "marketing",
				Mail:            "marketing@example.com",
				CreatedDateTime: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.group.ToGraphGroup()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromGraphGroup(t *testing.T) {
	tests := []struct {
		name         string
		graphGroup   *GraphGroup
		providerName string
		expected     *DirectoryGroup
	}{
		{
			name: "microsoft 365 group conversion",
			graphGroup: &GraphGroup{
				ID:              "12345",
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Mail:            "engineering@example.com",
				CreatedDateTime: "2023-01-01T12:00:00Z",
			},
			providerName: "entraid",
			expected: &DirectoryGroup{
				ID:              "12345",
				Name:            "Engineering Team",
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				GroupType:       GroupTypeMicrosoft365, // Both mail and security enabled
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Mail:            "engineering@example.com",
				Created:         func() *time.Time { t := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC); return &t }(),
				Source:          "entraid",
			},
		},
		{
			name: "security group conversion",
			graphGroup: &GraphGroup{
				ID:              "67890",
				DisplayName:     "Security Group",
				Description:     "A security-only group",
				MailEnabled:     false,
				SecurityEnabled: true,
				CreatedDateTime: "2023-02-01T08:30:00Z",
			},
			providerName: "entraid",
			expected: &DirectoryGroup{
				ID:              "67890",
				Name:            "Security Group",
				DisplayName:     "Security Group",
				Description:     "A security-only group",
				GroupType:       GroupTypeSecurity, // Security enabled, mail disabled
				MailEnabled:     false,
				SecurityEnabled: true,
				Created:         func() *time.Time { t := time.Date(2023, 2, 1, 8, 30, 0, 0, time.UTC); return &t }(),
				Source:          "entraid",
			},
		},
		{
			name: "distribution group conversion",
			graphGroup: &GraphGroup{
				ID:              "11111",
				DisplayName:     "Marketing Distribution",
				Description:     "Marketing team distribution list",
				MailEnabled:     true,
				SecurityEnabled: false,
				MailNickname:    "marketing",
				Mail:            "marketing@example.com",
			},
			providerName: "entraid",
			expected: &DirectoryGroup{
				ID:              "11111",
				Name:            "Marketing Distribution",
				DisplayName:     "Marketing Distribution",
				Description:     "Marketing team distribution list",
				GroupType:       GroupTypeDistribution, // Mail enabled, security disabled
				MailEnabled:     true,
				SecurityEnabled: false,
				MailNickname:    "marketing",
				Mail:            "marketing@example.com",
				Created:         nil, // No created date provided
				Source:          "entraid",
			},
		},
		{
			name: "invalid created date",
			graphGroup: &GraphGroup{
				ID:              "22222",
				DisplayName:     "Test Group",
				SecurityEnabled: true,
				CreatedDateTime: "invalid-date",
			},
			providerName: "entraid",
			expected: &DirectoryGroup{
				ID:              "22222",
				Name:            "Test Group",
				DisplayName:     "Test Group",
				GroupType:       GroupTypeSecurity,
				SecurityEnabled: true,
				Created:         nil, // Should be nil due to invalid date
				Source:          "entraid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromGraphGroup(tt.graphGroup, tt.providerName)

			// Check all fields except Modified (which is set to current time)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
			assert.Equal(t, tt.expected.Description, result.Description)
			assert.Equal(t, tt.expected.GroupType, result.GroupType)
			assert.Equal(t, tt.expected.MailEnabled, result.MailEnabled)
			assert.Equal(t, tt.expected.SecurityEnabled, result.SecurityEnabled)
			assert.Equal(t, tt.expected.MailNickname, result.MailNickname)
			assert.Equal(t, tt.expected.Mail, result.Mail)
			assert.Equal(t, tt.expected.Source, result.Source)

			// Check Created time separately
			if tt.expected.Created != nil {
				require.NotNil(t, result.Created)
				assert.Equal(t, *tt.expected.Created, *result.Created)
			} else {
				assert.Nil(t, result.Created)
			}

			// Modified should be set to current time (not zero)
			assert.NotNil(t, result.Modified)
			assert.False(t, result.Modified.IsZero())
		})
	}
}

func TestDirectoryGroup_ToEntraGroupConfig(t *testing.T) {
	tests := []struct {
		name     string
		group    *DirectoryGroup
		expected *EntraGroupConfig
	}{
		{
			name: "complete group to entra config",
			group: &DirectoryGroup{
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				GroupType:       GroupTypeMicrosoft365,
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Members:         []string{"user1", "user2", "user3"},
			},
			expected: &EntraGroupConfig{
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Members:         []string{"user1", "user2", "user3"},
				GroupType:       "microsoft365",
			},
		},
		{
			name: "minimal group to entra config",
			group: &DirectoryGroup{
				DisplayName:     "Security Group",
				GroupType:       GroupTypeSecurity,
				SecurityEnabled: true,
			},
			expected: &EntraGroupConfig{
				DisplayName:     "Security Group",
				SecurityEnabled: true,
				GroupType:       "security",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.group.ToEntraGroupConfig()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromEntraGroupConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       *EntraGroupConfig
		groupID      string
		providerName string
		expected     *DirectoryGroup
	}{
		{
			name: "complete entra config conversion",
			config: &EntraGroupConfig{
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Members:         []string{"user1", "user2", "user3"},
				GroupType:       "microsoft365",
			},
			groupID:      "12345",
			providerName: "entraid",
			expected: &DirectoryGroup{
				ID:              "12345",
				Name:            "Engineering Team",
				DisplayName:     "Engineering Team",
				Description:     "Development team for engineering projects",
				GroupType:       GroupTypeMicrosoft365,
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "engineering",
				Members:         []string{"user1", "user2", "user3"},
				Source:          "entraid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromEntraGroupConfig(tt.config, tt.groupID, tt.providerName)

			// Check all fields except Modified (which is set to current time)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
			assert.Equal(t, tt.expected.Description, result.Description)
			assert.Equal(t, tt.expected.GroupType, result.GroupType)
			assert.Equal(t, tt.expected.MailEnabled, result.MailEnabled)
			assert.Equal(t, tt.expected.SecurityEnabled, result.SecurityEnabled)
			assert.Equal(t, tt.expected.MailNickname, result.MailNickname)
			assert.Equal(t, tt.expected.Members, result.Members)
			assert.Equal(t, tt.expected.Source, result.Source)

			// Modified should be set to current time
			assert.NotNil(t, result.Modified)
			assert.False(t, result.Modified.IsZero())
		})
	}
}

func TestDirectoryGroup_Validate(t *testing.T) {
	tests := []struct {
		name        string
		group       *DirectoryGroup
		expectError bool
		expectedErr error
	}{
		{
			name: "valid security group",
			group: &DirectoryGroup{
				DisplayName:     "Security Group",
				GroupType:       GroupTypeSecurity,
				SecurityEnabled: true,
			},
			expectError: false,
		},
		{
			name: "valid distribution group",
			group: &DirectoryGroup{
				DisplayName:  "Marketing List",
				GroupType:    GroupTypeDistribution,
				MailEnabled:  true,
				MailNickname: "marketing",
			},
			expectError: false,
		},
		{
			name: "valid microsoft 365 group",
			group: &DirectoryGroup{
				DisplayName:     "Teams Group",
				GroupType:       GroupTypeMicrosoft365,
				MailEnabled:     true,
				SecurityEnabled: true,
				MailNickname:    "teams",
			},
			expectError: false,
		},
		{
			name: "missing display name",
			group: &DirectoryGroup{
				DisplayName: "",
				GroupType:   GroupTypeSecurity,
			},
			expectError: true,
			expectedErr: ErrInvalidGroupDisplayName,
		},
		{
			name: "invalid group type",
			group: &DirectoryGroup{
				DisplayName: "Test Group",
				GroupType:   GroupType("invalid"),
			},
			expectError: true,
			expectedErr: ErrInvalidGroupType,
		},
		{
			name: "mail-enabled without mail nickname",
			group: &DirectoryGroup{
				DisplayName:  "Test Group",
				GroupType:    GroupTypeDistribution,
				MailEnabled:  true,
				MailNickname: "", // Missing required mail nickname
			},
			expectError: true,
			expectedErr: ErrInvalidMailNickname,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.Equal(t, tt.expectedErr, err)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDirectoryGroup_HasMember(t *testing.T) {
	group := &DirectoryGroup{
		Members: []string{"user1", "user2", "user3"},
	}

	tests := []struct {
		name     string
		memberID string
		expected bool
	}{
		{
			name:     "member exists",
			memberID: "user2",
			expected: true,
		},
		{
			name:     "member does not exist",
			memberID: "user4",
			expected: false,
		},
		{
			name:     "empty member ID",
			memberID: "",
			expected: false,
		},
		{
			name:     "case sensitive",
			memberID: "User1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := group.HasMember(tt.memberID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDirectoryGroup_AddMember(t *testing.T) {
	tests := []struct {
		name            string
		initialMembers  []string
		memberToAdd     string
		expectedMembers []string
		expectModified  bool
	}{
		{
			name:            "add new member",
			initialMembers:  []string{"user1", "user2"},
			memberToAdd:     "user3",
			expectedMembers: []string{"user1", "user2", "user3"},
			expectModified:  true,
		},
		{
			name:            "add existing member",
			initialMembers:  []string{"user1", "user2", "user3"},
			memberToAdd:     "user2",
			expectedMembers: []string{"user1", "user2", "user3"},
			expectModified:  false,
		},
		{
			name:            "add to empty group",
			initialMembers:  []string{},
			memberToAdd:     "user1",
			expectedMembers: []string{"user1"},
			expectModified:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &DirectoryGroup{
				Members: make([]string, len(tt.initialMembers)),
			}
			copy(group.Members, tt.initialMembers)

			// Record initial modified time
			initialModified := group.Modified

			group.AddMember(tt.memberToAdd)

			assert.Equal(t, tt.expectedMembers, group.Members)

			if tt.expectModified {
				assert.NotEqual(t, initialModified, group.Modified)
				assert.NotNil(t, group.Modified)
			} else {
				assert.Equal(t, initialModified, group.Modified)
			}
		})
	}
}

func TestDirectoryGroup_RemoveMember(t *testing.T) {
	tests := []struct {
		name            string
		initialMembers  []string
		memberToRemove  string
		expectedMembers []string
		expectModified  bool
	}{
		{
			name:            "remove existing member",
			initialMembers:  []string{"user1", "user2", "user3"},
			memberToRemove:  "user2",
			expectedMembers: []string{"user1", "user3"},
			expectModified:  true,
		},
		{
			name:            "remove non-existing member",
			initialMembers:  []string{"user1", "user2", "user3"},
			memberToRemove:  "user4",
			expectedMembers: []string{"user1", "user2", "user3"},
			expectModified:  false,
		},
		{
			name:            "remove from empty group",
			initialMembers:  []string{},
			memberToRemove:  "user1",
			expectedMembers: []string{},
			expectModified:  false,
		},
		{
			name:            "remove last member",
			initialMembers:  []string{"user1"},
			memberToRemove:  "user1",
			expectedMembers: []string{},
			expectModified:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &DirectoryGroup{
				Members: make([]string, len(tt.initialMembers)),
			}
			copy(group.Members, tt.initialMembers)

			// Record initial modified time
			initialModified := group.Modified

			group.RemoveMember(tt.memberToRemove)

			assert.Equal(t, tt.expectedMembers, group.Members)

			if tt.expectModified {
				assert.NotEqual(t, initialModified, group.Modified)
				assert.NotNil(t, group.Modified)
			} else {
				assert.Equal(t, initialModified, group.Modified)
			}
		})
	}
}

func TestDirectoryGroup_GetMemberCount(t *testing.T) {
	tests := []struct {
		name     string
		members  []string
		expected int
	}{
		{
			name:     "multiple members",
			members:  []string{"user1", "user2", "user3", "user4"},
			expected: 4,
		},
		{
			name:     "single member",
			members:  []string{"user1"},
			expected: 1,
		},
		{
			name:     "no members",
			members:  []string{},
			expected: 0,
		},
		{
			name:     "nil members",
			members:  nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &DirectoryGroup{
				Members: tt.members,
			}
			result := group.GetMemberCount()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDirectoryGroup_TypeChecks(t *testing.T) {
	tests := []struct {
		name                      string
		group                     *DirectoryGroup
		expectedSecurityGroup     bool
		expectedDistributionGroup bool
		expectedMicrosoft365Group bool
	}{
		{
			name: "security group by type",
			group: &DirectoryGroup{
				GroupType:       GroupTypeSecurity,
				SecurityEnabled: true,
			},
			expectedSecurityGroup:     true,
			expectedDistributionGroup: false,
			expectedMicrosoft365Group: false,
		},
		{
			name: "security group by flag only",
			group: &DirectoryGroup{
				GroupType:       GroupTypeDistribution,
				SecurityEnabled: true,
			},
			expectedSecurityGroup:     true, // SecurityEnabled = true
			expectedDistributionGroup: true, // GroupType = Distribution
			expectedMicrosoft365Group: false,
		},
		{
			name: "distribution group by type",
			group: &DirectoryGroup{
				GroupType:       GroupTypeDistribution,
				MailEnabled:     true,
				SecurityEnabled: false,
			},
			expectedSecurityGroup:     false,
			expectedDistributionGroup: true,
			expectedMicrosoft365Group: false,
		},
		{
			name: "distribution group by flags only",
			group: &DirectoryGroup{
				GroupType:       GroupTypeSecurity,
				MailEnabled:     true,
				SecurityEnabled: false,
			},
			expectedSecurityGroup:     true, // GroupType = Security
			expectedDistributionGroup: true, // MailEnabled && !SecurityEnabled
			expectedMicrosoft365Group: false,
		},
		{
			name: "microsoft 365 group by type",
			group: &DirectoryGroup{
				GroupType:       GroupTypeMicrosoft365,
				MailEnabled:     true,
				SecurityEnabled: true,
			},
			expectedSecurityGroup:     true,  // SecurityEnabled = true
			expectedDistributionGroup: false, // !(MailEnabled && !SecurityEnabled)
			expectedMicrosoft365Group: true,
		},
		{
			name: "microsoft 365 group by flags only",
			group: &DirectoryGroup{
				GroupType:       GroupTypeSecurity,
				MailEnabled:     true,
				SecurityEnabled: true,
			},
			expectedSecurityGroup:     true, // Both type and flag check
			expectedDistributionGroup: false,
			expectedMicrosoft365Group: true, // Flag check wins
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedSecurityGroup, tt.group.IsSecurityGroup())
			assert.Equal(t, tt.expectedDistributionGroup, tt.group.IsDistributionGroup())
			assert.Equal(t, tt.expectedMicrosoft365Group, tt.group.IsMicrosoft365Group())
		})
	}
}

func TestDirectoryGroup_Clone(t *testing.T) {
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	original := &DirectoryGroup{
		ID:          "12345",
		DisplayName: "Engineering Team",
		Members:     []string{"user1", "user2", "user3"},
		Created:     &originalTime,
		ProviderAttributes: map[string]interface{}{
			"custom_field": "custom_value",
		},
	}

	clone := original.Clone()

	// Verify clone is not the same object
	assert.NotSame(t, original, clone)

	// Verify all fields are equal
	assert.Equal(t, original.ID, clone.ID)
	assert.Equal(t, original.DisplayName, clone.DisplayName)
	assert.Equal(t, original.Members, clone.Members)
	assert.Equal(t, original.ProviderAttributes, clone.ProviderAttributes)

	// Verify deep copy - modifying clone doesn't affect original
	clone.DisplayName = "Modified Team"
	clone.Members[0] = "modified_user"
	clone.ProviderAttributes["custom_field"] = "modified_value"

	assert.NotEqual(t, original.DisplayName, clone.DisplayName)
	assert.NotEqual(t, original.Members[0], clone.Members[0])
	assert.NotEqual(t, original.ProviderAttributes["custom_field"], clone.ProviderAttributes["custom_field"])
}

func TestDirectoryGroup_JSONSerialization(t *testing.T) {
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	group := &DirectoryGroup{
		ID:              "12345",
		DisplayName:     "Engineering Team",
		Description:     "Development team",
		GroupType:       GroupTypeMicrosoft365,
		MailEnabled:     true,
		SecurityEnabled: true,
		Members:         []string{"user1", "user2"},
		Created:         &originalTime,
		Source:          "entraid",
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(group)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test JSON unmarshaling
	var deserializedGroup DirectoryGroup
	err = json.Unmarshal(jsonData, &deserializedGroup)
	require.NoError(t, err)

	// Verify deserialized group matches original
	assert.Equal(t, group.ID, deserializedGroup.ID)
	assert.Equal(t, group.DisplayName, deserializedGroup.DisplayName)
	assert.Equal(t, group.Description, deserializedGroup.Description)
	assert.Equal(t, group.GroupType, deserializedGroup.GroupType)
	assert.Equal(t, group.MailEnabled, deserializedGroup.MailEnabled)
	assert.Equal(t, group.SecurityEnabled, deserializedGroup.SecurityEnabled)
	assert.Equal(t, group.Members, deserializedGroup.Members)
	assert.Equal(t, group.Source, deserializedGroup.Source)

	// Check time fields
	require.NotNil(t, deserializedGroup.Created)
	assert.Equal(t, originalTime.Unix(), deserializedGroup.Created.Unix())
}

func TestDirectoryGroup_YAMLSerialization(t *testing.T) {
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	group := &DirectoryGroup{
		ID:              "12345",
		DisplayName:     "Engineering Team",
		Description:     "Development team",
		GroupType:       GroupTypeMicrosoft365,
		MailEnabled:     true,
		SecurityEnabled: true,
		Members:         []string{"user1", "user2"},
		Created:         &originalTime,
		Source:          "entraid",
	}

	// Test YAML marshaling
	yamlData, err := yaml.Marshal(group)
	require.NoError(t, err)
	assert.NotEmpty(t, yamlData)

	// Test YAML unmarshaling
	var deserializedGroup DirectoryGroup
	err = yaml.Unmarshal(yamlData, &deserializedGroup)
	require.NoError(t, err)

	// Verify deserialized group matches original
	assert.Equal(t, group.ID, deserializedGroup.ID)
	assert.Equal(t, group.DisplayName, deserializedGroup.DisplayName)
	assert.Equal(t, group.Description, deserializedGroup.Description)
	assert.Equal(t, group.GroupType, deserializedGroup.GroupType)
	assert.Equal(t, group.MailEnabled, deserializedGroup.MailEnabled)
	assert.Equal(t, group.SecurityEnabled, deserializedGroup.SecurityEnabled)
	assert.Equal(t, group.Members, deserializedGroup.Members)
	assert.Equal(t, group.Source, deserializedGroup.Source)
}

func TestGroupTypeConstants(t *testing.T) {
	// Test that group type constants are as expected
	assert.Equal(t, "security", string(GroupTypeSecurity))
	assert.Equal(t, "distribution", string(GroupTypeDistribution))
	assert.Equal(t, "microsoft365", string(GroupTypeMicrosoft365))
}

func TestGroupScopeConstants(t *testing.T) {
	// Test that group scope constants are as expected
	assert.Equal(t, "domain_local", string(GroupScopeDomainLocal))
	assert.Equal(t, "global", string(GroupScopeGlobal))
	assert.Equal(t, "universal", string(GroupScopeUniversal))
}
