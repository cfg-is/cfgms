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

func TestDirectoryUser_ToGraphUser(t *testing.T) {
	tests := []struct {
		name     string
		user     *DirectoryUser
		expected *GraphUser
	}{
		{
			name: "complete user conversion",
			user: &DirectoryUser{
				ID:                "12345",
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				EmailAddress:      "john.doe@example.com",
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				Company:           "Example Corp",
				CompanyName:       "Example Corporation",
				Created:           func() *time.Time { t := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC); return &t }(),
			},
			expected: &GraphUser{
				ID:                "12345",
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				CompanyName:       "Example Corporation", // Should use CompanyName over Company
				CreatedDateTime:   "2023-01-01T12:00:00Z",
			},
		},
		{
			name: "minimal user conversion",
			user: &DirectoryUser{
				ID:                "67890",
				UserPrincipalName: "jane.smith@example.com",
				DisplayName:       "Jane Smith",
				AccountEnabled:    false,
			},
			expected: &GraphUser{
				ID:                "67890",
				UserPrincipalName: "jane.smith@example.com",
				DisplayName:       "Jane Smith",
				AccountEnabled:    false,
				Mail:              "", // No mail fields set
				CompanyName:       "", // No company fields set
				CreatedDateTime:   "", // No created date
			},
		},
		{
			name: "prioritize Mail over EmailAddress",
			user: &DirectoryUser{
				ID:                "11111",
				UserPrincipalName: "test@example.com",
				DisplayName:       "Test User",
				AccountEnabled:    true,
				EmailAddress:      "old@example.com",
				Mail:              "new@example.com", // This should be preferred
			},
			expected: &GraphUser{
				ID:                "11111",
				UserPrincipalName: "test@example.com",
				DisplayName:       "Test User",
				AccountEnabled:    true,
				Mail:              "new@example.com",
			},
		},
		{
			name: "prioritize CompanyName over Company",
			user: &DirectoryUser{
				ID:                "22222",
				UserPrincipalName: "test2@example.com",
				DisplayName:       "Test User 2",
				AccountEnabled:    true,
				Company:           "Old Company",
				CompanyName:       "New Company", // This should be preferred
			},
			expected: &GraphUser{
				ID:                "22222",
				UserPrincipalName: "test2@example.com",
				DisplayName:       "Test User 2",
				AccountEnabled:    true,
				CompanyName:       "New Company",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ToGraphUser()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromGraphUser(t *testing.T) {
	tests := []struct {
		name         string
		graphUser    *GraphUser
		providerName string
		expected     *DirectoryUser
	}{
		{
			name: "complete graph user conversion",
			graphUser: &GraphUser{
				ID:                "12345",
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				CompanyName:       "Example Corporation",
				CreatedDateTime:   "2023-01-01T12:00:00Z",
			},
			providerName: "entraid",
			expected: &DirectoryUser{
				ID:                "12345",
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				EmailAddress:      "john.doe@example.com",
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				Company:           "Example Corporation",
				CompanyName:       "Example Corporation",
				Created:           func() *time.Time { t := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC); return &t }(),
				Source:            "entraid",
			},
		},
		{
			name: "invalid created date time",
			graphUser: &GraphUser{
				ID:                "67890",
				UserPrincipalName: "jane.smith@example.com",
				DisplayName:       "Jane Smith",
				AccountEnabled:    false,
				CreatedDateTime:   "invalid-date",
			},
			providerName: "entraid",
			expected: &DirectoryUser{
				ID:                "67890",
				UserPrincipalName: "jane.smith@example.com",
				DisplayName:       "Jane Smith",
				AccountEnabled:    false,
				EmailAddress:      "",
				Mail:              "",
				Company:           "",
				CompanyName:       "",
				Created:           nil, // Should be nil due to invalid date
				Source:            "entraid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromGraphUser(tt.graphUser, tt.providerName)

			// Check all fields except Modified (which is set to current time)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.UserPrincipalName, result.UserPrincipalName)
			assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
			assert.Equal(t, tt.expected.MailNickname, result.MailNickname)
			assert.Equal(t, tt.expected.AccountEnabled, result.AccountEnabled)
			assert.Equal(t, tt.expected.EmailAddress, result.EmailAddress)
			assert.Equal(t, tt.expected.Mail, result.Mail)
			assert.Equal(t, tt.expected.MobilePhone, result.MobilePhone)
			assert.Equal(t, tt.expected.OfficeLocation, result.OfficeLocation)
			assert.Equal(t, tt.expected.JobTitle, result.JobTitle)
			assert.Equal(t, tt.expected.Department, result.Department)
			assert.Equal(t, tt.expected.Company, result.Company)
			assert.Equal(t, tt.expected.CompanyName, result.CompanyName)
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

func TestDirectoryUser_ToEntraUserConfig(t *testing.T) {
	tests := []struct {
		name     string
		user     *DirectoryUser
		expected *EntraUserConfig
	}{
		{
			name: "complete user to entra config",
			user: &DirectoryUser{
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				EmailAddress:      "john.doe@example.com",
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				Company:           "Example Corp",
				CompanyName:       "Example Corporation",
				Groups:            []string{"Engineers", "Developers"},
			},
			expected: &EntraUserConfig{
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				CompanyName:       "Example Corporation", // Should use CompanyName over Company
				Groups:            []string{"Engineers", "Developers"},
			},
		},
		{
			name: "minimal user to entra config",
			user: &DirectoryUser{
				UserPrincipalName: "jane.smith@example.com",
				DisplayName:       "Jane Smith",
				AccountEnabled:    false,
			},
			expected: &EntraUserConfig{
				UserPrincipalName: "jane.smith@example.com",
				DisplayName:       "Jane Smith",
				AccountEnabled:    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ToEntraUserConfig()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFromEntraUserConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       *EntraUserConfig
		userID       string
		providerName string
		expected     *DirectoryUser
	}{
		{
			name: "complete entra config conversion",
			config: &EntraUserConfig{
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				CompanyName:       "Example Corporation",
				Groups:            []string{"Engineers", "Developers"},
			},
			userID:       "12345",
			providerName: "entraid",
			expected: &DirectoryUser{
				ID:                "12345",
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
				MailNickname:      "johndoe",
				AccountEnabled:    true,
				EmailAddress:      "john.doe@example.com",
				Mail:              "john.doe@example.com",
				MobilePhone:       "+1-555-0123",
				OfficeLocation:    "Building A, Room 101",
				JobTitle:          "Software Engineer",
				Department:        "Engineering",
				Company:           "Example Corporation",
				CompanyName:       "Example Corporation",
				Groups:            []string{"Engineers", "Developers"},
				Source:            "entraid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromEntraUserConfig(tt.config, tt.userID, tt.providerName)

			// Check all fields except Modified (which is set to current time)
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.UserPrincipalName, result.UserPrincipalName)
			assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
			assert.Equal(t, tt.expected.MailNickname, result.MailNickname)
			assert.Equal(t, tt.expected.AccountEnabled, result.AccountEnabled)
			assert.Equal(t, tt.expected.EmailAddress, result.EmailAddress)
			assert.Equal(t, tt.expected.Mail, result.Mail)
			assert.Equal(t, tt.expected.MobilePhone, result.MobilePhone)
			assert.Equal(t, tt.expected.OfficeLocation, result.OfficeLocation)
			assert.Equal(t, tt.expected.JobTitle, result.JobTitle)
			assert.Equal(t, tt.expected.Department, result.Department)
			assert.Equal(t, tt.expected.Company, result.Company)
			assert.Equal(t, tt.expected.CompanyName, result.CompanyName)
			assert.Equal(t, tt.expected.Groups, result.Groups)
			assert.Equal(t, tt.expected.Source, result.Source)

			// Modified should be set to current time
			assert.NotNil(t, result.Modified)
			assert.False(t, result.Modified.IsZero())
		})
	}
}

func TestDirectoryUser_Validate(t *testing.T) {
	tests := []struct {
		name        string
		user        *DirectoryUser
		expectError bool
		expectedErr error
	}{
		{
			name: "valid user",
			user: &DirectoryUser{
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "John Doe",
			},
			expectError: false,
		},
		{
			name: "missing user principal name",
			user: &DirectoryUser{
				UserPrincipalName: "",
				DisplayName:       "John Doe",
			},
			expectError: true,
			expectedErr: ErrInvalidUserPrincipalName,
		},
		{
			name: "missing display name",
			user: &DirectoryUser{
				UserPrincipalName: "john.doe@example.com",
				DisplayName:       "",
			},
			expectError: true,
			expectedErr: ErrInvalidDisplayName,
		},
		{
			name: "invalid UPN format",
			user: &DirectoryUser{
				UserPrincipalName: "invalid-upn",
				DisplayName:       "John Doe",
			},
			expectError: true,
			expectedErr: ErrInvalidUserPrincipalNameFormat,
		},
		{
			name: "invalid UPN format - missing domain",
			user: &DirectoryUser{
				UserPrincipalName: "john.doe@",
				DisplayName:       "John Doe",
			},
			expectError: true,
			expectedErr: ErrInvalidUserPrincipalNameFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()

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

func TestDirectoryUser_GetPrimaryEmail(t *testing.T) {
	tests := []struct {
		name     string
		user     *DirectoryUser
		expected string
	}{
		{
			name: "prefer EmailAddress over Mail",
			user: &DirectoryUser{
				EmailAddress: "primary@example.com",
				Mail:         "secondary@example.com",
			},
			expected: "primary@example.com",
		},
		{
			name: "use Mail when EmailAddress is empty",
			user: &DirectoryUser{
				EmailAddress: "",
				Mail:         "mail@example.com",
			},
			expected: "mail@example.com",
		},
		{
			name: "both empty",
			user: &DirectoryUser{
				EmailAddress: "",
				Mail:         "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.GetPrimaryEmail()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDirectoryUser_GetPrimaryCompany(t *testing.T) {
	tests := []struct {
		name     string
		user     *DirectoryUser
		expected string
	}{
		{
			name: "prefer Company over CompanyName",
			user: &DirectoryUser{
				Company:     "Primary Corp",
				CompanyName: "Secondary Corp",
			},
			expected: "Primary Corp",
		},
		{
			name: "use CompanyName when Company is empty",
			user: &DirectoryUser{
				Company:     "",
				CompanyName: "Company Name",
			},
			expected: "Company Name",
		},
		{
			name: "both empty",
			user: &DirectoryUser{
				Company:     "",
				CompanyName: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.GetPrimaryCompany()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDirectoryUser_HasGroup(t *testing.T) {
	user := &DirectoryUser{
		Groups: []string{"Engineers", "Developers", "Admins"},
	}

	tests := []struct {
		name      string
		groupName string
		expected  bool
	}{
		{
			name:      "group exists",
			groupName: "Engineers",
			expected:  true,
		},
		{
			name:      "group does not exist",
			groupName: "Marketing",
			expected:  false,
		},
		{
			name:      "case sensitive",
			groupName: "engineers",
			expected:  false,
		},
		{
			name:      "empty group name",
			groupName: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := user.HasGroup(tt.groupName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDirectoryUser_Clone(t *testing.T) {
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	original := &DirectoryUser{
		ID:                "12345",
		UserPrincipalName: "john.doe@example.com",
		DisplayName:       "John Doe",
		Groups:            []string{"Engineers", "Developers"},
		Created:           &originalTime,
		ProviderAttributes: map[string]interface{}{
			"custom_field": "custom_value",
		},
	}

	clone := original.Clone()

	// Verify clone is not the same object
	assert.NotSame(t, original, clone)

	// Verify all fields are equal
	assert.Equal(t, original.ID, clone.ID)
	assert.Equal(t, original.UserPrincipalName, clone.UserPrincipalName)
	assert.Equal(t, original.DisplayName, clone.DisplayName)
	assert.Equal(t, original.Groups, clone.Groups)
	assert.Equal(t, original.ProviderAttributes, clone.ProviderAttributes)

	// Verify deep copy - modifying clone doesn't affect original
	clone.DisplayName = "Modified Name"
	clone.Groups[0] = "Modified Group"
	clone.ProviderAttributes["custom_field"] = "modified_value"

	assert.NotEqual(t, original.DisplayName, clone.DisplayName)
	assert.NotEqual(t, original.Groups[0], clone.Groups[0])
	assert.NotEqual(t, original.ProviderAttributes["custom_field"], clone.ProviderAttributes["custom_field"])
}

func TestDirectoryUser_JSONSerialization(t *testing.T) {
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	user := &DirectoryUser{
		ID:                "12345",
		UserPrincipalName: "john.doe@example.com",
		DisplayName:       "John Doe",
		AccountEnabled:    true,
		Created:           &originalTime,
		Groups:            []string{"Engineers", "Developers"},
		ProviderAttributes: map[string]interface{}{
			"custom_field": "custom_value",
		},
		Source: "entraid",
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(user)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test JSON unmarshaling
	var deserializedUser DirectoryUser
	err = json.Unmarshal(jsonData, &deserializedUser)
	require.NoError(t, err)

	// Verify deserialized user matches original
	assert.Equal(t, user.ID, deserializedUser.ID)
	assert.Equal(t, user.UserPrincipalName, deserializedUser.UserPrincipalName)
	assert.Equal(t, user.DisplayName, deserializedUser.DisplayName)
	assert.Equal(t, user.AccountEnabled, deserializedUser.AccountEnabled)
	assert.Equal(t, user.Groups, deserializedUser.Groups)
	assert.Equal(t, user.Source, deserializedUser.Source)

	// Check time fields (JSON time handling)
	require.NotNil(t, deserializedUser.Created)
	assert.Equal(t, originalTime.Unix(), deserializedUser.Created.Unix())
}

func TestDirectoryUser_YAMLSerialization(t *testing.T) {
	originalTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	user := &DirectoryUser{
		ID:                "12345",
		UserPrincipalName: "john.doe@example.com",
		DisplayName:       "John Doe",
		AccountEnabled:    true,
		Created:           &originalTime,
		Groups:            []string{"Engineers", "Developers"},
		Source:            "entraid",
	}

	// Test YAML marshaling
	yamlData, err := yaml.Marshal(user)
	require.NoError(t, err)
	assert.NotEmpty(t, yamlData)

	// Test YAML unmarshaling
	var deserializedUser DirectoryUser
	err = yaml.Unmarshal(yamlData, &deserializedUser)
	require.NoError(t, err)

	// Verify deserialized user matches original
	assert.Equal(t, user.ID, deserializedUser.ID)
	assert.Equal(t, user.UserPrincipalName, deserializedUser.UserPrincipalName)
	assert.Equal(t, user.DisplayName, deserializedUser.DisplayName)
	assert.Equal(t, user.AccountEnabled, deserializedUser.AccountEnabled)
	assert.Equal(t, user.Groups, deserializedUser.Groups)
	assert.Equal(t, user.Source, deserializedUser.Source)
}
