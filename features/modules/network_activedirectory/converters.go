// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
)

// ldapEntryToDirectoryUser converts an LDAP entry to a DirectoryUser
func (m *activeDirectoryModule) ldapEntryToDirectoryUser(entry *ldap.Entry) *interfaces.DirectoryUser {
	user := &interfaces.DirectoryUser{
		ID:                 entry.GetAttributeValue("objectGUID"),
		UserPrincipalName:  entry.GetAttributeValue("userPrincipalName"),
		SAMAccountName:     entry.GetAttributeValue("sAMAccountName"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		EmailAddress:       entry.GetAttributeValue("mail"),
		PhoneNumber:        entry.GetAttributeValue("telephoneNumber"),
		MobilePhone:        entry.GetAttributeValue("mobile"),
		Department:         entry.GetAttributeValue("department"),
		JobTitle:           entry.GetAttributeValue("title"),
		Manager:            entry.GetAttributeValue("manager"),
		Company:            entry.GetAttributeValue("company"),
		OfficeLocation:     entry.GetAttributeValue("physicalDeliveryOfficeName"),
		DistinguishedName:  entry.GetAttributeValue("distinguishedName"),
		Source:             "activedirectory",
		ProviderAttributes: make(map[string]interface{}),
	}

	// Handle account status
	userAccountControl := entry.GetAttributeValue("userAccountControl")
	if userAccountControl != "" {
		if uac, err := strconv.ParseUint(userAccountControl, 10, 32); err == nil {
			// AD userAccountControl bit 2 (0x2) = ACCOUNTDISABLE
			user.AccountEnabled = (uac & 0x2) == 0
			user.ProviderAttributes["userAccountControl"] = uac
		}
	}

	// Handle password expiry
	accountExpires := entry.GetAttributeValue("accountExpires")
	if accountExpires != "" && accountExpires != "0" && accountExpires != "9223372036854775807" {
		if expires, err := strconv.ParseInt(accountExpires, 10, 64); err == nil {
			// Convert from Windows FILETIME (100ns intervals since 1601) to Unix time
			unixTime := time.Unix((expires/10000000)-11644473600, 0)
			user.PasswordExpiry = &unixTime
		}
	}

	// Handle creation and modification times
	if created := entry.GetAttributeValue("whenCreated"); created != "" {
		if t, err := time.Parse("20060102150405.0Z", created); err == nil {
			user.Created = &t
		}
	}

	if modified := entry.GetAttributeValue("whenChanged"); modified != "" {
		if t, err := time.Parse("20060102150405.0Z", modified); err == nil {
			user.Modified = &t
		}
	}

	// Handle group memberships
	memberOf := entry.GetAttributeValues("memberOf")
	if len(memberOf) > 0 {
		user.Groups = memberOf
	}

	// Extract OU from DN
	user.OU = m.extractOUFromDN(user.DistinguishedName)

	// Store additional AD-specific attributes
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "objectSid":
			if len(attr.Values) > 0 {
				user.ProviderAttributes["objectSid"] = attr.Values[0]
			}
		case "lastLogon", "lastLogonTimestamp":
			if len(attr.Values) > 0 {
				user.ProviderAttributes[attr.Name] = attr.Values[0]
			}
		case "pwdLastSet":
			if len(attr.Values) > 0 {
				user.ProviderAttributes["pwdLastSet"] = attr.Values[0]
			}
		}
	}

	return user
}

// ldapEntryToDirectoryGroup converts an LDAP entry to a DirectoryGroup
func (m *activeDirectoryModule) ldapEntryToDirectoryGroup(entry *ldap.Entry) *interfaces.DirectoryGroup {
	group := &interfaces.DirectoryGroup{
		ID:                 entry.GetAttributeValue("objectGUID"),
		Name:               entry.GetAttributeValue("sAMAccountName"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		Description:        entry.GetAttributeValue("description"),
		DistinguishedName:  entry.GetAttributeValue("distinguishedName"),
		Source:             "activedirectory",
		ProviderAttributes: make(map[string]interface{}),
	}

	// Handle group type
	groupType := entry.GetAttributeValue("groupType")
	if groupType != "" {
		if gt, err := strconv.ParseInt(groupType, 10, 32); err == nil {
			// AD group type constants:
			// 0x2 = GLOBAL_GROUP, 0x4 = DOMAIN_LOCAL_GROUP, 0x8 = UNIVERSAL_GROUP
			// 0x80000000 = SECURITY_ENABLED

			if gt&0x80000000 != 0 {
				group.GroupType = interfaces.GroupTypeSecurity
			} else {
				group.GroupType = interfaces.GroupTypeDistribution
			}

			// Determine scope
			if gt&0x2 != 0 {
				group.GroupScope = interfaces.GroupScopeGlobal
			} else if gt&0x4 != 0 {
				group.GroupScope = interfaces.GroupScopeDomainLocal
			} else if gt&0x8 != 0 {
				group.GroupScope = interfaces.GroupScopeUniversal
			}

			group.ProviderAttributes["groupType"] = gt
		}
	}

	// Handle creation and modification times
	if created := entry.GetAttributeValue("whenCreated"); created != "" {
		if t, err := time.Parse("20060102150405.0Z", created); err == nil {
			group.Created = &t
		}
	}

	if modified := entry.GetAttributeValue("whenChanged"); modified != "" {
		if t, err := time.Parse("20060102150405.0Z", modified); err == nil {
			group.Modified = &t
		}
	}

	// Handle members
	members := entry.GetAttributeValues("member")
	if len(members) > 0 {
		// Extract GUIDs from member DNs (simplified - would need actual lookup)
		group.Members = members
	}

	// Extract OU from DN
	group.OU = m.extractOUFromDN(group.DistinguishedName)

	// Store additional AD-specific attributes
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "objectSid", "managedBy":
			if len(attr.Values) > 0 {
				group.ProviderAttributes[attr.Name] = attr.Values[0]
			}
		}
	}

	return group
}

// ldapEntryToOrganizationalUnit converts an LDAP entry to an OrganizationalUnit
func (m *activeDirectoryModule) ldapEntryToOrganizationalUnit(entry *ldap.Entry) *interfaces.OrganizationalUnit {
	ou := &interfaces.OrganizationalUnit{
		ID:                 entry.GetAttributeValue("objectGUID"),
		Name:               entry.GetAttributeValue("name"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		Description:        entry.GetAttributeValue("description"),
		DistinguishedName:  entry.GetAttributeValue("distinguishedName"),
		Source:             "activedirectory",
		ProviderAttributes: make(map[string]interface{}),
	}

	// Extract parent OU from DN
	ou.ParentOU = m.extractParentOUFromDN(ou.DistinguishedName)

	// Handle creation and modification times
	if created := entry.GetAttributeValue("whenCreated"); created != "" {
		if t, err := time.Parse("20060102150405.0Z", created); err == nil {
			ou.Created = &t
		}
	}

	if modified := entry.GetAttributeValue("whenChanged"); modified != "" {
		if t, err := time.Parse("20060102150405.0Z", modified); err == nil {
			ou.Modified = &t
		}
	}

	// Store additional AD-specific attributes
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "objectSid", "managedBy", "gPLink":
			if len(attr.Values) > 0 {
				ou.ProviderAttributes[attr.Name] = attr.Values[0]
			}
		}
	}

	return ou
}

// extractOUFromDN extracts the immediate parent OU from a distinguished name
func (m *activeDirectoryModule) extractOUFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	// Split DN into components
	parts := strings.Split(dn, ",")
	if len(parts) < 2 {
		return ""
	}

	// Find the first OU= component after the object itself
	for i := 1; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		if strings.HasPrefix(strings.ToUpper(part), "OU=") {
			// Return the OU name (without OU= prefix)
			return strings.TrimPrefix(part, "OU=")
		}
	}

	return ""
}

// extractParentOUFromDN extracts the parent OU DN from a distinguished name
func (m *activeDirectoryModule) extractParentOUFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	// Split DN into components
	parts := strings.Split(dn, ",")
	if len(parts) < 2 {
		return ""
	}

	// Find the first OU= component after the current OU
	for i := 1; i < len(parts); i++ {
		part := strings.TrimSpace(parts[i])
		if strings.HasPrefix(strings.ToUpper(part), "OU=") {
			// Return the full parent DN
			return strings.Join(parts[i:], ",")
		}
	}

	return ""
}

// extractDomainFromDN extracts the domain name from a distinguished name
func (m *activeDirectoryModule) extractDomainFromDN(dn string) string {
	if dn == "" {
		return ""
	}

	// Find DC= components and convert to domain name
	parts := strings.Split(dn, ",")
	var domainParts []string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			dcValue := strings.TrimPrefix(part, "DC=")
			domainParts = append(domainParts, dcValue)
		}
	}

	if len(domainParts) == 0 {
		return ""
	}

	return strings.Join(domainParts, ".")
}

// ldapEntryToGenericObject converts an LDAP entry to a generic DirectoryUser for unsupported object types
func (m *activeDirectoryModule) ldapEntryToGenericObject(entry *ldap.Entry, objectClass string) *interfaces.DirectoryUser {
	obj := &interfaces.DirectoryUser{
		ID:                 entry.GetAttributeValue("objectGUID"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		DistinguishedName:  entry.GetAttributeValue("distinguishedName"),
		Source:             "activedirectory",
		ProviderAttributes: make(map[string]interface{}),
	}

	// Mark as generic object
	obj.ProviderAttributes["object_class"] = objectClass

	// Add object-specific attributes based on type
	switch objectClass {
	case "groupPolicyContainer":
		// GPO-specific attributes
		obj.SAMAccountName = entry.GetAttributeValue("displayName") // Use displayName as identifier
		obj.ProviderAttributes["gpc_file_sys_path"] = entry.GetAttributeValue("gPCFileSysPath")
		obj.ProviderAttributes["gpc_functionality_version"] = entry.GetAttributeValue("gPCFunctionalityVersion")
		obj.ProviderAttributes["gpc_machine_extension_names"] = entry.GetAttributeValue("gPCMachineExtensionNames")
		obj.ProviderAttributes["gpc_user_extension_names"] = entry.GetAttributeValue("gPCUserExtensionNames")
		obj.ProviderAttributes["version_number"] = entry.GetAttributeValue("versionNumber")
		obj.ProviderAttributes["flags"] = entry.GetAttributeValue("flags")
		obj.ProviderAttributes["gpc_wql_filter"] = entry.GetAttributeValue("gPCWQLFilter")

	case "trustedDomain":
		// Domain trust-specific attributes
		obj.SAMAccountName = entry.GetAttributeValue("name") // Use trust name as identifier
		obj.ProviderAttributes["trust_direction"] = entry.GetAttributeValue("trustDirection")
		obj.ProviderAttributes["trust_type"] = entry.GetAttributeValue("trustType")
		obj.ProviderAttributes["trust_attributes"] = entry.GetAttributeValue("trustAttributes")
		obj.ProviderAttributes["flat_name"] = entry.GetAttributeValue("flatName")
		obj.ProviderAttributes["trust_partner"] = entry.GetAttributeValue("trustPartner")
		obj.ProviderAttributes["security_identifier"] = entry.GetAttributeValue("securityIdentifier")
	}

	// Handle creation and modification times
	if created := entry.GetAttributeValue("whenCreated"); created != "" {
		if t, err := time.Parse("20060102150405.0Z", created); err == nil {
			obj.Created = &t
		}
	}

	if modified := entry.GetAttributeValue("whenChanged"); modified != "" {
		if t, err := time.Parse("20060102150405.0Z", modified); err == nil {
			obj.Modified = &t
		}
	}

	// Store all other attributes
	for _, attr := range entry.Attributes {
		if len(attr.Values) > 0 && attr.Values[0] != "" {
			// Skip already processed attributes
			processed := map[string]bool{
				"objectGUID": true, "displayName": true, "distinguishedName": true,
				"whenCreated": true, "whenChanged": true,
			}

			if !processed[attr.Name] {
				if len(attr.Values) == 1 {
					obj.ProviderAttributes[attr.Name] = attr.Values[0]
				} else {
					obj.ProviderAttributes[attr.Name] = attr.Values
				}
			}
		}
	}

	return obj
}
