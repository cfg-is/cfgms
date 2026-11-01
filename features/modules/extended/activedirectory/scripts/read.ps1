# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# read.ps1 - the fixed, read-only Active Directory inventory script of the
# CFGMS activedirectory module.
#
# The module embeds this file, stages it in an admin-only directory, checks its
# SHA-256 against the embedded constant before every run, and runs it with
#   powershell.exe -NoProfile -NonInteractive -File <path>
# Nothing is composed at runtime: the request arrives as one JSON document on
# stdin, is validated here, and its values are only ever passed as typed cmdlet
# parameters (-ResultPageSize, -Server, -Identity) or as variables an
# ActiveDirectory -Filter refers to by name. Nothing from the request reaches
# argv or script text.
#
# Request (stdin): {"operation":"status"|"users"|"groups","page_size":1-5000,"domain":""}
#   or, to find the object of one declared resource:
#   {"operation":"find_user"|"find_group","id":"<objectGUID>","sam_account_name":"<name>",
#    "members":["<name>", ...]}       (members: find_group only)
#
# Output (stdout): newline-delimited JSON, one object per line:
#   {"type":"status", ...}   domain summary
#   {"type":"user", ...}     one line per user
#   {"type":"group", ...}    one line per group
#   find_user / find_group: up to two user or group lines, "match":"id" for the
#   object with the requested objectGUID and "match":"name" for the object with
#   the requested sAMAccountName, then for find_group one line per requested
#   member: {"type":"member","index":<request index>,"found":..,"id":..,
#   "is_member":..,"uncertain":..}, relative to the id match or, without one,
#   the name match.
#   {"type":"error","code":"<fixed code>","detail":"<exception type>"}
#                            on failure, followed by exit code 1
# Request values are never echoed, on any stream.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

[Console]::InputEncoding = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

# Direct-membership lists are bounded per object. A longer list is cut to the
# first entries in ordinal order and flagged, never dropped silently.
$MaxListEntries = 10000

# AD Web Services returns at most MaxGroupOrMemberEntries values of a
# membership attribute (memberOf, member) per object; the default is 5000. A
# memberOf list that reaches this count may have been capped by the server, so
# it is flagged as truncated rather than reported as complete.
$AdwsMembershipCap = 5000

function Write-Record($Record) {
    [Console]::Out.WriteLine(($Record | ConvertTo-Json -Compress -Depth 6))
}

function Stop-WithError([string]$Code, [string]$Detail = '') {
    Write-Record ([ordered]@{ type = 'error'; code = $Code; detail = $Detail })
    exit 1
}

function Get-OrdinalSorted([string[]]$Values) {
    $copy = [string[]]@($Values)
    [Array]::Sort($copy, [StringComparer]::Ordinal)
    return , $copy
}

function Get-StringOrEmpty($Value) {
    if ($null -eq $Value) { return '' }
    return [string]$Value
}

function Get-IsoUtc($Value) {
    if ($null -eq $Value) { return '' }
    return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

# ---- request ----------------------------------------------------------------

try {
    $raw = [Console]::In.ReadToEnd()
} catch {
    Stop-WithError 'request_unreadable'
}
if ($raw.Length -gt 131072) { Stop-WithError 'request_too_large' }

try {
    $request = $raw | ConvertFrom-Json
} catch {
    Stop-WithError 'request_not_json'
}
if ($null -eq $request -or $request -isnot [System.Management.Automation.PSCustomObject]) {
    Stop-WithError 'request_not_object'
}

$fields = @($request.PSObject.Properties | ForEach-Object { $_.Name })
foreach ($field in $fields) {
    if (@('operation', 'page_size', 'domain', 'id', 'sam_account_name', 'members') -notcontains $field) { Stop-WithError 'request_unknown_field' }
}

$operation = $request.operation
if ($operation -isnot [string] -or @('status', 'users', 'groups', 'find_user', 'find_group') -cnotcontains $operation) {
    Stop-WithError 'invalid_operation'
}

# Names: letters, digits, '.', '_', '@', '-' and spaces, not starting with '-'
# or a space, at most 64 characters (a user's sAMAccountName is at most 20).
$NamePattern = '^[A-Za-z0-9._@][A-Za-z0-9._@ -]{0,63}$'
$GuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

$findId = ''
if ($fields -contains 'id') {
    $value = $request.id
    if ($value -isnot [string] -or ($value -ne '' -and $value -cnotmatch $GuidPattern)) { Stop-WithError 'invalid_id' }
    $findId = $value
}
$findName = ''
if ($fields -contains 'sam_account_name') {
    $value = $request.sam_account_name
    if ($value -isnot [string] -or ($value -ne '' -and $value -cnotmatch $NamePattern)) { Stop-WithError 'invalid_name' }
    $findName = $value
}
$findMembers = @()
if ($fields -contains 'members') {
    if ($operation -cne 'find_group') { Stop-WithError 'request_unknown_field' }
    $findMembers = @($request.members)
    if ($findMembers.Count -gt 2000) { Stop-WithError 'too_many_members' }
    foreach ($value in $findMembers) {
        if ($value -isnot [string] -or $value -cnotmatch $NamePattern) { Stop-WithError 'invalid_member' }
    }
}
if (($operation -ceq 'find_user' -or $operation -ceq 'find_group') -and $findId -eq '' -and $findName -eq '') {
    Stop-WithError 'missing_identity'
}

$pageSize = 1000
if ($fields -contains 'page_size') {
    $value = $request.page_size
    if (-not ($value -is [int] -or $value -is [long])) { Stop-WithError 'invalid_page_size' }
    if ($value -lt 1 -or $value -gt 5000) { Stop-WithError 'invalid_page_size' }
    $pageSize = [int]$value
}

$domain = ''
if ($fields -contains 'domain') {
    $value = $request.domain
    if ($value -isnot [string]) { Stop-WithError 'invalid_domain' }
    if ($value -ne '' -and $value -cnotmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$') {
        Stop-WithError 'invalid_domain'
    }
    $domain = $value
}

# Typed parameters only: the validated domain becomes -Server, never text.
$server = @{}
if ($domain -ne '') { $server['Server'] = $domain }

# ---- directory reads ----------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Stop-WithError 'ad_module_unavailable' $_.Exception.GetType().FullName
}

try {
    $adDomain = Get-ADDomain @server
    $dnsRoot = Get-StringOrEmpty $adDomain.DNSRoot

    if ($operation -ceq 'status') {
        $forest = Get-ADForest @server
        $locator = @{ Discover = $true }
        if ($domain -ne '') { $locator['DomainName'] = $domain }
        $dc = Get-ADDomainController @locator
        Write-Record ([ordered]@{
                type              = 'status'
                domain            = $dnsRoot
                netbios_name      = Get-StringOrEmpty $adDomain.NetBIOSName
                forest_root       = Get-StringOrEmpty $forest.Name
                domain_controller = Get-StringOrEmpty (@($dc.HostName)[0])
            })
        exit 0
    }

    if ($operation -ceq 'find_user' -or $operation -ceq 'find_group') {
        $isGroup = $operation -ceq 'find_group'
        $props = @('DisplayName', 'mail', 'MemberOf', 'UserPrincipalName')
        if ($isGroup) { $props = @('DisplayName', 'MemberOf') }

        $byId = $null
        if ($findId -ne '') {
            $guid = [guid]$findId
            if ($isGroup) {
                $byId = @(Get-ADGroup -Filter 'ObjectGUID -eq $guid' -Properties $props @server)
            } else {
                $byId = @(Get-ADUser -Filter 'ObjectGUID -eq $guid' -Properties $props @server)
            }
            if ($byId.Count -eq 0) { $byId = $null } else { $byId = $byId[0] }
        }
        $byName = $null
        if ($findName -ne '') {
            $samValue = $findName
            if ($isGroup) {
                $byName = @(Get-ADGroup -Filter 'sAMAccountName -eq $samValue' -Properties $props @server)
            } else {
                $byName = @(Get-ADUser -Filter 'sAMAccountName -eq $samValue' -Properties $props @server)
            }
            if ($byName.Count -eq 0) { $byName = $null } else { $byName = $byName[0] }
        }

        foreach ($pair in @(@{ match = 'id'; o = $byId }, @{ match = 'name'; o = $byName })) {
            $o = $pair.o
            if ($null -eq $o) { continue }
            if ($isGroup) {
                Write-Record ([ordered]@{
                        type               = 'group'
                        match              = $pair.match
                        id                 = $o.ObjectGUID.ToString()
                        sam_account_name   = Get-StringOrEmpty $o.SamAccountName
                        display_name       = Get-StringOrEmpty $o.DisplayName
                        distinguished_name = Get-StringOrEmpty $o.DistinguishedName
                        group_scope        = Get-StringOrEmpty $o.GroupScope
                        group_category     = Get-StringOrEmpty $o.GroupCategory
                        directory_domain   = $dnsRoot
                    })
            } else {
                Write-Record ([ordered]@{
                        type                = 'user'
                        match               = $pair.match
                        id                  = $o.ObjectGUID.ToString()
                        sam_account_name    = Get-StringOrEmpty $o.SamAccountName
                        user_principal_name = Get-StringOrEmpty $o.UserPrincipalName
                        display_name        = Get-StringOrEmpty $o.DisplayName
                        mail                = Get-StringOrEmpty $o.mail
                        enabled             = [bool]$o.Enabled
                        distinguished_name  = Get-StringOrEmpty $o.DistinguishedName
                        directory_domain    = $dnsRoot
                    })
            }
        }

        if ($isGroup -and $findMembers.Count -gt 0) {
            $target = $byId
            if ($null -eq $target) { $target = $byName }
            $targetDn = ''
            if ($null -ne $target) { $targetDn = [string]$target.DistinguishedName }
            for ($i = 0; $i -lt $findMembers.Count; $i++) {
                $memberName = [string]$findMembers[$i]
                $found = @(Get-ADObject -Filter '(objectClass -eq "user" -or objectClass -eq "group") -and sAMAccountName -eq $memberName' -Properties memberOf @server)
                if ($found.Count -eq 0) {
                    Write-Record ([ordered]@{ type = 'member'; index = $i; found = $false; id = ''; is_member = $false; uncertain = $false })
                    continue
                }
                $o = $found[0]
                $rawMemberOf = @($o.memberOf | Where-Object { $null -ne $_ })
                $isMember = $false
                if ($targetDn -ne '') {
                    foreach ($dn in $rawMemberOf) {
                        if ([string]::Equals([string]$dn, $targetDn, [StringComparison]::OrdinalIgnoreCase)) { $isMember = $true; break }
                    }
                }
                # memberOf is capped by AD Web Services; a member that is not
                # found in a capped list may still be a member.
                $uncertain = (-not $isMember) -and ($rawMemberOf.Count -ge $AdwsMembershipCap)
                Write-Record ([ordered]@{
                        type      = 'member'
                        index     = $i
                        found     = $true
                        id        = $o.ObjectGUID.ToString()
                        is_member = $isMember
                        uncertain = $uncertain
                    })
            }
        }
        exit 0
    }

    # Group index: distinguished name -> objectGUID. PowerShell hashtables
    # compare string keys case-insensitively, as AD compares DNs.
    $groupIndex = @{}
    $groups = @(Get-ADGroup -Filter * -ResultPageSize $pageSize -Properties DisplayName, MemberOf @server)
    foreach ($g in $groups) {
        $groupIndex[[string]$g.DistinguishedName] = $g.ObjectGUID.ToString()
    }

    if ($operation -ceq 'users') {
        Get-ADUser -Filter * -ResultPageSize $pageSize -Properties DisplayName, mail, MemberOf, whenCreated, UserPrincipalName @server |
            ForEach-Object {
                $u = $_
                $rawMemberOf = @($u.MemberOf | Where-Object { $null -ne $_ })
                $ids = New-Object System.Collections.Generic.List[string]
                foreach ($dn in $rawMemberOf) {
                    if ($groupIndex.ContainsKey([string]$dn)) { $ids.Add($groupIndex[[string]$dn]) }
                }
                $sorted = Get-OrdinalSorted $ids.ToArray()
                $truncated = $rawMemberOf.Count -ge $AdwsMembershipCap
                if ($sorted.Count -gt $MaxListEntries) {
                    $sorted = [string[]]$sorted[0..($MaxListEntries - 1)]
                    $truncated = $true
                }
                Write-Record ([ordered]@{
                        type                = 'user'
                        id                  = $u.ObjectGUID.ToString()
                        sam_account_name    = Get-StringOrEmpty $u.SamAccountName
                        user_principal_name = Get-StringOrEmpty $u.UserPrincipalName
                        display_name        = Get-StringOrEmpty $u.DisplayName
                        mail                = Get-StringOrEmpty $u.mail
                        enabled             = [bool]$u.Enabled
                        distinguished_name  = Get-StringOrEmpty $u.DistinguishedName
                        object_sid          = Get-StringOrEmpty $u.SID.Value
                        when_created        = Get-IsoUtc $u.whenCreated
                        directory_domain    = $dnsRoot
                        member_of           = $sorted
                        member_of_truncated = $truncated
                    })
            }
        exit 0
    }

    # operation 'groups'. A group's own member list is never read: AD Web
    # Services caps it at $AdwsMembershipCap values, so a large group would
    # silently lose members. Membership is taken from the memberOf back-link
    # instead. User and group membership is carried on each member's own
    # member_of; other_members collects, per group, the direct members that are
    # neither users nor groups, found with one paged query per member class.
    $otherByGroup = @{}
    $otherCapped = @{}
    # The type comes from the query that matched. ObjectClass on the result is
    # only the most specific class (a group managed service account reports its
    # own class), so membership in the computer query is what makes a computer.
    # Computers carry objectClass user too, so the catch-all query, which
    # excludes users, never matches them.
    $memberQueries = @(
        @{ filter = '(&(memberOf=*)(|(objectClass=computer)(objectClass=contact)(objectClass=foreignSecurityPrincipal)))'; catchAll = $false },
        @{ filter = '(&(memberOf=*)(!(objectClass=user))(!(objectClass=group))(!(objectClass=contact))(!(objectClass=foreignSecurityPrincipal)))'; catchAll = $true }
    )
    foreach ($query in $memberQueries) {
        Get-ADObject -LDAPFilter $query.filter -ResultPageSize $pageSize -Properties DisplayName, memberOf @server |
            ForEach-Object {
                $o = $_
                $type = 'other'
                if (-not $query.catchAll) {
                    $type = 'computer'
                    if ($o.ObjectClass -ceq 'contact') { $type = 'contact' }
                    elseif ($o.ObjectClass -ceq 'foreignSecurityPrincipal') { $type = 'foreign_security_principal' }
                }
                $name = Get-StringOrEmpty $o.DisplayName
                if ($name -eq '') { $name = Get-StringOrEmpty $o.Name }
                $member = [ordered]@{ type = $type; id = $o.ObjectGUID.ToString(); name = $name }

                $rawMemberOf = @($o.memberOf | Where-Object { $null -ne $_ })
                $capped = $rawMemberOf.Count -ge $AdwsMembershipCap
                foreach ($dn in $rawMemberOf) {
                    $groupId = $groupIndex[[string]$dn]
                    if ($null -eq $groupId) { continue }
                    if (-not $otherByGroup.ContainsKey($groupId)) {
                        $otherByGroup[$groupId] = New-Object System.Collections.Generic.List[object]
                    }
                    $otherByGroup[$groupId].Add($member)
                    if ($capped) { $otherCapped[$groupId] = $true }
                }
            }
    }

    foreach ($g in $groups) {
        $groupId = $g.ObjectGUID.ToString()
        $rawMemberOf = @($g.MemberOf | Where-Object { $null -ne $_ })
        $parentIds = New-Object System.Collections.Generic.List[string]
        foreach ($dn in $rawMemberOf) {
            if ($groupIndex.ContainsKey([string]$dn)) { $parentIds.Add($groupIndex[[string]$dn]) }
        }
        $memberOf = Get-OrdinalSorted $parentIds.ToArray()
        $memberOfTruncated = $rawMemberOf.Count -ge $AdwsMembershipCap
        if ($memberOf.Count -gt $MaxListEntries) {
            $memberOf = [string[]]$memberOf[0..($MaxListEntries - 1)]
            $memberOfTruncated = $true
        }

        $otherList = @()
        if ($otherByGroup.ContainsKey($groupId)) {
            $otherList = @($otherByGroup[$groupId] | Sort-Object -Property @{ Expression = { $_.id } })
        }
        # A contributing member whose own memberOf may have been capped could
        # be missing from this list, so the list is flagged.
        $othersTruncated = $otherCapped.ContainsKey($groupId)
        if ($otherList.Count -gt $MaxListEntries) {
            $otherList = @($otherList[0..($MaxListEntries - 1)])
            $othersTruncated = $true
        }

        Write-Record ([ordered]@{
                type                    = 'group'
                id                      = $groupId
                sam_account_name        = Get-StringOrEmpty $g.SamAccountName
                display_name            = Get-StringOrEmpty $g.DisplayName
                distinguished_name      = Get-StringOrEmpty $g.DistinguishedName
                group_scope             = Get-StringOrEmpty $g.GroupScope
                group_category          = Get-StringOrEmpty $g.GroupCategory
                directory_domain        = $dnsRoot
                member_of               = $memberOf
                member_of_truncated     = $memberOfTruncated
                other_members           = $otherList
                other_members_truncated = $othersTruncated
            })
    }
    exit 0
} catch {
    Stop-WithError 'ad_query_failed' $_.Exception.GetType().FullName
}
