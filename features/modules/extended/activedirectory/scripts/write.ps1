# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# write.ps1 - the fixed write script of the CFGMS activedirectory module.
#
# The module embeds this file, stages it in an admin-only directory, checks its
# SHA-256 against the embedded constant before every run, and runs it with
#   powershell.exe -NoProfile -NonInteractive -File <path>
# Nothing is composed at runtime. Each run performs exactly one write on
# exactly one object; there is no delete operation.
#
# Stdin: one line holding the JSON request, then, for create_user only, the
# new user's one-time password. The password never becomes a PowerShell
# string: it is read one character at a time straight into a SecureString,
# which is the only form any cmdlet receives, so neither script block logging,
# module logging nor a transcript can record it. Request values are only ever
# passed as typed cmdlet parameters and are never echoed, on any stream.
#
# Request operations:
#   create_user          sam_account_name, user_principal_name, display_name, mail, ou, enabled
#   set_user_enabled     id, enabled
#   set_user_attributes  id, display_name and/or mail
#   create_group         sam_account_name, ou, group_scope, group_category
#   add_group_member     id (group), member_id
#   remove_group_member  id (group), member_id
#
# Output (stdout), one JSON object per line:
#   {"type":"done","id":"<objectGUID of the object written>"}
#   {"type":"error","code":"<fixed code>","detail":"<exception type>"}
#                            on failure, followed by exit code 1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

[Console]::InputEncoding = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

function Write-Record($Record) {
    [Console]::Out.WriteLine(($Record | ConvertTo-Json -Compress -Depth 3))
}

function Stop-WithError([string]$Code, [string]$Detail = '') {
    Write-Record ([ordered]@{ type = 'error'; code = $Code; detail = $Detail })
    exit 1
}

$NamePattern = '^[A-Za-z0-9._@][A-Za-z0-9._@ -]*$'
$GuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
$OuPattern = '^(?:(?:OU|CN)=[A-Za-z0-9._-](?:[A-Za-z0-9._ -]{0,62}[A-Za-z0-9._-])?,)*(?:DC=[A-Za-z0-9-]{1,63},)*DC=[A-Za-z0-9-]{1,63}$'

# ---- request ----------------------------------------------------------------

try {
    $line = [Console]::In.ReadLine()
} catch {
    Stop-WithError 'request_unreadable'
}
if ($null -eq $line -or $line.Length -gt 8192) { Stop-WithError 'request_too_large' }

try {
    $request = $line | ConvertFrom-Json
} catch {
    Stop-WithError 'request_not_json'
}
if ($null -eq $request -or $request -isnot [System.Management.Automation.PSCustomObject]) {
    Stop-WithError 'request_not_object'
}

$allowed = @('operation', 'id', 'member_id', 'sam_account_name', 'user_principal_name', 'display_name', 'mail', 'ou', 'enabled', 'group_scope', 'group_category')
$fields = @($request.PSObject.Properties | ForEach-Object { $_.Name })
foreach ($field in $fields) {
    if ($allowed -notcontains $field) { Stop-WithError 'request_unknown_field' }
}

$operation = $request.operation
if ($operation -isnot [string] -or @('create_user', 'set_user_enabled', 'set_user_attributes', 'create_group', 'add_group_member', 'remove_group_member') -cnotcontains $operation) {
    Stop-WithError 'invalid_operation'
}

function Get-Name([string]$Field, [int]$MaxLength, [bool]$Required) {
    if ($fields -notcontains $Field) {
        if ($Required) { Stop-WithError ('missing_' + $Field) }
        return $null
    }
    $value = $request.$Field
    if ($value -isnot [string]) { Stop-WithError ('invalid_' + $Field) }
    if ($value -eq '') {
        if ($Required) { Stop-WithError ('missing_' + $Field) }
        return ''
    }
    if ($value.Length -gt $MaxLength -or $value -cnotmatch $NamePattern) { Stop-WithError ('invalid_' + $Field) }
    return $value
}

function Get-Guid([string]$Field) {
    if ($fields -notcontains $Field) { Stop-WithError ('missing_' + $Field) }
    $value = $request.$Field
    if ($value -isnot [string] -or $value -cnotmatch $GuidPattern) { Stop-WithError ('invalid_' + $Field) }
    return [guid]$value
}

function Get-Ou {
    if ($fields -notcontains 'ou') { return '' }
    $value = $request.ou
    if ($value -isnot [string]) { Stop-WithError 'invalid_ou' }
    if ($value -ne '' -and ($value.Length -gt 512 -or $value -notmatch $OuPattern)) { Stop-WithError 'invalid_ou' }
    return $value
}

function Get-Enabled([bool]$Required) {
    if ($fields -notcontains 'enabled') {
        if ($Required) { Stop-WithError 'missing_enabled' }
        return $true
    }
    $value = $request.enabled
    if ($value -isnot [bool]) { Stop-WithError 'invalid_enabled' }
    return $value
}

# ---- password ---------------------------------------------------------------

# Reads the rest of stdin, up to the first line break, one character at a time
# into a SecureString. No string holding the password is ever created.
function Read-InitialPassword {
    $secure = New-Object System.Security.SecureString
    while ($true) {
        $c = [Console]::In.Read()
        if ($c -lt 0 -or $c -eq 10 -or $c -eq 13) { break }
        if ($secure.Length -ge 256) { $secure.Dispose(); Stop-WithError 'password_too_long' }
        $secure.AppendChar([char]$c)
    }
    if ($secure.Length -eq 0) { $secure.Dispose(); Stop-WithError 'password_missing' }
    $secure.MakeReadOnly()
    return , $secure
}

# ---- validate everything before touching the directory -----------------------

$params = @{}
$password = $null
switch -CaseSensitive ($operation) {
    'create_user' {
        $sam = Get-Name 'sam_account_name' 20 $true
        $params = @{
            Name                  = $sam
            SamAccountName        = $sam
            Enabled               = (Get-Enabled $false)
            ChangePasswordAtLogon = $true
            PassThru              = $true
        }
        $upn = Get-Name 'user_principal_name' 256 $false
        if ($upn) { $params['UserPrincipalName'] = $upn }
        $displayName = Get-Name 'display_name' 256 $false
        if ($displayName) { $params['DisplayName'] = $displayName }
        $mail = Get-Name 'mail' 256 $false
        if ($mail) { $params['EmailAddress'] = $mail }
        $ou = Get-Ou
        if ($ou -ne '') { $params['Path'] = $ou }
        $password = Read-InitialPassword
    }
    'set_user_enabled' {
        $id = Get-Guid 'id'
        $enabled = Get-Enabled $true
    }
    'set_user_attributes' {
        $id = Get-Guid 'id'
        $replace = @{}
        $clear = New-Object System.Collections.Generic.List[string]
        foreach ($pair in @(@{ field = 'display_name'; attribute = 'displayName' }, @{ field = 'mail'; attribute = 'mail' })) {
            $value = Get-Name $pair.field 256 $false
            if ($null -eq $value) { continue }
            if ($value -eq '') { $clear.Add($pair.attribute) } else { $replace[$pair.attribute] = $value }
        }
        if ($replace.Count -eq 0 -and $clear.Count -eq 0) { Stop-WithError 'nothing_to_set' }
    }
    'create_group' {
        $sam = Get-Name 'sam_account_name' 64 $true
        $scope = 'Global'
        if ($fields -contains 'group_scope') {
            $scope = $request.group_scope
            if (@('DomainLocal', 'Global', 'Universal') -cnotcontains $scope) { Stop-WithError 'invalid_group_scope' }
        }
        $category = 'Security'
        if ($fields -contains 'group_category') {
            $category = $request.group_category
            if (@('Security', 'Distribution') -cnotcontains $category) { Stop-WithError 'invalid_group_category' }
        }
        $params = @{
            Name           = $sam
            SamAccountName = $sam
            GroupScope     = $scope
            GroupCategory  = $category
            PassThru       = $true
        }
        $ou = Get-Ou
        if ($ou -ne '') { $params['Path'] = $ou }
    }
    default {
        # add_group_member, remove_group_member
        $id = Get-Guid 'id'
        $memberId = Get-Guid 'member_id'
    }
}

# ---- write ------------------------------------------------------------------

try {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Stop-WithError 'ad_module_unavailable' $_.Exception.GetType().FullName
    }

    switch -CaseSensitive ($operation) {
        'create_user' {
            $params['AccountPassword'] = $password
            $created = New-ADUser @params
            Write-Record ([ordered]@{ type = 'done'; id = $created.ObjectGUID.ToString() })
        }
        'set_user_enabled' {
            $user = Get-ADUser -Identity $id
            if ($enabled) {
                Enable-ADAccount -Identity $user
            } else {
                Disable-ADAccount -Identity $user
            }
            Write-Record ([ordered]@{ type = 'done'; id = $user.ObjectGUID.ToString() })
        }
        'set_user_attributes' {
            $user = Get-ADUser -Identity $id
            $setParams = @{ Identity = $user }
            if ($replace.Count -gt 0) { $setParams['Replace'] = $replace }
            if ($clear.Count -gt 0) { $setParams['Clear'] = $clear.ToArray() }
            Set-ADUser @setParams
            Write-Record ([ordered]@{ type = 'done'; id = $user.ObjectGUID.ToString() })
        }
        'create_group' {
            $created = New-ADGroup @params
            Write-Record ([ordered]@{ type = 'done'; id = $created.ObjectGUID.ToString() })
        }
        'add_group_member' {
            $group = Get-ADGroup -Identity $id
            $member = Get-ADObject -Identity $memberId
            Add-ADGroupMember -Identity $group -Members $member.DistinguishedName
            Write-Record ([ordered]@{ type = 'done'; id = $group.ObjectGUID.ToString() })
        }
        'remove_group_member' {
            $group = Get-ADGroup -Identity $id
            $member = Get-ADObject -Identity $memberId
            Remove-ADGroupMember -Identity $group -Members $member.DistinguishedName -Confirm:$false
            Write-Record ([ordered]@{ type = 'done'; id = $group.ObjectGUID.ToString() })
        }
    }
    exit 0
} catch {
    Stop-WithError 'ad_write_failed' $_.Exception.GetType().FullName
} finally {
    if ($null -ne $password) { $password.Dispose() }
}
