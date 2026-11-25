#Requires -Version 5.1
<#
.SYNOPSIS
    Removes a specific attacker foothold by ID: an MFA method, a directory role
    assignment, an app client secret, or an inbox rule.

.DESCRIPTION
    Precise, defender-side remediation. Each foothold is removed by its own
    identifier, so the user's legitimate methods and settings are left untouched.
    Supports -WhatIf and prompts before each change.

    Every removal is verified: the script reports success only when the Graph or
    Exchange call actually succeeds, and reports a clear message (including
    "already removed") when it does not. Run Get-AttackerFootholds.ps1 first to
    collect the IDs below.

    Connect to Microsoft Graph and Exchange Online as an administrator before
    running, or let the script prompt an interactive sign-in.

.PARAMETER User                UPN the foothold belongs to.
.PARAMETER MfaMethodId         Id of the attacker-registered authentication method to delete.
.PARAMETER RoleAssignmentId    Id of the directory role assignment to remove.
.PARAMETER AppObjectId         App (object id) whose secret to remove (with -SecretKeyId).
.PARAMETER SecretKeyId         KeyId of the client secret to remove.
.PARAMETER InboxRuleName       Name of the inbox rule to remove.
.PARAMETER WhatIf              Show what would be removed without changing anything.

.NOTES
    Author:  Sean O'Farrell
    Website: https://cloud-secure.ai/
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string] $User,
    [string] $MfaMethodId,
    [string] $RoleAssignmentId,
    [string] $AppObjectId,
    [string] $SecretKeyId,
    [string] $InboxRuleName
)

$ErrorActionPreference = 'Stop'
$removed = 0
function Say($icon, $msg, $col = 'White') { Write-Host "$icon $msg" -ForegroundColor $col }

$needGraph    = [bool]($MfaMethodId -or $RoleAssignmentId -or ($AppObjectId -and $SecretKeyId))
$needExchange = [bool]$InboxRuleName

# --- Prerequisite modules ---------------------------------------------------
$req = @()
if ($needGraph)    { $req += 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Identity.Governance','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Applications' }
if ($needExchange) { $req += 'ExchangeOnlineManagement' }
foreach ($m in ($req | Select-Object -Unique)) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Say '[X]' "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser" Red; exit 1
    }
}

$u = $null
if ($needGraph) {
    if (-not (Get-MgContext)) {
        Say '[*]' 'Connecting to Microsoft Graph (sign in as an administrator)...' Yellow
        Connect-MgGraph -Scopes 'UserAuthenticationMethod.ReadWrite.All','RoleManagement.ReadWrite.Directory','Application.ReadWrite.All','User.Read.All' | Out-Null
    }
    $u = Get-MgUser -Filter "userPrincipalName eq '$User'"
    if (-not $u) { Say '[X]' "User $User not found." Red; exit 1 }
}

# --- MFA method (dispatch on the method's actual type, verify the result) ----
if ($MfaMethodId -and $PSCmdlet.ShouldProcess("$User method $MfaMethodId", 'Delete authentication method')) {
    $method = Get-MgUserAuthenticationMethod -UserId $u.Id | Where-Object { $_.Id -eq $MfaMethodId }
    if (-not $method) {
        Say '[!]' "MFA method $MfaMethodId not found on $User (already removed?)." Yellow
    } else {
        $type = [string]$method.AdditionalProperties['@odata.type']
        try {
            switch -Wildcard ($type) {
                '*microsoftAuthenticator*' { Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $u.Id -MicrosoftAuthenticatorAuthenticationMethodId $MfaMethodId -ErrorAction Stop }
                '*softwareOath*'           { Remove-MgUserAuthenticationSoftwareOathMethod          -UserId $u.Id -SoftwareOathAuthenticationMethodId          $MfaMethodId -ErrorAction Stop }
                '*phone*'                  { Remove-MgUserAuthenticationPhoneMethod                 -UserId $u.Id -PhoneAuthenticationMethodId                 $MfaMethodId -ErrorAction Stop }
                '*fido2*'                  { Remove-MgUserAuthenticationFido2Method                 -UserId $u.Id -Fido2AuthenticationMethodId                 $MfaMethodId -ErrorAction Stop }
                '*email*'                  { Remove-MgUserAuthenticationEmailMethod                 -UserId $u.Id -EmailAuthenticationMethodId                 $MfaMethodId -ErrorAction Stop }
                default { throw "Unhandled method type '$type' - remove it manually in the portal." }
            }
            Say '[-]' "Removed $type method $MfaMethodId from $User." Green; $removed++
        } catch { Say '[!]' "Could not remove MFA method $MfaMethodId : $($_.Exception.Message)" Yellow }
    }
}

# --- Directory role ---------------------------------------------------------
if ($RoleAssignmentId -and $PSCmdlet.ShouldProcess("$User role $RoleAssignmentId", 'Remove role assignment')) {
    try {
        Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId $RoleAssignmentId -ErrorAction Stop
        Say '[-]' "Removed role assignment $RoleAssignmentId." Green; $removed++
    } catch { Say '[!]' "Could not remove role assignment $RoleAssignmentId (already removed?): $($_.Exception.Message)" Yellow }
}

# --- App secret -------------------------------------------------------------
if ($AppObjectId -and $SecretKeyId -and $PSCmdlet.ShouldProcess("app $AppObjectId secret $SecretKeyId", 'Remove client secret')) {
    try {
        Remove-MgApplicationPassword -ApplicationId $AppObjectId -KeyId $SecretKeyId -ErrorAction Stop
        Say '[-]' "Removed client secret $SecretKeyId from app $AppObjectId." Green
        Say '[*]' 'Review the app sign-in logs for anything the secret was used for.' Yellow
        $removed++
    } catch { Say '[!]' "Could not remove client secret $SecretKeyId (already removed?): $($_.Exception.Message)" Yellow }
}

# --- Inbox rule -------------------------------------------------------------
if ($InboxRuleName) {
    if (-not (Get-Command Remove-InboxRule -ErrorAction SilentlyContinue)) {
        Say '[*]' 'Connecting to Exchange Online (sign in as an administrator)...' Yellow
        Connect-ExchangeOnline -ShowBanner:$false
    }
    if ($PSCmdlet.ShouldProcess("$User rule $InboxRuleName", 'Remove inbox rule')) {
        $rule = Get-InboxRule -Mailbox $User -ErrorAction SilentlyContinue | Where-Object Name -eq $InboxRuleName
        if (-not $rule) {
            Say '[!]' "Inbox rule '$InboxRuleName' not found on $User (already removed?)." Yellow
        } else {
            try {
                Remove-InboxRule -Mailbox $User -Identity $InboxRuleName -Confirm:$false -ErrorAction Stop
                Say '[-]' "Removed inbox rule '$InboxRuleName'." Green; $removed++
            } catch { Say '[!]' "Could not remove inbox rule '$InboxRuleName': $($_.Exception.Message)" Yellow }
        }
    }
}

Say '[OK]' "Done. Footholds removed this run: $removed" Green
Say '[>]' 'Re-run Get-AttackerFootholds.ps1 to confirm the account is clean.' White
