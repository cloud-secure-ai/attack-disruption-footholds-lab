#Requires -Version 5.1
<#
.SYNOPSIS
    Enumerates the persistence footholds an attacker may leave on a compromised
    account: MFA methods, directory roles, app secrets, and inbox rules.

.DESCRIPTION
    Stage 5 of the "Contained isn't clean" lab - the hunt and verify step. Reads
    through Microsoft Graph and Exchange Online, so it surfaces hidden and
    temporary MFA methods the Entra portal does not show. Read-only.

    Run it once to find the footholds, and again after removal to confirm the
    account is clean.

.PARAMETER User          UPN of the account to inspect.
.PARAMETER AppObjectId   Optional app registration to list client secrets for.
.PARAMETER SkipMailbox   Skip the Exchange Online inbox-rule check.

.NOTES
    Author:  Sen O'Farrell
    Website: https://cloud-secure.ai/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $User,
    [string] $AppObjectId,
    [switch] $SkipMailbox
)

$ErrorActionPreference = 'Stop'

# --- Prerequisite modules ---------------------------------------------------
$req = @('Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Identity.Governance','Microsoft.Graph.Identity.SignIns','Microsoft.Graph.Applications')
if (-not $SkipMailbox) { $req += 'ExchangeOnlineManagement' }
foreach ($m in ($req | Select-Object -Unique)) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        Write-Host "[X] Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser" -ForegroundColor Red; exit 1
    }
}
function Section($t) { Write-Host ""; Write-Host "[*] $t" -ForegroundColor Cyan }

if (-not (Get-MgContext)) {
    Write-Host '[*] Connecting to Microsoft Graph (read-only)...' -ForegroundColor Yellow
    Connect-MgGraph -Scopes 'User.Read.All','UserAuthenticationMethod.Read.All','RoleManagement.Read.Directory','Application.Read.All' | Out-Null
}

$u = Get-MgUser -Filter "userPrincipalName eq '$User'"
if (-not $u) { Write-Host "[X] User $User not found." -ForegroundColor Red; exit 1 }
Write-Host "[*] Inspecting: $User ($($u.Id))" -ForegroundColor White

# --- MFA / auth methods (includes hidden + temporary) -----------------------
Section 'Authentication methods (full list via Graph)'
Get-MgUserAuthenticationMethod -UserId $u.Id | ForEach-Object {
    $type = ($_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.','')
    [pscustomobject]@{ MethodId = $_.Id; Type = $type }
} | Format-Table -AutoSize

# --- Directory roles --------------------------------------------------------
Section 'Directory role assignments'
Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$($u.Id)'" |
    ForEach-Object {
        $rd = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId
        [pscustomobject]@{ AssignmentId = $_.Id; Role = $rd.DisplayName; Scope = $_.DirectoryScopeId }
    } | Format-Table -AutoSize

# --- App secrets ------------------------------------------------------------
if ($AppObjectId) {
    Section "Client secrets on app $AppObjectId"
    (Get-MgApplication -ApplicationId $AppObjectId).PasswordCredentials |
        Select-Object KeyId, DisplayName, StartDateTime, EndDateTime | Format-Table -AutoSize
}

# --- Inbox rules ------------------------------------------------------------
if (-not $SkipMailbox) {
    Section 'Inbox rules'
    if (-not (Get-Command Get-InboxRule -ErrorAction SilentlyContinue)) {
        Write-Host '[*] Connecting to Exchange Online...' -ForegroundColor Yellow
        Connect-ExchangeOnline -ShowBanner:$false
    }
    Get-InboxRule -Mailbox $User |
        Select-Object Name, Enabled, SubjectOrBodyContainsWords, MoveToFolder, MarkAsRead, Forward* |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "[OK] Enumeration complete. Compare each item against the attacker IP and timestamps from your hunting queries." -ForegroundColor Green
