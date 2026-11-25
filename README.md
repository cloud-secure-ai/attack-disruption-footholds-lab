# Attack disruption footholds lab

Companion scripts for the cloud-secure.ai post on why containment is not the same
as clean-up. After Microsoft Defender attack disruption contains a compromised
account, the attacker's footholds - a rogue MFA method, an added directory role,
an app client secret, a hidden inbox rule - are left behind. These scripts stage
that scenario in a lab, hunt the footholds, and remove them precisely.

By Sean O'Farrell - https://cloud-secure.ai/

> Adversary emulation for defensive testing. Run only in an isolated test tenant
> you own. Do not run against production or any tenant you do not control.

## Scripts

| Script | Purpose |
|--------|---------|
| `Get-AttackerFootholds.ps1` | Read-only hunt. Enumerates MFA methods, directory roles, app secrets and inbox rules, reading through Microsoft Graph so hidden and temporary methods are surfaced. |
| `Remove-AttackerFootholds.ps1` | Removes a named foothold by its own ID, leaving the user's legitimate methods intact. Supports `-WhatIf` and verifies each removal. |
| `Invoke-CredentialTheftSim.ps1` | Thin wrapper that runs the public MITRE ATT&CK T1003 atomic test on a lab VM, to generate the on-device credential-theft signal. |

This repository is deliberately defensive. The script that plants the footholds
is not included - the post describes the planting steps in prose so the lab can be
reproduced, but the published tooling is limited to detection, hunting and removal.
Planting the footholds requires privileged access in any case, so the script would
add nothing an attacker with that access does not already have.

## Prerequisites

- Windows PowerShell 5.1 or PowerShell 7
- The Microsoft Graph sub-modules and Exchange Online module:

```powershell
Install-Module Microsoft.Graph.Authentication      -Scope CurrentUser
Install-Module Microsoft.Graph.Users               -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns    -Scope CurrentUser
Install-Module Microsoft.Graph.Applications        -Scope CurrentUser
Install-Module ExchangeOnlineManagement            -Scope CurrentUser
```

Each script checks for the modules it needs and tells you what to install if any
are missing. `Invoke-CredentialTheftSim.ps1` additionally needs the
`Invoke-AtomicRedTeam` module and the Atomic Red Team atomics folder.

Sign in to Microsoft Graph and Exchange Online as an administrator when prompted.

## Typical run order

```powershell
# 1. Baseline - what does the account look like before the attack?
.\Get-AttackerFootholds.ps1 -User victim@contoso.com -AppObjectId <app-object-id>

# 2. Plant the footholds (lab only)
.\Invoke-FootholdPlanting.ps1 -VictimUser victim@contoso.com `
    -RoleName "Helpdesk Administrator" -AppObjectId <app-object-id>

# 3. Hunt - confirm the footholds are present, note their IDs
.\Get-AttackerFootholds.ps1 -User victim@contoso.com -AppObjectId <app-object-id>

# 4. Remove each foothold by the IDs from step 3
.\Remove-AttackerFootholds.ps1 -User victim@contoso.com `
    -MfaMethodId <id> -RoleAssignmentId <id> `
    -AppObjectId <app-object-id> -SecretKeyId <id> `
    -InboxRuleName "System Mail Filter"

# 5. Verify clean
.\Get-AttackerFootholds.ps1 -User victim@contoso.com -AppObjectId <app-object-id>
```

Use `-WhatIf` on the planting and removal scripts to preview changes without
making them.

## Conventions

- Parameterised throughout - no tenant-specific identifiers are hard-coded.
- Removal is by explicit ID, so only what the attacker added is removed.
- Scripts are ASCII-encoded for portability across editors and PowerShell editions.
