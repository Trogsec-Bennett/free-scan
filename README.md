# TrogSec free discovery scan

A free, one-time scan of the identity configuration of your Microsoft Entra
tenant, from [Troglodyte Security](https://trogsec.com). You run it yourself,
signed in as your own administrator. **TrogSec is never granted access to your
tenant.** The scan writes its results to a folder on your machine; you review
them and send them to TrogSec, who turns them into a short report and a
30-minute readout.

Built on [Maester](https://maester.dev), an open-source Microsoft 365 security
test framework, which includes CISA's SCuBA baseline checks for Entra ID. See
[NOTICE.md](NOTICE.md).

## What it does

[`src/Invoke-TrogsecFreeScan.ps1`](src/Invoke-TrogsecFreeScan.ps1) is the
whole scan. In order, it:

1. Checks that you are running PowerShell 7.4 or later.
2. Installs, if they are missing, and loads these exact versions from the
   PowerShell Gallery, for the current user only:

   | Module | Version |
   | --- | --- |
   | Maester | 2.3.0 |
   | Microsoft.Graph.Authentication | 2.41.2 |
   | Pester | 5.7.1 |

3. Signs in to Microsoft Graph through Microsoft's own Graph PowerShell
   sign-in, asking only for the read-only permissions below. The sign-in is
   kept in memory for this PowerShell session and is not cached to disk.
4. Stops if the sign-in carries **any** permission that is not read-only.
5. Runs only these Maester test suites, with Maester's telemetry and update
   check turned off:
   - Maester Entra tests, including Conditional Access and Privileged Identity
     Management (except one DMARC test that would look up public DNS records)
   - EIDSCA
   - CISA SCuBA baseline for Entra ID (MS.AAD)
   - 11 identity tests from the CIS Microsoft 365 benchmark
6. Writes everything to one folder, signs out, and lists what it wrote.

It does not check Exchange Online, Teams, SharePoint or Intune.

## Permissions it asks for

All are delegated and read-only. The scan sees only what your own admin role
can see.

| Permission | Used for |
| --- | --- |
| AuditLog.Read.All | Sign-in activity for accounts named in findings |
| Directory.Read.All | Users, groups, roles and applications |
| DirectoryRecommendations.Read.All | Entra recommendations |
| EntitlementManagement.Read.All | Access packages |
| IdentityRiskEvent.Read.All | Risk-based policies |
| OnPremDirectorySynchronization.Read.All | Entra Connect settings |
| Policy.Read.All | Authentication, consent and tenant policies |
| Policy.Read.ConditionalAccess | Conditional Access policies |
| Reports.Read.All | MFA registration details |
| RoleEligibilitySchedule.Read.Directory | Privileged Identity Management eligible roles |
| RoleManagement.Read.All | Role assignments |
| RoleManagementAlert.Read.Directory | Privileged Identity Management alerts |
| UserAuthenticationMethod.Read.All | Authentication methods |

The first run in a tenant asks an administrator who can grant admin consent
(for example a Global Administrator) to consent to Microsoft's "Microsoft
Graph Command Line Tools" app for these permissions. **That consent stays in
your tenant after the scan.** You can review or remove it in the Microsoft
Entra admin center under Enterprise applications, Microsoft Graph Command
Line Tools, Permissions. The scan records the consent it found in
`scan-manifest.json` to help.

## Network use

The scan connects only to Microsoft sign-in, Microsoft Graph, and the
PowerShell Gallery (to install the pinned modules). It sends no telemetry and
**uploads nothing**.

## Running it

```powershell
# Check the file matches the hash published on trogsec.com first:
Get-FileHash .\Invoke-TrogsecFreeScan.ps1 -Algorithm SHA256

pwsh -File .\Invoke-TrogsecFreeScan.ps1
```

Options:

- `-OutputPath <folder>`: where to create the output folder (default: the
  current folder).
- `-TenantId <id or domain>`: the tenant to sign in to.
- `-UseDeviceCode`: sign in with a device code instead of a browser.
- `-Redact`: replace user names, user principal names and object IDs with
  placeholder IDs in every output file.

## What you send

```
TrogSec-FreeScan-<tenant>-<yyyyMMdd-HHmmss>/
  README.txt
  scan-manifest.json
  scan-log.txt
  maester/TestResults.json, .html, .md, -summary.md
```

The results include identifiers from your tenant, such as user principal
names, policy names and group names. Review them before you send the folder.

## Development

Tests use [Pester](https://pester.dev) 5.7.1 with Maester and Microsoft Graph
mocked, so they need no tenant:

```powershell
Invoke-Pester ./tests
```

Files are UTF-8 without BOM, with LF line endings.
