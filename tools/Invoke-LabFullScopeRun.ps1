#Requires -Version 7.4
<#
.SYNOPSIS
    Lab-only comparison run: the free scan with Maester's full default scope list.

.DESCRIPTION
    For TrogSec's own lab tenant only. Not part of what clients run.

    Runs src/Invoke-TrogsecFreeScan.ps1 unchanged except for the Graph scopes:
    instead of the scan's 13, it requests the 25 read-only scopes Maester 2.3.0
    asks for by default (Get-MtGraphScope with no switches). Comparing this run
    with a normal run shows whether any identity test needs a scope the scan
    does not request. All 25 are read-only, and the scan's read-only check
    still applies.

.PARAMETER OutputPath
    Where to create the output folder. Defaults to the current folder.

.PARAMETER TenantId
    The lab tenant's ID or domain.

.EXAMPLE
    ./tools/Invoke-LabFullScopeRun.ps1 -TenantId redherringfishing.com -OutputPath C:\LabRuns\full-25
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Get-Location).Path,
    [Parameter(Mandatory)] [string] $TenantId,
    [switch] $UseDeviceCode
)

$scanScript = Join-Path $PSScriptRoot '..' 'src' 'Invoke-TrogsecFreeScan.ps1'
. $scanScript

# Get-MtGraphScope default list, Maester 2.3.0.
$script:GraphScopes = @(
    'AuditLog.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementManagedDevices.Read.All'
    'DeviceManagementRBAC.Read.All'
    'DeviceManagementServiceConfig.Read.All'
    'Directory.Read.All'
    'DirectoryRecommendations.Read.All'
    'EntitlementManagement.Read.All'
    'IdentityRiskEvent.Read.All'
    'NetworkAccess.Read.All'
    'OnPremDirectorySynchronization.Read.All'
    'OrgSettings-AppsAndServices.Read.All'
    'OrgSettings-Forms.Read.All'
    'Policy.Read.All'
    'Policy.Read.ConditionalAccess'
    'Reports.Read.All'
    'ReportSettings.Read.All'
    'RoleEligibilitySchedule.Read.Directory'
    'RoleManagement.Read.All'
    'RoleManagementAlert.Read.Directory'
    'SecurityIdentitiesSensors.Read.All'
    'SecurityIdentitiesHealth.Read.All'
    'SharePointTenantSettings.Read.All'
    'ThreatHunting.Read.All'
    'UserAuthenticationMethod.Read.All'
)

Write-Warning 'Lab comparison run with Maester''s full default scope list (25 read-only scopes). For TrogSec''s lab tenant only.'
Invoke-TrogsecFreeScan -OutputPath $OutputPath -TenantId $TenantId -UseDeviceCode:$UseDeviceCode -ScriptPath $scanScript
