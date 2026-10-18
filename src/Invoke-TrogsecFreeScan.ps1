#Requires -Version 7.4
<#
.SYNOPSIS
    TrogSec free discovery scan: runs a fixed, read-only set of Maester identity
    tests in your own Microsoft Entra tenant and writes the results to one folder.

.DESCRIPTION
    This script is run by you, signed in as your own administrator. Troglodyte
    Security (TrogSec) is never granted access to your tenant.

    What it does, in order:
      1. Checks that PowerShell is 7.4 or later.
      2. Installs (if missing) and loads exact, pinned versions of Maester,
         Microsoft.Graph.Authentication and Pester from the PowerShell Gallery.
      3. Signs in to Microsoft Graph through Microsoft's own Graph PowerShell
         sign-in, asking only for the read-only permissions listed in
         $script:GraphScopes below. It stops if the sign-in carries any
         permission that is not read-only.
      4. Runs only the identity test suites listed in $script:Suites below,
         with Maester's telemetry and update check turned off.
      5. Writes everything to one output folder and prints what is in it.

    The script uploads nothing. Its only network calls are Microsoft sign-in,
    Microsoft Graph, and the PowerShell Gallery (to install the pinned modules).
    You review the output folder and send it to TrogSec yourself.

    Built on Maester (https://maester.dev), an open-source Microsoft 365
    security test framework published under the MIT licence.

.PARAMETER OutputPath
    The folder in which the scan's output folder is created. Defaults to the
    current folder.

.PARAMETER TenantId
    Optional tenant ID or primary domain to sign in to.

.PARAMETER UseDeviceCode
    Sign in with a device code instead of a browser window.

.PARAMETER Redact
    Replace user names, user principal names and object IDs in every output
    file with stable placeholder IDs. Findings stay countable but name no one.

.EXAMPLE
    ./Invoke-TrogsecFreeScan.ps1

.EXAMPLE
    ./Invoke-TrogsecFreeScan.ps1 -Redact -OutputPath C:\Temp
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Get-Location).Path,
    [string] $TenantId,
    [switch] $UseDeviceCode,
    [switch] $Redact
)

Set-StrictMode -Version 3.0

$script:ScanVersion = '0.1.0'

$script:MinimumPowerShellVersion = [version] '7.4'

# Exact versions. The scan never uses "latest".
$script:PinnedModules = @(
    [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = '2.41.2'; SkipPublisherCheck = $false }
    [pscustomobject]@{ Name = 'Pester'; Version = '5.7.1'; SkipPublisherCheck = $true }
    [pscustomobject]@{ Name = 'Maester'; Version = '2.3.0'; SkipPublisherCheck = $false }
)

# Delegated, read-only Microsoft Graph permissions. Nothing else is requested.
$script:GraphScopes = @(
    'AuditLog.Read.All'
    'Directory.Read.All'
    'DirectoryRecommendations.Read.All'
    'EntitlementManagement.Read.All'
    'IdentityRiskEvent.Read.All'
    'OnPremDirectorySynchronization.Read.All'
    'Policy.Read.All'
    'Policy.Read.ConditionalAccess'
    'Reports.Read.All'
    'RoleEligibilitySchedule.Read.Directory'
    'RoleManagement.Read.All'
    'RoleManagementAlert.Read.Directory'
    'UserAuthenticationMethod.Read.All'
)

# Sign-in scopes that carry no data access.
$script:OpenIdScopes = @('openid', 'profile', 'offline_access', 'email')

# Microsoft Graph Command Line Tools, the Microsoft app Graph PowerShell signs in through.
$script:GraphCliAppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

# Test folders and files copied from Maester's bundled tests. Nothing else runs.
$script:Suites = @(
    [pscustomobject]@{ Name = 'Maester Entra (incl. Conditional Access and PIM)'; Path = 'Maester/Entra'; Include = @(); Exclude = @(
            # Looks up public DNS records, a network call outside Microsoft Graph.
            'Test-MtDomainsDmarcRecordMaturity.Tests.ps1'
        )
    }
    [pscustomobject]@{ Name = 'EIDSCA'; Path = 'EIDSCA'; Include = @(); Exclude = @() }
    [pscustomobject]@{ Name = 'CISA SCuBA Entra ID (MS.AAD)'; Path = 'cisa/entra'; Include = @(); Exclude = @() }
    [pscustomobject]@{ Name = 'CIS Microsoft 365 (Graph-only identity tests)'; Path = 'cis'; Exclude = @(); Include = @(
            'Test-MtCis365PublicGroup.Tests.ps1'
            'Test-MtCisAdminConsentWorkflowEnabled.Tests.ps1'
            'Test-MtCisCloudAdmin.Tests.ps1'
            'Test-MtCisCreateTenantDisallowed.Tests.ps1'
            'Test-MtCisEnsureBitLockerKeyRecoveryRestricted.Tests.ps1'
            'Test-MtCisEnsureGuestAccessRestricted.Tests.ps1'
            'Test-MtCisEnsureUserConsentToAppsDisallowed.Tests.ps1'
            'Test-MtCisGlobalAdminCount.Tests.ps1'
            'Test-MtCisPasswordExpiry.Tests.ps1'
            'Test-MtCisThirdPartyApplicationsDisallowed.Tests.ps1'
            'Test-MtCisWeakAuthenticationMethodsDisabled.Tests.ps1'
        )
    }
)

$script:ExcludedTags = @('Preview', 'LongRunning')

function Write-ScanLog {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('Info', 'Warning', 'Error')] [string] $Level = 'Info'
    )
    $line = '{0:yyyy-MM-ddTHH:mm:ssZ} [{1}] {2}' -f [datetime]::UtcNow, $Level.ToUpperInvariant(), $Message
    $script:LogLines.Add($line)
    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Host $Message -ForegroundColor Red }
        default { Write-Host $Message }
    }
}

function Assert-PowerShellVersion {
    param([version] $Version = $PSVersionTable.PSVersion, [string] $Edition = $PSVersionTable.PSEdition)
    if ($Edition -ne 'Core' -or $Version -lt $script:MinimumPowerShellVersion) {
        throw "This scan needs PowerShell $($script:MinimumPowerShellVersion) or later (you are running $Edition $Version). Install PowerShell 7 from https://aka.ms/powershell, then run the scan from 'pwsh'."
    }
}

function Test-ReadOnlyScope {
    <# Returns $true only for a Graph permission that is read-only, or a sign-in scope with no data access. #>
    param([Parameter(Mandatory)] [string] $Scope)
    if ($script:OpenIdScopes -contains $Scope) { return $true }
    $segments = $Scope.Split('.')
    if ($segments | Where-Object { $_ -match 'Write' }) { return $false }
    return [bool] ($segments | Where-Object { $_ -in @('Read', 'ReadBasic') })
}

function Assert-ReadOnlyScope {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Scopes, [Parameter(Mandatory)] [string] $Context)
    $notReadOnly = @($Scopes | Where-Object { -not (Test-ReadOnlyScope -Scope $_) })
    if ($notReadOnly.Count -gt 0) {
        throw "Stopped: $Context includes permissions that are not read-only: $($notReadOnly -join ', '). The scan only runs with read-only access."
    }
}

function Initialize-PinnedModule {
    param([Parameter(Mandatory)] [pscustomobject] $Module)
    $installed = Get-Module -ListAvailable -Name $Module.Name | Where-Object { $_.Version -eq [version] $Module.Version }
    if (-not $installed) {
        Write-ScanLog "Installing $($Module.Name) $($Module.Version) from the PowerShell Gallery for the current user."
        $installParams = @{
            Name            = $Module.Name
            RequiredVersion = $Module.Version
            Repository      = 'PSGallery'
            Scope           = 'CurrentUser'
            Force           = $true
            AllowClobber    = $true
            ErrorAction     = 'Stop'
        }
        if ($Module.SkipPublisherCheck) { $installParams.SkipPublisherCheck = $true }
        Install-Module @installParams
    }
    Import-Module -Name $Module.Name -RequiredVersion $Module.Version -Force -ErrorAction Stop
    $loaded = @(Get-Module -Name $Module.Name)
    if ($loaded.Count -ne 1 -or $loaded[0].Version -ne [version] $Module.Version) {
        throw "Expected $($Module.Name) $($Module.Version) to be loaded, found: $(($loaded | ForEach-Object { $_.Version }) -join ', '). Close PowerShell, open a new 'pwsh' window and run the scan again."
    }
    Write-ScanLog "Loaded $($Module.Name) $($Module.Version)."
}

function Copy-ScanTest {
    <# Copies only the agreed suites from Maester's bundled tests into a staging folder. Returns the file count. #>
    param([Parameter(Mandatory)] [string] $SourceRoot, [Parameter(Mandatory)] [string] $Destination)
    if (-not (Test-Path -LiteralPath $SourceRoot -PathType Container)) {
        throw "Maester's bundled tests were not found at '$SourceRoot'."
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $config = Join-Path $SourceRoot 'maester-config.json'
    if (Test-Path -LiteralPath $config) { Copy-Item -LiteralPath $config -Destination $Destination }

    $count = 0
    foreach ($suite in $script:Suites) {
        $from = Join-Path $SourceRoot $suite.Path
        if (-not (Test-Path -LiteralPath $from -PathType Container)) {
            throw "Maester test folder '$($suite.Path)' was not found. The installed Maester version may not match the pinned one."
        }
        $to = Join-Path $Destination $suite.Path
        New-Item -ItemType Directory -Path $to -Force | Out-Null
        $files = Get-ChildItem -LiteralPath $from -Filter '*.Tests.ps1' -File
        if ($suite.Include.Count -gt 0) {
            $missing = @($suite.Include | Where-Object { $_ -notin $files.Name })
            if ($missing.Count -gt 0) { throw "Expected Maester test files are missing from '$($suite.Path)': $($missing -join ', ')." }
            $files = $files | Where-Object { $_.Name -in $suite.Include }
        }
        $files = @($files | Where-Object { $_.Name -notin $suite.Exclude })
        foreach ($file in $files) {
            Copy-Item -LiteralPath $file.FullName -Destination $to
            $count++
        }
    }
    return $count
}

function Get-GraphCliConsent {
    <# Records the scopes granted to Microsoft Graph Command Line Tools in this tenant, so you can review or remove them later. #>
    try {
        $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$($script:GraphCliAppId)')?`$select=id" -ErrorAction Stop
        $grants = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)'&`$select=consentType,scope" -ErrorAction Stop
        return @($grants.value | ForEach-Object {
                [ordered]@{
                    consentType = $_.consentType
                    scopes      = @($_.scope -split ' ' | Where-Object { $_ } | Sort-Object)
                }
            })
    } catch {
        Write-ScanLog "Could not read the Graph Command Line Tools consent record: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-OutputFolderName {
    param([Parameter(Mandatory)] [string] $TenantLabel, [Parameter(Mandatory)] [datetime] $StartUtc)
    $safe = ($TenantLabel -replace '[^A-Za-z0-9.-]', '-').Trim('-')
    if (-not $safe) { $safe = 'tenant' }
    return 'TrogSec-FreeScan-{0}-{1:yyyyMMdd-HHmmss}' -f $safe, $StartUtc
}

function Write-Utf8File {
    <# UTF-8 without BOM, LF line endings. #>
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Content)
    $text = ($Content -replace "`r`n", "`n")
    if (-not $text.EndsWith("`n")) { $text += "`n" }
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($false))
}

function Get-ReadmeText {
    param([Parameter(Mandatory)] [bool] $Redacted)
    $identifiers = if ($Redacted) {
        'You ran the scan with -Redact, so user names, user principal names and object IDs are replaced with placeholder IDs. Policy names, group names, application names and domain names still appear.'
    } else {
        'The results include identifiers from your tenant: user principal names, display names, object IDs, policy names, group names, application names and domain names. Run the scan again with -Redact if you want user identities replaced with placeholder IDs.'
    }
    return @"
TrogSec free discovery scan: output folder
==========================================

This folder was written by Invoke-TrogsecFreeScan.ps1 on your machine.
Nothing was uploaded. TrogSec had no access to your tenant.

Files
-----
README.txt                     This file.
scan-manifest.json             Script version and SHA-256 hash, module versions,
                               PowerShell version, permissions requested and
                               granted, suites run, start and end time (UTC),
                               tenant ID, and the Graph Command Line Tools
                               consent recorded after sign-in.
scan-log.txt                   The scan's own log of what it did.
maester/TestResults.json       Full results; TrogSec builds your report from it.
maester/TestResults.html       The same results as a page you can open and read.
maester/TestResults.md         The same results as Markdown.
maester/TestResults-summary.md A short summary.

Before you send
---------------
$identifiers

Review the files, then send the whole folder to TrogSec using the upload link
or encrypted email TrogSec gave you.

About the sign-in
-----------------
Signing in may have asked an administrator to consent to Microsoft's
"Microsoft Graph Command Line Tools" app. That consent stays in your tenant
after the scan. TrogSec's client instructions explain how to review or
remove it.

Built on Maester (https://maester.dev), an open-source Microsoft 365 security
test framework published under the MIT licence.
"@
}

function Invoke-TrogsecFreeScan {
    [CmdletBinding()]
    param(
        [string] $OutputPath = (Get-Location).Path,
        [string] $TenantId,
        [switch] $UseDeviceCode,
        [switch] $Redact,
        [string] $ScriptPath = $PSCommandPath
    )

    $script:LogLines = [System.Collections.Generic.List[string]]::new()
    $startUtc = [datetime]::UtcNow
    $staging = $null
    $folder = $null
    $connected = $false

    try {
        Write-ScanLog "TrogSec free discovery scan $($script:ScanVersion). Built on Maester (https://maester.dev, MIT licence)."
        Assert-PowerShellVersion

        # Checked before anything is installed or any sign-in happens.
        Assert-ReadOnlyScope -Scopes $script:GraphScopes -Context 'the permission list in this script'

        $scriptHash = if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) { (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash } else { $null }

        foreach ($module in $script:PinnedModules) { Initialize-PinnedModule -Module $module }

        $connectParams = @{
            Scopes       = $script:GraphScopes
            ContextScope = 'Process'
            NoWelcome    = $true
            ErrorAction  = 'Stop'
        }
        if ($TenantId) { $connectParams.TenantId = $TenantId }
        if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }
        Write-ScanLog 'Signing in to Microsoft Graph with read-only permissions.'
        Connect-MgGraph @connectParams
        $connected = $true

        $context = Get-MgContext
        if (-not $context) { throw 'Sign-in did not complete.' }
        $granted = @($context.Scopes | Sort-Object)
        # A sign-in can carry permissions consented earlier for the same Microsoft app; any that are not read-only stop the scan.
        Assert-ReadOnlyScope -Scopes $granted -Context 'the signed-in session'
        Write-ScanLog "Signed in to tenant $($context.TenantId) with $($granted.Count) read-only permissions."

        $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,verifiedDomains' -ErrorAction Stop
        $orgInfo = @($org.value)[0]
        $initialDomain = @($orgInfo.verifiedDomains | Where-Object { $_.isInitial })[0].name
        $tenantLabel = if ($initialDomain) { $initialDomain } else { $context.TenantId }

        $folder = Join-Path $OutputPath (Get-OutputFolderName -TenantLabel $tenantLabel -StartUtc $startUtc)
        $maesterFolder = Join-Path $folder 'maester'
        New-Item -ItemType Directory -Path $maesterFolder -Force | Out-Null
        Write-ScanLog "Writing results to $folder"

        $consent = Get-GraphCliConsent

        $maesterBase = (Get-Module -Name Maester).ModuleBase
        $staging = Join-Path ([System.IO.Path]::GetTempPath()) ('trogsec-freescan-' + [guid]::NewGuid().ToString('N'))
        $testCount = Copy-ScanTest -SourceRoot (Join-Path $maesterBase 'maester-tests') -Destination $staging
        Write-ScanLog "Running $testCount Maester test files from the agreed identity suites."

        $maesterParams = @{
            Path                 = $staging
            OutputFolder         = $maesterFolder
            OutputFolderFileName = 'TestResults'
            ExcludeTag           = $script:ExcludedTags
            SkipGraphConnect     = $true
            DisableTelemetry     = $true
            SkipVersionCheck     = $true
            NonInteractive       = $true
            NoLogo               = $true
            PassThru             = $true
            RedactUserIdentity   = if ($Redact) { 'AllOutputs' } else { 'None' }
        }
        $results = Invoke-Maester @maesterParams
        if (-not $results) { throw 'Maester returned no results.' }

        $endUtc = [datetime]::UtcNow
        $counts = [ordered]@{
            total       = $results.TotalCount
            passed      = $results.PassedCount
            failed      = $results.FailedCount
            investigate = $results.InvestigateCount
            skipped     = $results.SkippedCount
            error       = $results.ErrorCount
            notRun      = $results.NotRunCount
        }

        $manifest = [ordered]@{
            scan                = [ordered]@{ name = 'TrogSec free discovery scan'; version = $script:ScanVersion; sha256 = $scriptHash }
            maester             = [ordered]@{ version = $script:PinnedModules.Where({ $_.Name -eq 'Maester' })[0].Version; url = 'https://maester.dev'; licence = 'MIT' }
            modules             = @($script:PinnedModules | ForEach-Object { [ordered]@{ name = $_.Name; version = $_.Version } })
            powershell          = [ordered]@{ version = $PSVersionTable.PSVersion.ToString(); edition = $PSVersionTable.PSEdition; os = $PSVersionTable.OS }
            tenant              = [ordered]@{ id = $context.TenantId; initialDomain = $initialDomain; displayName = $orgInfo.displayName }
            startUtc            = $startUtc.ToString('o')
            endUtc              = $endUtc.ToString('o')
            scopesRequested     = @($script:GraphScopes)
            scopesGranted       = $granted
            graphCliConsent     = $consent
            suites              = @($script:Suites | ForEach-Object { [ordered]@{ name = $_.Name; path = $_.Path; include = @($_.Include); exclude = @($_.Exclude) } })
            excludedTags        = @($script:ExcludedTags)
            redacted            = [bool] $Redact
            counts              = $counts
        }
        Write-Utf8File -Path (Join-Path $folder 'scan-manifest.json') -Content ($manifest | ConvertTo-Json -Depth 6)
        Write-Utf8File -Path (Join-Path $folder 'README.txt') -Content (Get-ReadmeText -Redacted ([bool] $Redact))

        Write-ScanLog ('Results: {0} tests; {1} passed, {2} failed, {3} to investigate, {4} skipped, {5} errors, {6} not run.' -f `
                $counts.total, $counts.passed, $counts.failed, $counts.investigate, $counts.skipped, $counts.error, $counts.notRun)
        Write-Utf8File -Path (Join-Path $folder 'scan-log.txt') -Content ($script:LogLines -join "`n")

        Write-Host ''
        Write-Host 'Files written:'
        Get-ChildItem -LiteralPath $folder -Recurse -File | Sort-Object FullName | ForEach-Object {
            Write-Host ('  {0}  ({1:N0} bytes)' -f [System.IO.Path]::GetRelativePath($folder, $_.FullName), $_.Length)
        }
        Write-Host ''
        if ($Redact) {
            Write-Warning 'User identities are replaced with placeholder IDs, but policy, group, application and domain names still appear. Review the files before you send them.'
        } else {
            Write-Warning 'These results include identifiers from your tenant, such as user principal names and policy names. Review the files before you send them.'
        }
        Write-Host "Send the whole folder to TrogSec using the upload link or encrypted email you were given: $folder"

        return [pscustomobject]@{ OutputFolder = $folder; Counts = $counts }
    } catch {
        Write-ScanLog $_.Exception.Message -Level Error
        if ($folder -and (Test-Path -LiteralPath $folder)) {
            Write-Utf8File -Path (Join-Path $folder 'scan-log.txt') -Content ($script:LogLines -join "`n")
        }
        throw
    } finally {
        if ($connected) {
            try { Disconnect-MgGraph -ErrorAction Stop | Out-Null } catch { Write-Verbose "Disconnect-MgGraph: $($_.Exception.Message)" }
        }
        if ($staging -and (Test-Path -LiteralPath $staging)) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Run the scan unless the script is being dot-sourced (as the tests do).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-TrogsecFreeScan @PSBoundParameters | Out-Null
}
