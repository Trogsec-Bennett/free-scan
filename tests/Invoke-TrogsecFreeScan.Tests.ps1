#Requires -Modules @{ ModuleName = 'Pester'; RequiredVersion = '5.7.1' }

BeforeAll {
    # Stand-ins for Microsoft.Graph.Authentication and Maester, so the tests need neither module nor a tenant.
    function global:Connect-MgGraph { param([string[]] $Scopes, [string] $ContextScope, [switch] $NoWelcome, [string] $TenantId, [switch] $UseDeviceCode) }
    function global:Get-MgContext { }
    function global:Disconnect-MgGraph { }
    function global:Invoke-MgGraphRequest { param([string] $Method, [string] $Uri) }
    function global:Invoke-Maester {
        param([string] $Path, [string] $OutputFolder, [string] $OutputFolderFileName, [string[]] $ExcludeTag, [switch] $SkipGraphConnect,
            [switch] $DisableTelemetry, [switch] $SkipVersionCheck, [switch] $NonInteractive, [switch] $NoLogo, [switch] $PassThru, [string] $RedactUserIdentity)
    }

    $script:ScriptUnderTest = Join-Path $PSScriptRoot '..' 'src' 'Invoke-TrogsecFreeScan.ps1'
    . $script:ScriptUnderTest

    $script:ExpectedScopes = @(
        'AuditLog.Read.All', 'Directory.Read.All', 'DirectoryRecommendations.Read.All', 'EntitlementManagement.Read.All',
        'IdentityRiskEvent.Read.All', 'OnPremDirectorySynchronization.Read.All', 'Policy.Read.All', 'Policy.Read.ConditionalAccess',
        'Reports.Read.All', 'RoleEligibilitySchedule.Read.Directory', 'RoleManagement.Read.All', 'RoleManagementAlert.Read.Directory',
        'UserAuthenticationMethod.Read.All'
    )

    function New-FakeMaesterTests {
        param([string] $Root)
        $files = @(
            'maester-config.json'
            'Maester/Entra/Test-ConditionalAccessBaseline.Tests.ps1'
            'Maester/Entra/Test-PrivilegedAssignments.Tests.ps1'
            'Maester/Entra/Test-MtDomainsDmarcRecordMaturity.Tests.ps1'
            'Maester/Exchange/Test-MtExo.Tests.ps1'
            'Maester/Intune/Test-MtIntunePlatform.Tests.ps1'
            'EIDSCA/Test-EIDSCA.Generated.Tests.ps1'
            'cisa/entra/Test-MtCisaMfa.Tests.ps1'
            'cisa/exchange/Test-MtCisaDkim.Tests.ps1'
            'cisa/spo/Test-MtCisaSpoSharing.Tests.ps1'
            'orca/Test-ORCA100.Tests.ps1'
            'cis/Test-MtCisDkim.Tests.ps1'
            'cis/Test-MtCisFormsPhishingProtectionEnabled.Tests.ps1'
        ) + @($script:Suites.Where({ $_.Path -eq 'cis' })[0].Include | ForEach-Object { "cis/$_" })
        foreach ($f in $files) {
            $p = Join-Path $Root $f
            New-Item -ItemType Directory -Path (Split-Path $p) -Force | Out-Null
            Set-Content -LiteralPath $p -Value '# test'
        }
    }
}

Describe 'Pinned configuration' {
    It 'requests exactly the 13 agreed read-only Graph scopes' {
        @($script:GraphScopes | Sort-Object) | Should -Be @($script:ExpectedScopes | Sort-Object)
    }

    It 'does not request ThreatHunting.Read.All' {
        $script:GraphScopes | Should -Not -Contain 'ThreatHunting.Read.All'
    }

    It 'requests only read-only scopes' {
        $script:GraphScopes | ForEach-Object { Test-ReadOnlyScope -Scope $_ | Should -BeTrue -Because $_ }
    }

    It 'pins <Name> to <Version>' -ForEach @(
        @{ Name = 'Maester'; Version = '2.3.0' }
        @{ Name = 'Microsoft.Graph.Authentication'; Version = '2.41.2' }
        @{ Name = 'Pester'; Version = '5.7.1' }
    ) {
        $script:PinnedModules.Where({ $_.Name -eq $Name })[0].Version | Should -BeExactly $Version
    }

    It 'requires PowerShell 7.4 or later' {
        $script:MinimumPowerShellVersion | Should -Be ([version] '7.4')
    }
}

Describe 'Test-ReadOnlyScope' {
    It 'accepts <Scope>' -ForEach @(
        @{ Scope = 'Directory.Read.All' }
        @{ Scope = 'Policy.Read.ConditionalAccess' }
        @{ Scope = 'RoleEligibilitySchedule.Read.Directory' }
        @{ Scope = 'User.Read' }
        @{ Scope = 'User.ReadBasic.All' }
        @{ Scope = 'openid' }
        @{ Scope = 'offline_access' }
    ) {
        Test-ReadOnlyScope -Scope $Scope | Should -BeTrue
    }

    It 'rejects <Scope>' -ForEach @(
        @{ Scope = 'Directory.ReadWrite.All' }
        @{ Scope = 'ReportSettings.ReadWrite.All' }
        @{ Scope = 'DelegatedPermissionGrant.ReadWrite.All' }
        @{ Scope = 'Mail.Send' }
        @{ Scope = 'ChannelMessage.Send' }
        @{ Scope = 'Directory.AccessAsUser.All' }
        @{ Scope = 'Application.ReadWrite.OwnedBy' }
        @{ Scope = 'User.Invite.All' }
    ) {
        Test-ReadOnlyScope -Scope $Scope | Should -BeFalse
    }

    It 'stops when any scope in a list is not read-only' {
        { Assert-ReadOnlyScope -Scopes @('Directory.Read.All', 'Mail.Send') -Context 'test' } | Should -Throw '*Mail.Send*'
    }
}

Describe 'Assert-PowerShellVersion' {
    It 'accepts PowerShell <Version> (<Edition>)' -ForEach @(
        @{ Version = '7.4.0'; Edition = 'Core' }
        @{ Version = '7.6.7'; Edition = 'Core' }
    ) {
        { Assert-PowerShellVersion -Version $Version -Edition $Edition } | Should -Not -Throw
    }

    It 'rejects PowerShell <Version> (<Edition>)' -ForEach @(
        @{ Version = '7.3.12'; Edition = 'Core' }
        @{ Version = '5.1.22621'; Edition = 'Desktop' }
    ) {
        { Assert-PowerShellVersion -Version $Version -Edition $Edition } | Should -Throw '*7.4*'
    }
}

Describe 'Initialize-PinnedModule' {
    BeforeEach {
        $script:LogLines = [System.Collections.Generic.List[string]]::new()
        $module = [pscustomobject]@{ Name = 'Maester'; Version = '2.3.0'; SkipPublisherCheck = $false }
        Mock Install-Module { }
        Mock Import-Module { }
        Mock Write-Host { }
    }

    It 'installs the exact pinned version from the PowerShell Gallery when it is missing' {
        Mock Get-Module -ParameterFilter { $ListAvailable } { }
        Mock Get-Module -ParameterFilter { -not $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.3.0' } }

        Initialize-PinnedModule -Module $module

        Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'Maester' -and $RequiredVersion -eq '2.3.0' -and $Repository -eq 'PSGallery' -and $Scope -eq 'CurrentUser'
        }
        Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'Maester' -and $RequiredVersion -eq '2.3.0' }
    }

    It 'does not install when the pinned version is already present' {
        Mock Get-Module -ParameterFilter { $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.3.0' } }
        Mock Get-Module -ParameterFilter { -not $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.3.0' } }

        Initialize-PinnedModule -Module $module

        Should -Invoke Install-Module -Times 0 -Exactly
    }

    It 'installs the pinned version even when a different version is present' {
        Mock Get-Module -ParameterFilter { $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.4.0' } }
        Mock Get-Module -ParameterFilter { -not $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.3.0' } }

        Initialize-PinnedModule -Module $module

        Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter { $RequiredVersion -eq '2.3.0' }
    }

    It 'stops when a different version ends up loaded' {
        Mock Get-Module -ParameterFilter { $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.3.0' } }
        Mock Get-Module -ParameterFilter { -not $ListAvailable } { [pscustomobject]@{ Name = 'Maester'; Version = [version] '2.4.0' } }

        { Initialize-PinnedModule -Module $module } | Should -Throw '*Expected Maester 2.3.0*'
    }
}

Describe 'Copy-ScanTest' {
    BeforeEach {
        $source = Join-Path $TestDrive ('src-' + [guid]::NewGuid().ToString('N'))
        $dest = Join-Path $TestDrive ('dst-' + [guid]::NewGuid().ToString('N'))
        New-FakeMaesterTests -Root $source
    }

    It 'copies only the agreed identity suites' {
        $count = Copy-ScanTest -SourceRoot $source -Destination $dest
        $copied = @(Get-ChildItem $dest -Recurse -File -Filter '*.Tests.ps1' | ForEach-Object { [System.IO.Path]::GetRelativePath($dest, $_.FullName) -replace '\\', '/' } | Sort-Object)
        $expected = @(
            'Maester/Entra/Test-ConditionalAccessBaseline.Tests.ps1'
            'Maester/Entra/Test-PrivilegedAssignments.Tests.ps1'
            'EIDSCA/Test-EIDSCA.Generated.Tests.ps1'
            'cisa/entra/Test-MtCisaMfa.Tests.ps1'
        ) + @($script:Suites.Where({ $_.Path -eq 'cis' })[0].Include | ForEach-Object { "cis/$_" })
        $copied | Should -Be @($expected | Sort-Object)
        $count | Should -Be $expected.Count
    }

    It 'leaves out the DMARC test, which makes public DNS lookups' {
        Copy-ScanTest -SourceRoot $source -Destination $dest | Out-Null
        Join-Path $dest 'Maester/Entra/Test-MtDomainsDmarcRecordMaturity.Tests.ps1' | Should -Not -Exist
    }

    It 'copies no Exchange, SharePoint, ORCA or Intune tests' {
        Copy-ScanTest -SourceRoot $source -Destination $dest | Out-Null
        foreach ($p in 'Maester/Exchange', 'Maester/Intune', 'cisa/exchange', 'cisa/spo', 'orca') {
            Join-Path $dest $p | Should -Not -Exist
        }
    }

    It 'copies maester-config.json to the staging root' {
        Copy-ScanTest -SourceRoot $source -Destination $dest | Out-Null
        Join-Path $dest 'maester-config.json' | Should -Exist
    }

    It 'stops when an expected CIS test file is missing' {
        Remove-Item (Join-Path $source 'cis/Test-MtCisGlobalAdminCount.Tests.ps1')
        { Copy-ScanTest -SourceRoot $source -Destination $dest } | Should -Throw '*Test-MtCisGlobalAdminCount*'
    }

    It 'stops when a suite folder is missing' {
        Remove-Item (Join-Path $source 'EIDSCA') -Recurse
        { Copy-ScanTest -SourceRoot $source -Destination $dest } | Should -Throw "*'EIDSCA'*"
    }
}

Describe 'Get-OutputFolderName' {
    It 'names the folder for the tenant and UTC start time' {
        Get-OutputFolderName -TenantLabel 'contoso.onmicrosoft.com' -StartUtc ([datetime]::new(2026, 11, 2, 21, 5, 9, [DateTimeKind]::Utc)) |
            Should -BeExactly 'TrogSec-FreeScan-contoso.onmicrosoft.com-20261102-210509'
    }

    It 'strips characters that are unsafe in a folder name' {
        Get-OutputFolderName -TenantLabel 'a/b\c:d' -StartUtc ([datetime]::new(2026, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) |
            Should -BeExactly 'TrogSec-FreeScan-a-b-c-d-20260101-000000'
    }
}

Describe 'Invoke-TrogsecFreeScan' {
    BeforeEach {
        $out = Join-Path $TestDrive ('out-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $out | Out-Null
        $maesterBase = Join-Path $TestDrive ('maester-' + [guid]::NewGuid().ToString('N'))
        New-FakeMaesterTests -Root (Join-Path $maesterBase 'maester-tests')
        $script:StagingSeen = $null
        $script:GrantedScopes = @($script:ExpectedScopes + 'openid', 'profile', 'User.Read')

        Mock Initialize-PinnedModule { }
        Mock Get-Module -ParameterFilter { $Name -eq 'Maester' } { [pscustomobject]@{ Name = 'Maester'; ModuleBase = $maesterBase } }
        Mock Connect-MgGraph { }
        Mock Disconnect-MgGraph { }
        Mock Get-MgContext { [pscustomobject]@{ TenantId = '00000000-0000-0000-0000-000000000001'; Scopes = $script:GrantedScopes } }
        Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*/organization*' } {
            @{ value = @(@{ displayName = 'Red Herring Fishing'; verifiedDomains = @(@{ name = 'redherring.onmicrosoft.com'; isInitial = $true }, @{ name = 'redherringfishing.com'; isInitial = $false }) }) }
        }
        Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*/servicePrincipals*' } { @{ id = 'sp-1' } }
        Mock Invoke-MgGraphRequest -ParameterFilter { $Uri -like '*/oauth2PermissionGrants*' } {
            @{ value = @(@{ consentType = 'AllPrincipals'; scope = ' Directory.Read.All Policy.Read.All ' }) }
        }
        Mock Invoke-Maester {
            $script:StagingSeen = $Path
            [pscustomobject]@{ TotalCount = 10; PassedCount = 5; FailedCount = 2; InvestigateCount = 1; SkippedCount = 1; ErrorCount = 1; NotRunCount = 0 }
        }
        Mock Invoke-RestMethod { throw 'unexpected network call' }
        Mock Invoke-WebRequest { throw 'unexpected network call' }
        Mock Write-Host { }
        Mock Write-Warning { }
    }

    It 'signs in with exactly the pinned scopes, in process scope only' {
        Invoke-TrogsecFreeScan -OutputPath $out | Out-Null
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            (Compare-Object @($Scopes) $script:ExpectedScopes) -eq $null -and $ContextScope -eq 'Process'
        }
    }

    It 'passes the tenant and device-code options through' {
        Invoke-TrogsecFreeScan -OutputPath $out -TenantId 'contoso.com' -UseDeviceCode | Out-Null
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $TenantId -eq 'contoso.com' -and $UseDeviceCode }
    }

    It 'always runs Maester with telemetry and the version check off, using the existing sign-in' {
        Invoke-TrogsecFreeScan -OutputPath $out | Out-Null
        Should -Invoke Invoke-Maester -Times 1 -Exactly -ParameterFilter {
            $DisableTelemetry -and $SkipVersionCheck -and $SkipGraphConnect -and $NonInteractive -and $PassThru -and
            $OutputFolderFileName -eq 'TestResults' -and $RedactUserIdentity -eq 'None' -and
            ($ExcludeTag -contains 'Preview') -and ($ExcludeTag -contains 'LongRunning')
        }
    }

    It 'asks Maester to redact every output when -Redact is used' {
        Invoke-TrogsecFreeScan -OutputPath $out -Redact | Out-Null
        Should -Invoke Invoke-Maester -Times 1 -Exactly -ParameterFilter { $RedactUserIdentity -eq 'AllOutputs' }
    }

    It 'stops before running any test when the sign-in carries a write permission' {
        $script:GrantedScopes = @($script:ExpectedScopes + 'Directory.ReadWrite.All')
        { Invoke-TrogsecFreeScan -OutputPath $out } | Should -Throw '*Directory.ReadWrite.All*'
        Should -Invoke Invoke-Maester -Times 0 -Exactly
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
    }

    It 'disconnects from Microsoft Graph after a successful scan' {
        Invoke-TrogsecFreeScan -OutputPath $out | Out-Null
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
    }

    It 'disconnects and keeps a log when Maester fails' {
        Mock Invoke-Maester { throw 'Maester broke' }
        { Invoke-TrogsecFreeScan -OutputPath $out } | Should -Throw '*Maester broke*'
        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
        $log = Get-ChildItem $out -Recurse -Filter 'scan-log.txt'
        $log | Should -Not -BeNullOrEmpty
        Get-Content $log.FullName -Raw | Should -Match 'Maester broke'
    }

    It 'makes no web requests of its own' {
        Invoke-TrogsecFreeScan -OutputPath $out | Out-Null
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'removes the staging copy of the tests' {
        Invoke-TrogsecFreeScan -OutputPath $out | Out-Null
        $script:StagingSeen | Should -Not -BeNullOrEmpty
        $script:StagingSeen | Should -Not -Exist
    }

    It 'writes one output folder named for the initial domain' {
        $result = Invoke-TrogsecFreeScan -OutputPath $out
        @(Get-ChildItem $out -Directory).Count | Should -Be 1
        Split-Path $result.OutputFolder -Leaf | Should -Match '^TrogSec-FreeScan-redherring\.onmicrosoft\.com-\d{8}-\d{6}$'
        foreach ($f in 'README.txt', 'scan-manifest.json', 'scan-log.txt') {
            Join-Path $result.OutputFolder $f | Should -Exist
        }
        Join-Path $result.OutputFolder 'maester' | Should -Exist
    }

    It 'records versions, scopes, consent and counts in the manifest' {
        $result = Invoke-TrogsecFreeScan -OutputPath $out
        $m = Get-Content (Join-Path $result.OutputFolder 'scan-manifest.json') -Raw | ConvertFrom-Json
        $m.scan.version | Should -Be $script:ScanVersion
        $m.scan.sha256 | Should -Match '^[0-9A-F]{64}$'
        $m.maester.version | Should -Be '2.3.0'
        $m.maester.licence | Should -Be 'MIT'
        @($m.scopesRequested) | Should -Be $script:GraphScopes
        @($m.scopesGranted) | Should -Contain 'Directory.Read.All'
        $m.graphCliConsent[0].consentType | Should -Be 'AllPrincipals'
        @($m.graphCliConsent[0].scopes) | Should -Be @('Directory.Read.All', 'Policy.Read.All')
        $m.tenant.initialDomain | Should -Be 'redherring.onmicrosoft.com'
        $m.counts.failed | Should -Be 2
        $m.counts.skipped | Should -Be 1
        $m.redacted | Should -BeFalse
    }

    It 'writes its own files as UTF-8 without BOM and with LF line endings' {
        $result = Invoke-TrogsecFreeScan -OutputPath $out
        foreach ($f in 'README.txt', 'scan-manifest.json', 'scan-log.txt') {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $result.OutputFolder $f))
            ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse -Because "$f has no BOM"
            $bytes | Should -Not -Contain ([byte] 13) -Because "$f uses LF line endings"
        }
    }

    It 'warns in the README that results include identifiers' {
        $result = Invoke-TrogsecFreeScan -OutputPath $out
        Get-Content (Join-Path $result.OutputFolder 'README.txt') -Raw | Should -Match 'user principal names'
    }

    It 'tells the client which files were written and warns about identifiers' {
        Invoke-TrogsecFreeScan -OutputPath $out | Out-Null
        Should -Invoke Write-Host -ParameterFilter { "$Object" -like '*scan-manifest.json*' }
        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*user principal names*' }
    }
}

Describe 'Repository hygiene' {
    It '<_> is UTF-8 without BOM with LF line endings' -ForEach @(
        Get-ChildItem (Join-Path $PSScriptRoot '..') -Recurse -File -Include '*.ps1', '*.psd1', '*.md', '*.yml', '*.txt', '.gitattributes', '.editorconfig' |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } | ForEach-Object { $_.FullName }
    ) {
        $bytes = [System.IO.File]::ReadAllBytes($_)
        ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
        $bytes | Should -Not -Contain ([byte] 13)
    }

    It 'the scan script calls no web request cmdlets directly' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptUnderTest, [ref] $null, [ref] $null)
        $commands = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() }
        $commands | Should -Not -Contain 'Invoke-RestMethod'
        $commands | Should -Not -Contain 'Invoke-WebRequest'
        $commands | Should -Not -Contain 'Start-BitsTransfer'
    }
}
