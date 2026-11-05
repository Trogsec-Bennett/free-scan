#Requires -Modules @{ ModuleName = 'Pester'; RequiredVersion = '5.7.1' }

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'src' 'Invoke-TrogsecFreeScan.ps1')
    . (Join-Path $PSScriptRoot '..' 'tools' 'Compare-ScanResult.ps1') -Reference x -Difference y

    function New-FakeScanFolder {
        param([string] $Root, [object[]] $Tests)
        $maester = Join-Path $Root 'maester'
        New-Item -ItemType Directory -Path $maester -Force | Out-Null
        @{ Tests = $Tests } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $maester 'TestResults.json')
        return $Root
    }

    function New-FakeTest {
        param([string] $Name, [string] $Result, [string] $Id = $Name)
        [pscustomobject]@{ Id = $Id; Title = "Title of $Name"; Name = $Name; Result = $Result }
    }
}

Describe 'Compare-ScanResult' {
    BeforeEach {
        $ref = New-FakeScanFolder -Root (Join-Path $TestDrive "ref-$([guid]::NewGuid().ToString('N'))") -Tests @(
            New-FakeTest 'A' 'Passed'
            New-FakeTest 'B' 'Skipped'
            New-FakeTest 'C' 'Failed'
            New-FakeTest 'D1' 'Passed' -Id 'D'
            New-FakeTest 'D2' 'Skipped' -Id 'D'
        )
        $dif = New-FakeScanFolder -Root (Join-Path $TestDrive "dif-$([guid]::NewGuid().ToString('N'))") -Tests @(
            New-FakeTest 'A' 'Passed'
            New-FakeTest 'B' 'Failed'
            New-FakeTest 'C' 'Failed'
            New-FakeTest 'D1' 'Passed' -Id 'D'
            New-FakeTest 'D2' 'Passed' -Id 'D'
            New-FakeTest 'E' 'Investigate'
        )
        $refTests = Read-ScanResult -Folder $ref
        $difTests = Read-ScanResult -Folder $dif
    }

    It 'counts results per run' {
        $c = Get-ResultCount -Tests $refTests
        $c.Passed | Should -Be 2
        $c.Skipped | Should -Be 2
        $c.Failed | Should -Be 1
        $c.Total | Should -Be 5
    }

    It 'lists only tests whose result changed, including tests with a shared Id and tests present in one run only' {
        $changed = @(Compare-ScanResultSet -ReferenceTests $refTests -DifferenceTests $difTests)
        $changed.Count | Should -Be 3
        ($changed | Where-Object Id -eq 'B').Difference | Should -Be 'Failed'
        ($changed | Where-Object Id -eq 'D').Reference | Should -Be 'Skipped'
        ($changed | Where-Object Id -eq 'E').Reference | Should -Be '(absent)'
    }

    It 'reports nothing when the runs match' {
        @(Compare-ScanResultSet -ReferenceTests $refTests -DifferenceTests $refTests).Count | Should -Be 0
    }

    It 'stops when a folder has no results' {
        { Read-ScanResult -Folder (Join-Path $TestDrive 'missing') } | Should -Throw '*No results found*'
    }

    It 'outputs only test IDs, titles and results' {
        $json = & (Join-Path $PSScriptRoot '..' 'tools' 'Compare-ScanResult.ps1') -Reference $ref -Difference $dif -AsJson | ConvertFrom-Json
        @($json.Changed[0].PSObject.Properties.Name | Sort-Object) | Should -Be @('Difference', 'Id', 'Reference', 'Title')
        $json.Changed.Count | Should -Be 3
    }
}

Describe 'Invoke-LabFullScopeRun' {
    BeforeAll {
        $path = Join-Path $PSScriptRoot '..' 'tools' 'Invoke-LabFullScopeRun.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $null, [ref] $null)
        $assign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:GraphScopes' }, $true)
        $script:LabScopes = @($assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object Value)
    }

    It 'requests Maester''s 25 default scopes' {
        $script:LabScopes.Count | Should -Be 25
        @($script:LabScopes | Sort-Object -Unique).Count | Should -Be 25
    }

    It 'requests only read-only scopes' {
        $script:LabScopes | ForEach-Object { Test-ReadOnlyScope -Scope $_ | Should -BeTrue -Because $_ }
    }

    It 'includes every scope the scan requests' {
        $script:GraphScopes | ForEach-Object { $script:LabScopes | Should -Contain $_ }
    }
}
