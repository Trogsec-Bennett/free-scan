#Requires -Version 7.4
<#
.SYNOPSIS
    Compares two free scan output folders test by test.

.DESCRIPTION
    Reads maester/TestResults.json from two scan output folders and prints:
      - the result counts for each run;
      - every test whose result differs between the runs.

    The output names only Maester test IDs, test titles and results. It
    contains no tenant data, so it can be shared to confirm the scope list.

.PARAMETER Reference
    The output folder of the normal scan (13 scopes).

.PARAMETER Difference
    The output folder of the comparison run (for example, 25 scopes).

.PARAMETER AsJson
    Emit the comparison as JSON instead of tables.

.EXAMPLE
    ./tools/Compare-ScanResult.ps1 -Reference .\scan-13\TrogSec-FreeScan-... -Difference .\full-25\TrogSec-FreeScan-...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Reference,
    [Parameter(Mandatory)] [string] $Difference,
    [switch] $AsJson
)

Set-StrictMode -Version 3.0

function Read-ScanResult {
    param([Parameter(Mandatory)] [string] $Folder)
    $path = Join-Path $Folder 'maester' 'TestResults.json'
    if (-not (Test-Path -LiteralPath $path)) { throw "No results found at '$path'." }
    $json = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -Depth 64
    $tests = @{}
    foreach ($t in @($json.Tests)) {
        # Id is not unique for some generated tests; the full name is.
        $tests[$t.Name] = [pscustomobject]@{ Id = $t.Id; Title = $t.Title; Result = $t.Result }
    }
    return $tests
}

function Get-ResultCount {
    param([Parameter(Mandatory)] [hashtable] $Tests)
    $counts = [ordered]@{}
    foreach ($r in 'Passed', 'Failed', 'Investigate', 'Skipped', 'Error', 'NotRun') {
        $counts[$r] = @($Tests.Values | Where-Object { $_.Result -eq $r }).Count
    }
    $counts['Total'] = $Tests.Count
    return [pscustomobject]$counts
}

function Compare-ScanResultSet {
    param([Parameter(Mandatory)] [hashtable] $ReferenceTests, [Parameter(Mandatory)] [hashtable] $DifferenceTests)
    $names = @($ReferenceTests.Keys) + @($DifferenceTests.Keys) | Sort-Object -Unique
    foreach ($name in $names) {
        $ref = $ReferenceTests[$name]
        $dif = $DifferenceTests[$name]
        $refResult = if ($ref) { $ref.Result } else { '(absent)' }
        $difResult = if ($dif) { $dif.Result } else { '(absent)' }
        if ($refResult -ne $difResult) {
            $any = if ($ref) { $ref } else { $dif }
            [pscustomobject]@{ Id = $any.Id; Title = $any.Title; Reference = $refResult; Difference = $difResult }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $refTests = Read-ScanResult -Folder $Reference
    $difTests = Read-ScanResult -Folder $Difference
    $comparison = [ordered]@{
        ReferenceCounts  = Get-ResultCount -Tests $refTests
        DifferenceCounts = Get-ResultCount -Tests $difTests
        Changed          = @(Compare-ScanResultSet -ReferenceTests $refTests -DifferenceTests $difTests | Sort-Object Id, Title)
    }
    if ($AsJson) {
        $comparison | ConvertTo-Json -Depth 5
    } else {
        Write-Host 'Reference counts:'
        $comparison.ReferenceCounts | Format-Table -AutoSize | Out-Host
        Write-Host 'Difference counts:'
        $comparison.DifferenceCounts | Format-Table -AutoSize | Out-Host
        if ($comparison.Changed.Count -eq 0) {
            Write-Host 'Every test has the same result in both runs.'
        } else {
            Write-Host "$($comparison.Changed.Count) tests differ:"
            $comparison.Changed | Format-Table Id, Reference, Difference, Title -Wrap | Out-Host
        }
    }
}
