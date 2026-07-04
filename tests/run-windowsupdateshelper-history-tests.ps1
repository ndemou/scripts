<#
.SYNOPSIS
Runs focused regression tests for WindowsUpdatesHelper history pagination.

.DESCRIPTION
Loads only the helper functions needed for Get-WindowsUpdateHistory from
WindowsUpdatesHelper.ps1 and exercises them with a fake Windows Update
searcher. This avoids touching the real Windows Update COM API during tests.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot '..\WindowsUpdatesHelper.ps1'

function Assert-True {
  param(
    [Parameter(Mandatory)][bool]$Condition,
    [Parameter(Mandatory)][string]$Message
  )

  if (-not $Condition) {
    throw $Message
  }
}

function Assert-Equal {
  param(
    [Parameter(Mandatory)]$Actual,
    [Parameter(Mandatory)]$Expected,
    [Parameter(Mandatory)][string]$Message
  )

  if ($Actual -cne $Expected) {
    throw "$Message`nExpected: $Expected`nActual:   $Actual"
  }
}

function Invoke-TestCase {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Body
  )

  Write-Host "Running $Name"
  & $Body
  Write-Host "PASS    $Name" -ForegroundColor Green
}

function Import-FunctionFromScript {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string[]]$FunctionName
  )

  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $Path),
    [ref]$tokens,
    [ref]$errors
  )
  if ($errors) {
    throw "Could not parse ${Path}: $($errors[0].Message)"
  }

  foreach ($name in $FunctionName) {
    $func = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }, $true)

    if (-not $func) {
      throw "Function not found in ${Path}: $name"
    }

    Invoke-Expression ("function script:{0} {1}" -f $name, $func.Body.Extent.Text)
  }
}

function New-HistoryEntry {
  param(
    [Parameter(Mandatory)][datetime]$Date,
    [Parameter(Mandatory)][string]$Title,
    [int]$Operation = 1,
    [int]$ResultCode = 2,
    [int]$HResult = 0
  )

  [pscustomobject]@{
    Date = $Date
    Title = $Title
    Operation = $Operation
    ResultCode = $ResultCode
    HResult = $HResult
  }
}

class FakeUpdateSearcher {
  [object[]]$History
  [object[]]$Calls

  FakeUpdateSearcher([object[]]$history) {
    $this.History = @($history)
    $this.Calls = @()
  }

  [object[]] QueryHistory([int]$start, [int]$take) {
    $this.Calls += [pscustomobject]@{ Start = $start; Take = $take }
    if ($start -ge $this.History.Count) {
      return @()
    }

    return @($this.History | Select-Object -Skip $start -First $take)
  }
}

Import-FunctionFromScript -Path $scriptPath -FunctionName @(
  'Get-DescrFromResultCode',
  'Get-DescrFromHResult',
  'Get-WindowsUpdateHistory'
)

$tests = @(
  @{
    Name = 'Continues scanning when a full page is filtered out as Defender definitions'
    Body = {
      $now = Get-Date
      $history = @()
      1..100 | ForEach-Object {
        $history += New-HistoryEntry -Date $now.AddMinutes(-1 * $_) -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'
      }
      $history += New-HistoryEntry -Date $now.AddMinutes(-101) -Title '2026-06 Cumulative Update for Windows (KB5094128)'
      $searcher = [FakeUpdateSearcher]::new($history)

      $rows = @(Get-WindowsUpdateHistory -MaxResults 30 -MaxScanEntries 200 -Searcher $searcher)

      Assert-Equal $rows.Count 1 'Expected the non-Defender entry after the first page to be returned.'
      Assert-Equal $rows[0].KB 'KB5094128' 'Unexpected KB returned after filtering a full Defender page.'
      Assert-True ($searcher.Calls.Count -ge 2) 'Expected the function to continue to the second history page.'
    }
  },
  @{
    Name = 'IncludeAV keeps Defender definition entries'
    Body = {
      $now = Get-Date
      $history = @(
        (New-HistoryEntry -Date $now.AddMinutes(-1) -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'),
        (New-HistoryEntry -Date $now.AddMinutes(-2) -Title '2026-06 Security Update (KB5094126)')
      )
      $searcher = [FakeUpdateSearcher]::new($history)

      $rows = @(Get-WindowsUpdateHistory -MaxResults 10 -MaxScanEntries 10 -IncludeAV -Searcher $searcher)

      Assert-Equal $rows.Count 2 'Expected Defender entries to be included when -IncludeAV is set.'
      Assert-True (@($rows.KB) -contains 'KB2267602') 'Expected KB2267602 to appear with -IncludeAV.'
    }
  },
  @{
    Name = 'MaxResults is applied after filtering'
    Body = {
      $now = Get-Date
      $history = @()
      1..100 | ForEach-Object {
        $history += New-HistoryEntry -Date $now.AddMinutes(-1 * $_) -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'
      }
      1..5 | ForEach-Object {
        $history += New-HistoryEntry -Date $now.AddMinutes(-100 - $_) -Title ("Regular Update {0} (KB50941{0})" -f $_)
      }
      $searcher = [FakeUpdateSearcher]::new($history)

      $rows = @(Get-WindowsUpdateHistory -MaxResults 2 -MaxScanEntries 200 -Searcher $searcher)

      Assert-Equal $rows.Count 2 'Expected MaxResults to limit matching rows, not scanned rows.'
      Assert-Equal @($rows.KB)[0] 'KB509412' 'Unexpected first matching KB.'
      Assert-Equal @($rows.KB)[1] 'KB509411' 'Unexpected second matching KB.'
    }
  },
  @{
    Name = 'LastDays filters older rows but still scans past filtered Defender rows'
    Body = {
      $now = Get-Date
      $history = @()
      1..100 | ForEach-Object {
        $history += New-HistoryEntry -Date $now.AddMinutes(-1 * $_) -Title 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'
      }
      $history += New-HistoryEntry -Date $now.AddDays(-2) -Title 'Recent regular update (KB5099999)'
      $history += New-HistoryEntry -Date $now.AddDays(-40) -Title 'Old regular update (KB5088888)'
      $searcher = [FakeUpdateSearcher]::new($history)

      $rows = @(Get-WindowsUpdateHistory -MaxResults 30 -LastDays 30 -MaxScanEntries 200 -Searcher $searcher)

      Assert-Equal $rows.Count 1 'Expected only the recent non-Defender row.'
      Assert-Equal $rows[0].KB 'KB5099999' 'Unexpected KB returned for LastDays filtering.'
    }
  },
  @{
    Name = 'Startup diagnostic output is only shown with Debug'
    Body = {
      $normalOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -ListRecentLogs *>&1 | Out-String
      $debugOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -ListRecentLogs -Debug *>&1 | Out-String

      Assert-True (-not ($normalOutput -match 'Logging to file:')) 'Did not expect transcript path output without -Debug.'
      Assert-True (-not ($normalOutput -match 'Debug: Command:')) 'Did not expect command diagnostics without -Debug.'
      Assert-True (-not ($normalOutput -match 'Debug: Arguments:')) 'Did not expect argument diagnostics without -Debug.'
      Assert-True ($debugOutput -match 'Logging to file:') 'Expected transcript path output with -Debug.'
      Assert-True ($debugOutput -match 'Debug: Command:') 'Expected command diagnostics with -Debug.'
      Assert-True ($debugOutput -match 'Debug: Arguments:') 'Expected argument diagnostics with -Debug.'
    }
  }
)

$passed = 0
foreach ($test in $tests) {
  Invoke-TestCase -Name $test.Name -Body $test.Body
  $passed++
}

Write-Host ''
Write-Host "All $passed WindowsUpdatesHelper history tests passed." -ForegroundColor Green
