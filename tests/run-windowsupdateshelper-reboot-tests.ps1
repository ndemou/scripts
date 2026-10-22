<#
.SYNOPSIS
Tests the native boot clock and forced-reboot decisions without rebooting.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\WindowsUpdatesHelper.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  $scriptPath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors) { throw $parseErrors[0].Message }

# Import only these functions and the forced-reboot branch. The script entry
# point, Windows Update operations, and real scheduled tasks are never run.
foreach ($name in @('Get-WuSystemBootTimeUtc', 'Register-WuForcedRebootTask')) {
  $definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
  }, $true)
  . ([scriptblock]::Create($definition.Extent.Text))
}
$rebootBranch = @($ast.EndBlock.Statements | Where-Object {
  $_ -is [System.Management.Automation.Language.IfStatementAst] -and
    $_.Extent.Text -match '^if\s*\(\$XXX_RebootNow\)'
})
if ($rebootBranch.Count -ne 1) { throw 'Expected one forced-reboot branch.' }
$rebootBlock = [scriptblock]::Create($rebootBranch[0].Extent.Text)

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Invoke-RebootCase {
  param([string]$ArmedAt, [datetime]$BootTimeUtc, [switch]$FailBootTimeRead)

  $XXX_RebootNow = $true
  $XXX_RebootArmedAt = $ArmedAt
  $script:TranscriptEnabled = $false
  $state = [pscustomobject]@{
    BootReads = 0
    Shutdowns = 0
    TaskLookups = 0
    Messages = [System.Collections.Generic.List[string]]::new()
  }

  function Assert-Elevated {}
  function Write-Host {
    param($Object, $ForegroundColor)
    $state.Messages.Add([string]$Object)
  }
  function Get-ScheduledTask {
    param($TaskName, $ErrorAction)
    $state.TaskLookups++
    return $null
  }
  function Unregister-ScheduledTask { throw 'Unexpected task removal.' }
  function Get-CimInstance { throw 'The forced-reboot check must not query WMI.' }
  function Get-WuSystemBootTimeUtc {
    $state.BootReads++
    if ($FailBootTimeRead) { throw 'Simulated boot clock failure' }
    $BootTimeUtc
  }
  function shutdown.exe {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    Assert-True ($Arguments -contains '/f' -and $Arguments -contains '/r') 'Expected a forced restart request.'
    $state.Shutdowns++
  }
  function Stop-Transcript { throw 'Unexpected transcript operation.' }

  & $rebootBlock
  $state
}

$firstBootUtc = Get-WuSystemBootTimeUtc
$secondBootUtc = Get-WuSystemBootTimeUtc
Assert-True ($firstBootUtc.Kind -eq [DateTimeKind]::Utc -and $firstBootUtc -le [datetime]::UtcNow) 'Expected a past UTC boot estimate from the real native API.'
Assert-True ([math]::Abs(($secondBootUtc - $firstBootUtc).TotalSeconds) -lt 1) 'Expected a stable boot estimate across successive native calls.'
Write-Host 'PASS    Native GetTickCount64 produces a stable UTC boot estimate.'

$armedUtc = [datetime]::SpecifyKind([datetime]'2026-10-22T03:00:00', [DateTimeKind]::Utc)
$armedText = $armedUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
$legacyText = $armedUtc.ToLocalTime().ToString('s', [Globalization.CultureInfo]::InvariantCulture)
$offsetText = ([datetimeoffset]$armedUtc).ToOffset([timespan]::FromHours(5.5)).ToString('o')
$cases = @(
  @{ Name = 'A reboot after arming skips the forced restart'; ArmedAt = $armedText; BootTime = $armedUtc.AddMinutes(1); Shutdowns = 0 },
  @{ Name = 'A boot 90 days before arming still allows the forced restart'; ArmedAt = $armedText; BootTime = $armedUtc.AddDays(-90); Shutdowns = 1 },
  @{ Name = 'A boot equal to armed-at does not count as a later reboot'; ArmedAt = $armedText; BootTime = $armedUtc; Shutdowns = 1 },
  @{ Name = 'Legacy local armed-at timestamps remain accepted'; ArmedAt = $legacyText; BootTime = $armedUtc.AddMinutes(1); Shutdowns = 0 },
  @{ Name = 'Explicit timezone offsets are compared as UTC'; ArmedAt = $offsetText; BootTime = $armedUtc.AddMinutes(1); Shutdowns = 0 }
)
foreach ($case in $cases) {
  $result = Invoke-RebootCase -ArmedAt $case.ArmedAt -BootTimeUtc $case.BootTime
  Assert-True ($result.BootReads -eq 1 -and $result.TaskLookups -eq 1) "Expected one boot check and one mocked task lookup: $($case.Name)"
  Assert-True ($result.Shutdowns -eq $case.Shutdowns) "Wrong reboot decision: $($case.Name)"
  Write-Host "PASS    $($case.Name)"
}

foreach ($invalidText in @('', 'not-a-timestamp')) {
  $result = Invoke-RebootCase -ArmedAt $invalidText -BootTimeUtc $armedUtc
  Assert-True ($result.BootReads -eq 0 -and $result.TaskLookups -eq 0 -and $result.Shutdowns -eq 0) 'Missing or invalid armed-at timestamps must refuse reboot before any external operation.'
}
Write-Host 'PASS    Missing and invalid armed-at timestamps refuse reboot.'

$failed = Invoke-RebootCase -ArmedAt $armedText -BootTimeUtc $armedUtc -FailBootTimeRead
Assert-True ($failed.BootReads -eq 1 -and $failed.Shutdowns -eq 1) 'Expected the existing forced-reboot fallback after a boot clock error.'
Assert-True (($failed.Messages -join "`n") -match 'WARNING:.*Simulated boot clock failure') 'Expected the boot clock failure to be logged.'
Write-Host 'PASS    Boot clock errors preserve the existing warning and forced-reboot fallback.'

& {
  $registration = [pscustomobject]@{ Arguments = '' }
  function New-ScheduledTaskAction {
    param($Execute, $Argument)
    [pscustomobject]@{ Execute = $Execute; Argument = $Argument }
  }
  function New-ScheduledTaskTrigger {
    param([switch]$Once, $At)
    [pscustomobject]@{ At = $At }
  }
  function New-ScheduledTaskPrincipal {
    param($UserId, $LogonType, $RunLevel)
    [pscustomobject]@{ UserId = $UserId }
  }
  function Register-ScheduledTask {
    param($TaskName, $Action, $Trigger, $Principal, [switch]$Force)
    $registration.Arguments = $Action.Argument
  }

  $success = Register-WuForcedRebootTask -ScriptPath 'C:\Test\WindowsUpdatesHelper.ps1' -Minutes 10 -ArmedAt $armedUtc.ToLocalTime()
  Assert-True $success 'Expected mocked task registration to succeed.'
  Assert-True ($registration.Arguments.Contains('-XXX_RebootArmedAt "' + $armedText + '"')) 'Expected new tasks to carry an unambiguous UTC round-trip timestamp.'
}
Write-Host 'PASS    New forced-reboot tasks store armed-at in UTC.'

Write-Host 'All 9 WindowsUpdatesHelper reboot checks passed.' -ForegroundColor Green
