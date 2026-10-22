<#
.SYNOPSIS
Tests reboot conditions and propagation without updates, tasks, or reboots.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\WindowsUpdatesHelper.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) { throw $parseErrors[0].Message }
foreach ($name in @('Test-WuRebootCondition', 'Get-WuRebootPlan', 'Invoke-WuApplyRebootPlan', 'Register-WuForcedRebootTask', 'Register-WuResumeAfterRebootTask')) {
  $definition = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
  }, $true)
  . ([scriptblock]::Create($definition.Extent.Text))
}

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

$sunday = [datetime]'2026-11-08T08:59:30'
$trueConditions = @(
  'WeekDay=Sunday', 'WeekDay<>Monday', 'MonthDay<>4', 'MonthDay=8',
  'MonthDay<9', 'MonthDay<=8', 'MonthDay>5', 'MonthDay>=8',
  'Hour24<9', 'Hour24<=8', 'Hour24>1', 'Hour24>=1', 'Hour24=8', 'Hour24<>9',
  'WeekDay=Sunday and MonthDay>5 and Hour24<9 and Hour24>1',
  ' weekday = SUNDAY  AnD  monthday > 05 and HOUR24 < 9 '
)
foreach ($condition in $trueConditions) {
  Assert-True (Test-WuRebootCondition -Condition $condition -At $sunday) "Expected true: $condition"
}
foreach ($condition in @('WeekDay=Monday', 'WeekDay<>Sunday', 'MonthDay=4', 'MonthDay<8', 'MonthDay>8', 'Hour24<8', 'Hour24>8', 'Hour24=9', 'WeekDay=Monday and Hour24<9')) {
  Assert-True (-not (Test-WuRebootCondition -Condition $condition -At $sunday)) "Expected false: $condition"
}
Assert-True (Test-WuRebootCondition -Condition 'Hour24>=1' -At $sunday.Date.AddHours(1)) 'Hour24>=1 must include 01:00.'
Assert-True (-not (Test-WuRebootCondition -Condition 'Hour24>1' -At $sunday.Date.AddHours(1))) 'Hour24>1 must exclude the whole 01:00 hour.'
Assert-True (Test-WuRebootCondition -Condition 'Hour24=0' -At $sunday.Date) 'Midnight must be hour zero.'
Assert-True (Test-WuRebootCondition -Condition 'Hour24=23' -At $sunday.Date.AddHours(23)) '23 must be an accepted hour.'
Assert-True (-not (Test-WuRebootCondition -Condition 'MonthDay=31' -At ([datetime]'2026-02-28'))) 'A valid day absent from this month must simply be false.'
Write-Host 'PASS    Comparisons, AND, casing, whitespace, and date boundaries.'

foreach ($condition in @('', ' ', 'Hour<9', 'Hour24=24', 'MonthDay=0', 'MonthDay=32', 'WeekDay=Funday', 'WeekDay=0', 'WeekDay>Monday', 'Hour24>-1', 'Hour24=1.5', 'Hour24=99999999999999999999', 'Hour24==8', 'Hour24=8 or Hour24=9', '(Hour24<9)', 'Hour24<9 and', 'MonthDay=4 and Hour<9', 'WeekDay=Monday and Hour24=24', 'Hour24<9; throw "injected"')) {
  $rejected = $false
  try { [void](Test-WuRebootCondition -Condition $condition -At $sunday) }
  catch { $rejected = $true }
  Assert-True $rejected "Expected invalid condition to be rejected: '$condition'"
}
Write-Host 'PASS    Invalid input is rejected even after an earlier false clause.'

$preflight = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith('if($PSBoundParameters.ContainsKey(''RebootIf''))') })
$logging = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -match '^\$script:WuDebugOutputEnabled\s*=' })
Assert-True ($preflight.Count -eq 1 -and $logging.Count -eq 1 -and $preflight[0].Extent.StartOffset -lt $logging[0].Extent.StartOffset) 'RebootIf validation must run before logging, task cleanup, and update work.'
Write-Host 'PASS    Entry-point validation precedes operational work.'

$bindingSource = @($ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text })
$bindingSource += $ast.ParamBlock.Extent.Text
$bindingSource += '$PSCmdlet.ParameterSetName'
$bindingBlock = [scriptblock]::Create(($bindingSource -join "`n"))
Assert-True ((& $bindingBlock -RebootIf 'WeekDay=Sunday') -eq 'Install') 'RebootIf alone must select normal installation.'
Assert-True ((& $bindingBlock -RebootAnyway -RebootIf 'WeekDay=Sunday') -eq 'Install') 'RebootIf must combine with RebootAnyway.'
Assert-True ((& $bindingBlock -XXX_ResumeAfterReboot -RebootIf 'WeekDay=Sunday') -eq 'Install') 'Continuation invocations must accept RebootIf.'
Assert-True ((& $bindingBlock -XXX_RebootNow -XXX_RebootArmedAt '2026-11-08T01:00:00' -RebootIf 'WeekDay=Sunday') -eq 'Special') 'Forced reboot invocations must accept RebootIf.'
Write-Host 'PASS    Public arguments bind correctly for normal, forced, and continuation runs.'

function Invoke-PolicyCase {
  param([string]$Condition, [datetime]$At, [bool]$NeedsReboot = $true, [switch]$RebootAnyway, [switch]$Resume, [datetime]$AfterPreparation = [datetime]::MinValue)

  $state = [pscustomobject]@{ Now = $At.AddDays(-1); Shutdowns = 0; Delay = 0; Forced = @(); Continuations = @(); RemovedTasks = @(); RemovedFlags = 0 }
  $script:TranscriptEnabled = $false
  function Get-Date { $state.Now }
  function Test-RebootPending { $NeedsReboot }
  function Write-Host { param($Object, $ForegroundColor) }
  function Write-DbgDump { param([switch]$Json, $Label, $Obj) }
  function Start-Sleep { param($Seconds) $state.Now = $state.Now.AddSeconds($Seconds) }
  function Stop-Transcript { throw 'Unexpected transcript operation.' }
  function Register-WuForcedRebootTask {
    param($ScriptPath, $Minutes, $ArmedAt, $RebootIf)
    $state.Forced += $RebootIf
    if($AfterPreparation -ne [datetime]::MinValue){ $state.Now = $AfterPreparation }
    return $true
  }
  function Register-WuResumeAfterRebootTask {
    param($ScriptPath, $FlagFilePath, $RebootIf)
    $state.Continuations += $RebootIf
    return $true
  }
  function shutdown.exe {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)
    $state.Shutdowns++
    $delayIndex = [array]::IndexOf($Arguments, '/t')
    $state.Delay = [int]$Arguments[$delayIndex + 1]
  }
  function Unregister-ScheduledTask {
    param($TaskName, [switch]$Confirm, $ErrorAction)
    $state.RemovedTasks += $TaskName
  }
  function Remove-Item {
    param($LiteralPath, [switch]$Force, $ErrorAction)
    Assert-True ($LiteralPath -eq 'C:\Test\resume.flag') 'Only the newly created continuation flag may be removed.'
    $state.RemovedFlags++
  }

  $results = @()
  if ($NeedsReboot) { $results += [pscustomobject]@{ ResultCode = 'Failed'; HResult = '0x80240030' } }
  $plan = Get-WuRebootPlan -InstalledSomething:$NeedsReboot -WuaRequestsReboot:$NeedsReboot -RebootPendingAtStart:$false -AllUpdateResults $results -RebootIf $Condition -RebootAnyway:$RebootAnyway -XXX_ResumeAfterReboot:$Resume
  # The time at installation start is irrelevant; evaluate when applying the plan.
  $state.Now = $At
  Invoke-WuApplyRebootPlan -Plan $plan -ScriptPath 'C:\Test\WindowsUpdatesHelper.ps1' -FlagFilePath 'C:\Test\resume.flag'
  return $state
}

$condition = 'WeekDay=Sunday and MonthDay>5 and Hour24<9 and Hour24>1'
$allowed = Invoke-PolicyCase -Condition $condition -At $sunday
Assert-True ($allowed.Shutdowns -eq 1 -and $allowed.Delay -eq 60) 'RebootIf alone must enable a needed reboot and preserve the 60-second countdown at 08:59:30.'
Assert-True ($allowed.Forced.Count -eq 1 -and $allowed.Forced[0] -eq $condition) 'The forced task must inherit the condition.'
Assert-True ($allowed.Continuations.Count -eq 1 -and $allowed.Continuations[0] -eq $condition) 'The continuation task must inherit the condition.'
Write-Host 'PASS    RebootIf implies Reboot, is evaluated late, and propagates to both tasks.'

$denied = Invoke-PolicyCase -Condition $condition -At $sunday.Date.AddHours(9) -RebootAnyway
Assert-True ($denied.Shutdowns -eq 0 -and $denied.Forced.Count -eq 0 -and $denied.Continuations.Count -eq 0) 'A false condition must block RebootAnyway without scheduling a retry or continuation.'
$unneeded = Invoke-PolicyCase -Condition $condition -At $sunday -NeedsReboot $false
Assert-True ($unneeded.Shutdowns -eq 0) 'RebootIf alone must not reboot when there is no need.'
$anyway = Invoke-PolicyCase -Condition $condition -At $sunday -NeedsReboot $false -RebootAnyway
Assert-True ($anyway.Shutdowns -eq 1) 'RebootAnyway may reboot without need when the condition matches.'
$resume = Invoke-PolicyCase -Condition $condition -At $sunday.Date.AddHours(9) -Resume
Assert-True ($resume.Shutdowns -eq 0) 'Continuation runs must obey a false condition.'
$unconditional = Invoke-PolicyCase -Condition '' -At $sunday -NeedsReboot $false -RebootAnyway
Assert-True ($unconditional.Shutdowns -eq 1) 'Omitting RebootIf must preserve existing behavior.'
Write-Host 'PASS    RebootAnyway, no-reboot-needed, continuation, and unfiltered behavior.'

$changed = Invoke-PolicyCase -Condition $condition -At $sunday -AfterPreparation $sunday.Date.AddHours(9)
Assert-True ($changed.Shutdowns -eq 0 -and $changed.RemovedTasks.Count -eq 2 -and $changed.RemovedFlags -eq 1) 'If preparation crosses the allowed boundary, skip shutdown and clean up newly registered state.'
$changedDuringDelay = Invoke-PolicyCase -Condition $condition -At $sunday.Date.AddHours(9).AddSeconds(-1)
Assert-True ($changedDuringDelay.Shutdowns -eq 0 -and $changedDuringDelay.RemovedTasks.Count -eq 2) 'The final check must follow the one-second preparation delay, immediately before the shutdown request.'
Write-Host 'PASS    A condition that expires during task preparation prevents reboot and removes prepared state.'

& {
  $state = [pscustomobject]@{ Arguments = @(); FlagWrites = 0 }
  function Set-Content { param($LiteralPath, $Value, $Encoding, [switch]$Force) $state.FlagWrites++ }
  function New-ScheduledTaskAction { param($Execute, $Argument) [pscustomobject]@{ Argument = $Argument } }
  function New-ScheduledTaskTrigger { param([switch]$Once, [switch]$AtStartup, $At) return $null }
  function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return $null }
  function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, [switch]$Force) $state.Arguments += $Action.Argument }
  $forced = Register-WuForcedRebootTask -ScriptPath 'C:\Test\helper.ps1' -Minutes 5 -ArmedAt $sunday -RebootIf $condition
  $continuation = @(Register-WuResumeAfterRebootTask -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -RebootIf $condition)
  Assert-True ($forced -and $continuation.Count -eq 1 -and $continuation[0] -is [bool] -and $continuation[0] -and $state.FlagWrites -eq 1 -and $state.Arguments.Count -eq 2) 'Expected Boolean registration results, both mocked tasks, and the continuation flag.'
  foreach ($arguments in $state.Arguments) {
    Assert-True ($arguments.Contains('-RebootIf "' + $condition + '"')) 'The task action must preserve the entire condition as one quoted argument.'
  }
}
Write-Host 'PASS    Both registered task command lines preserve the quoted condition.'

Write-Host 'All WindowsUpdatesHelper reboot-condition tests passed.' -ForegroundColor Green
