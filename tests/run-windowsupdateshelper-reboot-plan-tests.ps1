<#
.SYNOPSIS
Tests immediate reboot plans without updates, tasks, or reboots.
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
foreach ($name in @('Get-WuRebootPlan', 'Invoke-WuApplyRebootPlan')) {
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

function Invoke-PlanCase {
  param([switch]$Reboot, [bool]$NeedsReboot = $true, [switch]$RebootAnyway, [switch]$Resume)

  $state = [pscustomobject]@{ Shutdowns = 0; Delay = 0; Forced = @(); Continuations = @() }
  $script:TranscriptEnabled = $false
  function Test-RebootPending { $NeedsReboot }
  function Write-Host { param($Object, $ForegroundColor) }
  function Write-DbgDump { param([switch]$Json, $Label, $Obj) }
  function Start-Sleep { param($Seconds) }
  function Stop-Transcript { throw 'Unexpected transcript operation.' }
  function Register-WuForcedRebootTask {
    param($ScriptPath, $Minutes, $ArmedAt)
    $state.Forced += $Minutes
    return $true
  }
  function Register-WuResumeAfterRebootTask {
    param($ScriptPath, $FlagFilePath)
    $state.Continuations += $ScriptPath
    return $true
  }
  function shutdown.exe {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)
    $state.Shutdowns++
    $delayIndex = [array]::IndexOf($Arguments, '/t')
    $state.Delay = [int]$Arguments[$delayIndex + 1]
  }
  $results = @()
  if ($NeedsReboot) { $results += [pscustomobject]@{ ResultCode = 'Failed'; HResult = '0x80240030' } }
  $plan = Get-WuRebootPlan -InstalledSomething:$NeedsReboot -WuaRequestsReboot:$NeedsReboot -RebootPendingAtStart:$false -AllUpdateResults $results -Reboot:$Reboot -RebootAnyway:$RebootAnyway -XXX_ResumeAfterReboot:$Resume
  Invoke-WuApplyRebootPlan -Plan $plan -ScriptPath 'C:\Test\WindowsUpdatesHelper.ps1' -FlagFilePath 'C:\Test\resume.flag'
  return $state
}

$needed = Invoke-PlanCase -Reboot
Assert-True ($needed.Shutdowns -eq 1 -and $needed.Delay -eq 60) 'Reboot must preserve the 60-second countdown when needed.'
Assert-True ($needed.Forced.Count -eq 1 -and $needed.Forced[0] -eq 5 -and $needed.Continuations.Count -eq 1) 'A needed reboot must prepare the five-minute fallback and continuation.'
$disabled = Invoke-PlanCase
Assert-True ($disabled.Shutdowns -eq 0 -and $disabled.Forced.Count -eq 0 -and $disabled.Continuations.Count -eq 0) 'Without a reboot option, no restart or tasks may be requested.'
$unneeded = Invoke-PlanCase -Reboot -NeedsReboot $false
Assert-True ($unneeded.Shutdowns -eq 0 -and $unneeded.Forced.Count -eq 0) 'Reboot must not restart when no reboot is needed.'
$anyway = Invoke-PlanCase -NeedsReboot $false -RebootAnyway
Assert-True ($anyway.Shutdowns -eq 1 -and $anyway.Forced.Count -eq 1) 'RebootAnyway must restart even without pending updates.'
$resume = Invoke-PlanCase -Reboot -Resume
Assert-True ($resume.Shutdowns -eq 1 -and $resume.Continuations.Count -eq 0) 'Immediate continuation runs must not register another continuation.'
Write-Host 'All WindowsUpdatesHelper immediate-reboot plan tests passed.' -ForegroundColor Green
