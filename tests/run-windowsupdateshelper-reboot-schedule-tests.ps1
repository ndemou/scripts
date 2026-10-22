<#
.SYNOPSIS
Tests one-shot reboot scheduling and the fixed continuation window without system changes.
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
foreach ($name in @('Test-WuRebootCondition', 'Get-WuRebootTime', 'Get-WuRebootPlan', 'Invoke-WuApplyRebootPlan', 'Register-WuScheduledRebootTask', 'Register-WuResumeAfterRebootTask', 'Invoke-WuScheduledRestart', 'Invoke-WuScheduledReboot')) {
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
function Assert-Throws {
  param([scriptblock]$Action, [string]$Message)
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  Assert-True $rejected $Message
}

$localDue = [datetime]'2026-11-22T06:14:00'
$due = [datetimeoffset]$localDue
$deadline = $due.AddHours(1)
Assert-True ((Get-WuRebootTime '06:14' -After $localDue.AddMinutes(-1)) -eq $localDue) 'An upcoming time must use today.'
Assert-True ((Get-WuRebootTime '06:14' -After $localDue) -eq $localDue.AddDays(1)) 'A reached time must use tomorrow.'
Assert-True ((Get-WuRebootTime '06:14' -After $localDue.AddSeconds(1)) -eq $localDue.AddDays(1)) 'A past minute must never be scheduled retroactively.'
Assert-True ((Get-WuRebootTime '06:14 and WeekDay=Sunday and MonthDay>14' -After ([datetime]'2026-11-08T07:00')) -eq ([datetime]'2026-11-15T06:14')) 'Expected the next matching Sunday after the 14th.'
Assert-True ((Get-WuRebootTime ' 06:14 AnD weekday = SUNDAY and monthday <> 22 ' -After $localDue.AddMinutes(-1)) -eq $localDue.AddDays(7)) 'Casing, whitespace, and exclusions must work.'
Assert-True ((Get-WuRebootTime '00:00 and MonthDay=31' -After ([datetime]'2026-02-28')) -eq ([datetime]'2026-03-31')) 'Absent month days must advance to a matching month.'
Assert-True ((Get-WuRebootTime '06:14 and MonthDay=31 and WeekDay=Sunday' -After ([datetime]'2022-07-31T07:00')) -eq ([datetime]'2023-12-31T06:14')) 'Valid schedules may require looking more than one year ahead.'
$springTime = [datetime]'2026-03-29T03:30'
if ([TimeZoneInfo]::Local.IsInvalidTime($springTime)) {
  Assert-True ((Get-WuRebootTime '03:30' -After $springTime.AddDays(-1).AddHours(1)) -eq $springTime.AddDays(1)) 'Skip a nonexistent local time rather than reboot at a different hour.'
}
$autumnTime = [datetime]'2026-10-25T03:30'
if ([TimeZoneInfo]::Local.IsAmbiguousTime($autumnTime)) {
  $daylightOffset = @([TimeZoneInfo]::Local.GetAmbiguousTimeOffsets($autumnTime) | Sort-Object -Descending)[0]
  $afterFirstOccurrence = ([datetimeoffset]::new($autumnTime.AddMinutes(10), $daylightOffset)).LocalDateTime
  Assert-True ((Get-WuRebootTime '03:30' -After $afterFirstOccurrence) -eq $autumnTime) 'The standard-time occurrence is still future after the daylight-time occurrence.'
}
foreach ($invalid in @('', '6:14', '24:00', '06:60', '06:14:00', '06:14 and', '06:14 or 07:00', '06:14 and Hour24<9', '06:14 and Hour<9', '06:14 and MonthDay=0', '06:14 and WeekDay>Sunday', '06:14 and WeekDay=Sunday and WeekDay=Monday', '06:14 and MonthDay>20 and MonthDay<15', '06:14 and MonthDay<15 and Hour24<9', '06:14; throw "injected"')) {
  Assert-Throws { Get-WuRebootTime $invalid -After $localDue } "Expected invalid/impossible schedule to fail: $invalid"
}
Write-Host 'PASS    Time parsing, next occurrence, calendar boundaries, and impossible conditions.'

# Check public binding and execute only the preflight statements, never the entry point.
$bindingSource = @($ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text })
$bindingSource += $ast.ParamBlock.Extent.Text
$bindingBlock = [scriptblock]::Create(($bindingSource -join "`n") + "`n" + '$PSCmdlet.ParameterSetName')
Assert-True ((& $bindingBlock -RebootAt '06:14' -RebootAnyway) -eq 'Install') 'RebootAt must bind with RebootAnyway.'
Assert-True ((& $bindingBlock -XXX_ScheduledRebootAt $due -XXX_ContinueAfterReboot) -eq 'Special') 'The scheduled action must bind.'
Assert-True ((& $bindingBlock -XXX_ResumeAfterReboot -XXX_RebootAtUntil $deadline.ToString('o')) -eq 'Install') 'Continuation must bind the fixed deadline.'
$preflight = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith('if($PSBoundParameters.ContainsKey(''RebootAt''))') })
$logging = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text -match '^\$script:WuDebugOutputEnabled\s*=' })
Assert-True ($preflight.Count -eq 1 -and $preflight[0].Extent.StartOffset -lt $logging[0].Extent.StartOffset) 'Schedule validation must precede all operational work.'
$preflightBlock = [scriptblock]::Create('param([string]$RebootAt, [string]$RebootIf)' + "`n" + $preflight[0].Extent.Text)
Assert-Throws { & $preflightBlock -RebootAt '06:14' -RebootIf 'WeekDay=Sunday' } 'RebootAt and RebootIf must be mutually exclusive.'
Write-Host 'PASS    Public binding and validation before logging, tasks, or updates.'

# All operations below are mocks. Do not import or invoke the script entry point.
function Reset-State {
  $script:Now = $localDue
  $script:TranscriptEnabled = $false
  $script:Pending = $true
  $script:State = [pscustomobject]@{
    Tasks = @(); Removed = @(); Stopped = @(); Shutdowns = @(); FlagWrites = 0; FlagRemovals = 0
    ExistingTasks = @(); FlagExists = $false; ExitCode = 0; AdvanceDuringResume = [datetime]::MinValue; PendingWork = $false; FailStop = $false; FailResume = $false
    Messages = [System.Collections.Generic.List[string]]::new()
  }
}
function Get-Date { $script:Now }
function Write-Host { param($Object, $ForegroundColor) $State.Messages.Add([string]$Object) }
function Assert-Elevated {}
function Test-RebootPending { $script:Pending }
function Register-WuForcedRebootTask { throw 'Scheduled reboots must never register a forced fallback.' }
function Get-WuSystemBootTimeUtc { throw 'An intervening reboot must not suppress the scheduled request.' }
function Get-CimInstance { throw 'Scheduling must not query WMI.' }
function Start-Sleep { throw 'The scheduled path must not sleep until the reboot time.' }
function Stop-Transcript {}
function New-ScheduledTaskAction { param($Execute, $Argument) [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
function New-ScheduledTaskTrigger { param([switch]$Once, [switch]$AtStartup, $At) [pscustomobject]@{ Once = [bool]$Once; AtStartup = [bool]$AtStartup; At = $At; StartBoundary = ''; EndBoundary = '' } }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) [pscustomobject]@{ UserId = $UserId } }
function New-ScheduledTaskSettingsSet {
  param([switch]$StartWhenAvailable, $DeleteExpiredTaskAfter, $ExecutionTimeLimit)
  [pscustomobject]@{ StartWhenAvailable = [bool]$StartWhenAvailable; DeleteAfter = $DeleteExpiredTaskAfter }
}
function Register-ScheduledTask {
  [CmdletBinding()]
  param($TaskName, $Action, $Trigger, $Settings, $Principal, [switch]$Force)
  if ($State.FailResume -and $TaskName -eq 'WindowsUpdateHelper-ResumeAfterReboot') { Write-Error 'Simulated continuation registration failure'; return }
  $State.Tasks += [pscustomobject]@{ Name = $TaskName; Action = $Action; Trigger = $Trigger; Settings = $Settings; Principal = $Principal }
  if ($TaskName -eq 'WindowsUpdateHelper-ResumeAfterReboot' -and $State.AdvanceDuringResume -ne [datetime]::MinValue) { $script:Now = $State.AdvanceDuringResume }
}
function Set-Content {
  param($LiteralPath, $Value, $Encoding, [switch]$Force)
  Assert-True ($LiteralPath.EndsWith('resume.flag', [StringComparison]::OrdinalIgnoreCase) -or $LiteralPath.EndsWith('ResumeAfterReboot.flag', [StringComparison]::OrdinalIgnoreCase)) 'Unexpected flag path.'
  $State.FlagWrites++
  if ($State.AdvanceDuringResume -ne [datetime]::MinValue) { $script:Now = $State.AdvanceDuringResume }
}
function Remove-Item { [CmdletBinding()] param($LiteralPath, [switch]$Force) $State.FlagRemovals++ }
function Test-Path { param($LiteralPath) $State.FlagExists }
function Get-ScheduledTask { [CmdletBinding()] param($TaskName) if ($TaskName -in $State.ExistingTasks) { [pscustomobject]@{ State = 'Running' } } }
function Unregister-ScheduledTask { [CmdletBinding(SupportsShouldProcess=$true)] param($TaskName) $State.Removed += $TaskName }
function Stop-ScheduledTask { [CmdletBinding()] param($TaskName) if ($State.FailStop) { throw 'Simulated task stop failure' }; $State.Stopped += $TaskName }
function shutdown.exe {
  param([Parameter(ValueFromRemainingArguments=$true)][object[]]$Arguments)
  $State.Shutdowns += ,$Arguments
  $global:LASTEXITCODE = $State.ExitCode
}
function New-Plan {
  param([bool]$Needed = $true, [switch]$Anyway, [string]$Schedule = '06:14', [datetimeoffset]$Until = [datetimeoffset]::MinValue)
  $script:Pending = $Needed
  $results = @()
  if ($Needed) { $results += [pscustomobject]@{ ResultCode = 'Failed'; HResult = '0x80240030' } }
  Get-WuRebootPlan -InstalledSomething $Needed -WuaRequestsReboot $Needed -RebootPendingAtStart $false -AllUpdateResults $results -RebootAt $Schedule -RebootAtUntil $Until -RebootAnyway:$Anyway -XXX_ResumeAfterReboot:($Until -ne [datetimeoffset]::MinValue)
}

Reset-State
$script:Now = $localDue.AddMinutes(-2)
$plan = New-Plan
$script:Now = $localDue.AddMinutes(1) # Installation crossed the requested time.
Invoke-WuApplyRebootPlan -Plan $plan -ScriptPath 'C:\Test Path\helper.ps1' -FlagFilePath 'C:\Test\resume.flag'
Assert-True ($State.Tasks.Count -eq 1 -and $State.Tasks[0].Name -eq 'WindowsUpdateHelper-ScheduledReboot') 'Expected only one future reboot task.'
$task = $State.Tasks[0]
Assert-True ($task.Trigger.Once -and $task.Trigger.At -eq $localDue.AddDays(1)) 'Compute the next occurrence after installation completes.'
Assert-True ($State.FlagWrites -eq 0 -and $State.Shutdowns.Count -eq 0) 'Future scheduling must not create continuation state or reboot immediately.'
Assert-True (-not $task.Settings.StartWhenAvailable -and $task.Trigger.EndBoundary -ne '') 'A missed task must not catch up.'
Assert-True ($task.Principal.UserId -eq 'SYSTEM' -and $task.Action.Argument.Contains('-File "C:\Test Path\helper.ps1"')) 'Expected SYSTEM execution and a quoted script path.'
Assert-True ($task.Action.Argument.Contains('-XXX_ScheduledRebootAt "' + $localDue.AddDays(1).ToUniversalTime().ToString('o') + '"') -and $task.Action.Argument.Contains('-XXX_ContinueAfterReboot')) 'Carry the exact UTC instant and continuation need.'
Assert-True (($State.Messages -join ' ') -match '2026-11-23 06:14:00') 'Log the exact chosen local date and time.'

Reset-State
Invoke-WuApplyRebootPlan -Plan (New-Plan -Needed $false) -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag'
Assert-True ($State.Tasks.Count -eq 0) 'RebootAt alone must not schedule an unneeded reboot.'
Invoke-WuApplyRebootPlan -Plan (New-Plan -Needed $false -Anyway) -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag'
Assert-True ($State.Tasks.Count -eq 1 -and $State.Shutdowns.Count -eq 0) 'RebootAnyway must still obey the future schedule.'
Write-Output 'PASS    One-shot registration, late evaluation, logging, reboot need, and RebootAnyway.'

foreach ($at in @($localDue.AddSeconds(-1), $localDue.AddMinutes(1), $localDue.AddDays(1))) {
  Reset-State
  $script:Now = $at
  Invoke-WuScheduledReboot -At $due -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -ContinueAfterReboot
  Assert-True ($State.Shutdowns.Count -eq 0 -and $State.FlagWrites -eq 0 -and $State.Tasks.Count -eq 0) 'Early/missed executions must not reboot, retry, or prepare continuation.'
}
Reset-State
Invoke-WuScheduledReboot -At $due -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -ContinueAfterReboot
Assert-True ($State.Shutdowns.Count -eq 1 -and ($State.Shutdowns[0] -join ' ') -match '/r /t 60') 'At the scheduled minute, request a restart with the accepted countdown.'
Assert-True ($State.FlagWrites -eq 0 -and $State.Tasks.Count -eq 1 -and $State.Tasks[0].Trigger.AtStartup) 'Only prepare startup continuation at reboot time, using the task deadline without a redundant flag.'
Assert-True ($State.Tasks[0].Action.Argument.Contains('-XXX_RebootAtUntil "' + $deadline.ToString('o') + '"')) 'Pass the original fixed one-hour deadline.'
Reset-State
$State.AdvanceDuringResume = $localDue.AddMinutes(1)
Invoke-WuScheduledReboot -At $due -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -ContinueAfterReboot
Assert-True ($State.Shutdowns.Count -eq 0 -and $State.Removed.Count -eq 1) 'Crossing the scheduled minute during preparation must cancel reboot and its prepared state.'
Write-Output 'PASS    Scheduled minute, no boot check, countdown, missed runs, and late preparation cleanup.'

Reset-State
$script:Now = $localDue.AddMinutes(20)
Invoke-WuApplyRebootPlan -Plan (New-Plan -Schedule '' -Until $deadline) -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag'
Assert-True ($State.Shutdowns.Count -eq 1 -and $State.Tasks.Count -eq 1 -and $State.Tasks[0].Trigger.AtStartup) 'A continuation may reboot immediately and prepare another continuation within the original hour.'
Assert-True ($State.Tasks[0].Action.Argument.Contains($deadline.ToString('o'))) 'A continuation must never extend its deadline.'
foreach ($at in @($localDue.AddMinutes(59).AddSeconds(1), $localDue.AddHours(1), $localDue.AddDays(7))) {
  Reset-State
  $script:Now = $at
  Invoke-WuApplyRebootPlan -Plan (New-Plan -Schedule '' -Until $deadline) -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag'
  Assert-True ($State.Shutdowns.Count -eq 0 -and $State.FlagWrites -eq 0 -and $State.Tasks.Count -eq 0) 'An expired continuation must not reboot or schedule another occurrence.'
}
Reset-State
$script:Now = $localDue.AddMinutes(59)
Invoke-WuScheduledRestart -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -Until $deadline
Assert-True ($State.Shutdowns.Count -eq 1) 'A countdown ending exactly at the one-hour deadline is allowed.'
Reset-State
$script:Now = $localDue.AddMinutes(58)
$State.AdvanceDuringResume = $localDue.AddMinutes(59).AddSeconds(1)
Invoke-WuScheduledRestart -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -Until $deadline -ContinueAfterReboot
Assert-True ($State.Shutdowns.Count -eq 0 -and $State.Removed.Count -eq 1) 'Recheck the original deadline after creating continuation state.'
Reset-State
$State.ExitCode = 5
Assert-Throws { Invoke-WuScheduledReboot -At $due -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -ContinueAfterReboot } 'A failed shutdown command must be reported without a fallback.'
Assert-True ($State.Shutdowns.Count -eq 1 -and $State.Removed.Count -eq 1) 'Do not retry a failed request, and remove prepared continuation.'
Reset-State
$State.FailResume = $true
Invoke-WuScheduledReboot -At $due -ScriptPath 'C:\Test\helper.ps1' -FlagFilePath 'C:\Test\resume.flag' -ContinueAfterReboot
Assert-True ($State.Shutdowns.Count -eq 1 -and $State.Tasks.Count -eq 0) 'A continuation registration failure must warn and preserve the requested scheduled reboot.'
Assert-True (($State.Messages -join ' ') -match 'Could not prepare continuation') 'Report continuation preparation failure.'
Write-Output 'PASS    Continuation reboot, fixed deadline, countdown boundary, and no fallback on command failure.'

$install = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-InstallPhase' }, $true)
$expiredGuard = @($install.Body.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] -and $_.Clauses[0].Item1.Extent.Text -match '\$RebootAtUntil.UtcDateTime' })
Assert-True ($expiredGuard.Count -eq 1) 'Expected one continuation deadline guard before update work.'
$serviceStart = @($install.Body.EndBlock.Statements | Where-Object { $_.Extent.Text -eq 'Ensure-WuService' })
Assert-True ($expiredGuard[0].Extent.StartOffset -lt $serviceStart[0].Extent.StartOffset) 'Expired continuation must exit before service/update operations.'
Reset-State
$script:Now = $localDue.AddHours(1)
$RebootAtUntil = $deadline
$State.PendingWork = $false
$guardBlock = [scriptblock]::Create($expiredGuard[0].Extent.Text + "`n" + '$State.PendingWork = $true')
& $guardBlock
Assert-True (-not $State.PendingWork) 'Expired continuation must return before installation.'

Reset-State
$cleanup = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.TryStatementAst] -and $_.Extent.Text -match 'during startup cleanup' })
$State.ExistingTasks = @('WindowsUpdateHelper-ScheduledReboot')
$taskName = 'WindowsUpdateHelper-ForcedReboot'
& ([scriptblock]::Create($cleanup[0].Extent.Text))
Assert-True ($State.Removed.Count -eq 0) 'Another helper invocation must preserve the future scheduled reboot.'

$abort = @($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith('if($AbortReboot)') })
Reset-State
$AbortReboot = $true
$State.ExistingTasks = @('WindowsUpdateHelper-ScheduledReboot', 'WindowsUpdateHelper-ForcedReboot', 'WindowsUpdateHelper-ResumeAfterReboot')
$State.FlagExists = $true
& ([scriptblock]::Create($abort[0].Extent.Text))
Assert-True ($State.Removed.Count -eq 3 -and $State.Stopped.Count -eq 3 -and $State.FlagRemovals -eq 1) 'Abort must cancel future/running tasks and continuation state.'
Assert-True ($State.Shutdowns.Count -eq 1 -and $State.Shutdowns[0][0] -eq '/a') 'Abort must also cancel a pending countdown.'
Reset-State
$State.ExistingTasks = @('WindowsUpdateHelper-ScheduledReboot')
$State.FailStop = $true
& ([scriptblock]::Create($abort[0].Extent.Text))
Assert-True ($State.Removed.Count -eq 1 -and $State.Shutdowns.Count -eq 1) 'A task stop failure must not prevent unregistering the future task or cancelling the countdown.'
Write-Output 'PASS    Expired installation guard, persistent scheduled task, and complete AbortReboot cancellation.'
Write-Output 'All WindowsUpdatesHelper reboot-schedule tests passed.'
