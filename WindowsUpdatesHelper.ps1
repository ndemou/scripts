<#
.SYNOPSIS
Installs Windows Updates using the supported WUA COM API, with optional download, controlled reboot (now or scheduled), and detailed logging.

.DESCRIPTION

SPECIAL SHOW UPDATE HISTORY MODE
---------------------------------
If -ShowHistory is used, the script does NOT install/download/reboot.
Instead it queries Windows Update history (same source as the GUI "View update history"),
optionally filtered, and then exits.

NORMAL INSTALL UPDATES MODE
----------------------------
By default(without -ShowHistory) it installs Windows updates like this:
- Installs already downloaded updates if any.
- With -Download, will also download all required updates.
- With -Reboot, will reboot after installation if needed (or regardless with -RebootAnyway).

Batches "normal" updates together; installs "exclusive" updates one-by-one; accepts EULAs.

Robustness:
Service start is retried up to 3x with exponential delays (5s, 10s, 20s) before failing.

Pending reboot detection uses WU `RebootRequired` and CBS `RebootPending`.

Post-download refresh search has a catch/fallback: if the refresh search throws, proceeds using the initial search results (with a warning).

Uses only supported, inbox components (no extra modules, no `UsoClient`, PS 5.1-safe syntax).

Reboot is first tried without /f and after a few minutes with /f.

If an update (e.g. Servicing Stack) installs and immediately requires a reboot; subsequent updates will fail with 0x80240030 until reboot. If such failures are detected and the script was run with -Reboot or -RebootAnyway,
  the script will ensure continuation of installations after the reboot like this:
  - Create a temporary scheduled task that runs this script again
    at startup with -XXX_ResumeAfterReboot.
- On that second automated run with -XXX_ResumeAfterReboot:
  - The startup task is removed and the script continues as normal (install + maybe reboot).

Logging:
- Logs everything to WindowsUpdateHelper-YYYY-MM-DD.log
  1. If C:\IT\LOG exists, log is created there.
  2. Else if C:\IT\LOGS exists, there.
  3. Else in the system temp folder.


.PARAMETER Download
Perform online scan and download applicable updates that are not yet downloaded, then proceed to install everything downloaded.

.PARAMETER Reboot
After installation, reboot only if updates require it (or regardless if -RebootAnyway is also used).

.PARAMETER Interactive
If specified, the script will include updates flagged as InstallationBehavior.CanRequestUserInput
(Like some drivers/firmware that show GUI prompts and wait for user actions -- e.g. clicking "Accept").
Without this switch, such updates are skipped.
Alias: -CanRequestUserInput

.PARAMETER RebootAnyway
Reboot regardless of whether updates require it (implies -Reboot).

.PARAMETER XXX_ResumeAfterReboot
DO NOT USE THIS SWITCH. It is used INTERNALLY to continue installations after a reboot.

.PARAMETER AbortReboot
Abort a reboot initiated by this script

.PARAMETER XXX_RebootNow
DO NOT USE THIS SWITCH. It is used INTERNALLY to force a reboot.

.PARAMETER XXX_RebootArmedAt
DO NOT USE THIS SWITCH. It is used INTERNALLY to avoid rebooting if a reboot already occured after this time.


.PARAMETER ShowHistory
List Windows Update history (no install/download/reboot) and exit.

.PARAMETER MaxResults
(ShowHistory mode) Maximum number of matching history entries to output. Default: 30. Use 0 to return all matches found (within MaxScanEntries).

.PARAMETER LastDays
(ShowHistory mode) Only include history entries from the last N days.

.PARAMETER IncludeAV
(ShowHistory mode) Include KB2267602 (Defender definitions) entries (excluded by default).

.PARAMETER MaxScanEntries
(ShowHistory mode) Safety cap: maximum number of history rows to scan. Default: 10000.

.PARAMETER ListRecentLogs
List this script's log files and exit. Returns FileInfo objects sorted by LastWriteTime (oldest -> newest; most recent last).
By default it returns the most recent 10 log files.

.PARAMETER ListAll
Used only with -ListRecentLogs. If specified, returns all log files that can be found (instead of only the most recent 10).

.PARAMETER InstallOptional
Installs an optional update (needs the update ID)

.EXAMPLE
# Install any already downloaded updates and reboot if needed:
.\WindowsUpdatesHelper.ps1 -Reboot

# Download, Install and if needed reboot:
.\WindowsUpdatesHelper.ps1 -Download -Reboot

# Download, Install and reboot regardless of whether updates require it:
.\WindowsUpdatesHelper.ps1 -Download -Reboot -RebootAnyway

# Show latest Windows Update history entries:
.\WindowsUpdatesHelper.ps1 -ShowHistory

# Show latest Windows Update history entries, include AV updates:
.\WindowsUpdatesHelper.ps1 -ShowHistory -LastDays 14 -IncludeAV

# List the most recent 10 log files created by this script (most recent last):
.\WindowsUpdatesHelper.ps1 -ListRecentLogs
#>

<#
=== TODO ===
 * Interactive updates should be defered as long as possible:
Without -Reboot:
    We should first try to install everything that is
    Non-interactive, then try to install interactive ones.
With -Reboot:
    We should first try to install everything that is
    Non-interactive, reboot as necessary, then try to install
    interactive ones then again reboot as necessary.
    (For the moment I have logic that never reboots a 2nd time
    I must adjust it for this case)

 * Detect if another version of this script is already running
   Notify user accordingly

 * React to these access denied errors that are thrown if you run this script from within Enter-PSSession. 
I can probably create a throwaway scheduled task that will execute the script with the same arguments.

Downloading 1 update(s)...
Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
    + CategoryInfo          : OperationStopped: (:) [WindowsUpdatesHelper.ps1], UnauthorizedAccessException
    + FullyQualifiedErrorId : System.UnauthorizedAccessException,WindowsUpdatesHelper.ps1

Installing 1 normal update(s) as a batch...
Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
    + CategoryInfo          : OperationStopped: (:) [WindowsUpdatesHelper.ps1], UnauthorizedAccessException
    + FullyQualifiedErrorId : System.UnauthorizedAccessException,WindowsUpdatesHelper.ps1
#>
[CmdletBinding(PositionalBinding=$false, DefaultParameterSetName='Install')]
param(
    [Parameter(ParameterSetName='Install')][switch]$Download,
    [Parameter(ParameterSetName='Install')][switch]$Reboot,
    [Parameter(ParameterSetName='Install')][switch]$RebootAnyway,
    [Parameter(ParameterSetName='Install')][Alias('CanRequestUserInput')][switch]$Interactive,
    [Parameter(ParameterSetName='Install')][switch]$XXX_ResumeAfterReboot,

    [Parameter(ParameterSetName='History', Mandatory=$true)][switch]$ShowHistory,
    [Parameter(ParameterSetName='History')][int]$MaxResults = 30,
    [Parameter(ParameterSetName='History')][int]$LastDays,
    [Parameter(ParameterSetName='History')][switch]$IncludeAV,
    [Parameter(ParameterSetName='History')][int]$MaxScanEntries = 10000,

    [Parameter(ParameterSetName='Logs', Mandatory=$true)][switch]$ListRecentLogs,
    [Parameter(ParameterSetName='Logs')][switch]$ListAll,
    
    [Parameter(ParameterSetName='Special')][switch]$XXX_RebootNow,
    [Parameter(ParameterSetName='Special')][string]$XXX_RebootArmedAt,
	
	[Parameter(ParameterSetName='InstallOptional')][string]$InstallOptional,
    
    [Parameter(ParameterSetName='AbortReboot')][switch]$AbortReboot
)

# -------------------------------------------------------------------------------------------------
# START
#       Generic Helper Functions
# -------------------------------------------------------------------------------------------------
function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal $id
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Must be run elevated."
    }
}

function Test-IsSystemAccount {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($id -and $id.User){ return ($id.User.Value -eq 'S-1-5-18') }
  return $false
}

function Test-RebootPending {
    $wu  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    return ($wu -or $cbs)
}

<#
.SYNOPSIS
Writes a labeled debug dump of an object to host output.

.DESCRIPTION
Writes a host-formatted debug block for the supplied label and object.

When Obj is null, it writes a null marker line. When Json is set, it writes
JSON text. Otherwise it writes a CLIXML block delimited by BEGIN/END marker
lines. If dump generation fails, it writes an error line to the host and does
not throw.

.OUTPUTS
None.

.PARAMETER Label
Text shown in the debug header.
.PARAMETER Obj
Value to dump. Null is accepted and produces a null marker line.
.PARAMETER Depth
Maximum serialization depth used for JSON or CLIXML output.
.PARAMETER Json
When set, writes JSON output; otherwise writes CLIXML output.
#>
function Write-DbgDump {
  [CmdletBinding()]
  param(
  [Parameter(Mandatory=$true)][string]$Label,
  [Parameter()][AllowNull()][object]$Obj,
  [int]$Depth=20,
  [switch]$Json
  )
  try {
      if ($null -eq $Obj) {
        Write-Host "`n-----DEBUG $Label = `$null -----" -ForegroundColor Cyan
      } else {
        if ($Json) {
            Write-Host "`n-----DEBUG JSON of $Label -----" -ForegroundColor Cyan
            Write-Host -ForegroundColor DarkCyan ($Obj|ConvertTo-Json -Depth $Depth)
        } else {
            Write-Host ("`n-----BEGIN DEBUG CLIXML of {0} -----" -f $Label) -ForegroundColor Cyan
            $xml=[System.Management.Automation.PSSerializer]::Serialize($Obj,$Depth)
            Write-Host $xml -ForegroundColor DarkCyan
            Write-Host ("-----END DEBUG CLIXML --------------------`n" -f $Label) -ForegroundColor Cyan
        }
      }
  } catch {
        Write-Host -ForegroundColor Red "Write-DbgDump exception: $($_.Exception.Message)"
  }
}

<#
.SYNOPSIS
Reads a CLIXML debug dump text and returns the deserialized value.

.OUTPUTS
Deserialized object from the CLIXML content.

.DESCRIPTION
Accepts either a full debug dump block produced by Write-DbgDump in CLIXML
mode or raw CLIXML text.

If Text does not contain a CLIXML debug block, the full Text value is treated
as CLIXML input. The function throws if the effective CLIXML input is empty or
cannot be deserialized.

.PARAMETER Text
Input text containing a CLIXML debug block or raw CLIXML text.

.EXAMPLE
$obj = Read-DbgDump -Text $dumpText
#>
function Read-DbgDump {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Text)
  $m=[regex]::Match($Text,'(?ms)-----BEGIN DEBUG CLIXML .*?-----\s*(?<xml>.*?)\s*-----END DEBUG CLIXML .*?-----')
  $xml=if($m.Success){$m.Groups['xml'].Value}else{$Text}
  if(-not $xml -or -not $xml.Trim()){ throw "Read-DbgDump: empty input." }
  try{ [System.Management.Automation.PSSerializer]::Deserialize($xml) }catch{ throw "Read-DbgDump: deserialize failed: $($_.Exception.Message)" }
}

<#
.SYNOPSIS
Starts transcript logging in a timestamped file

.DESCRIPTION
Chooses a log root in this order:
  1. C:\IT\LOG
  2. C:\IT\LOGS
  3. System temp folder

Attempts to start transcript to the chosen file. If that fails, falls back to temp and retries.
Returns the chosen log path and whether transcript was successfully enabled.

.OUTPUTS
PSCustomObject with properties:
 - LogFile (string)
 - TranscriptEnabled (bool)
#>
function Start-WuTranscript {
    [CmdletBinding()]
    param()

    $logRoot = if (Test-Path 'C:\IT\LOG') { 'C:\IT\LOG' } elseif (Test-Path 'C:\IT\LOGS') { 'C:\IT\LOGS' } else { [System.IO.Path]::GetTempPath().TrimEnd('\') }
    $logName = 'WindowsUpdateHelper-{0}.log' -f (Get-Date -Format 'yyyy-MM-dd_HH.mm.ss')
    $LogFile = Join-Path $logRoot $logName
    $enabled = $false

    try {
        Start-Transcript -Path $LogFile -Force | Out-Null
        $enabled = $true
        Write-Host "Logging to file: $LogFile"
    } catch {
        Write-Host -ForegroundColor Yellow ("WARNING: Failed to start transcript at '{0}'. Error: {1}" -f $LogFile, $_.Exception.Message)

        $fallbackRoot = [System.IO.Path]::GetTempPath().TrimEnd('\')
        $fallbackFile = Join-Path $fallbackRoot ([System.IO.Path]::GetFileName($LogFile))
        if ($fallbackFile -ne $LogFile) {
            try {
                Start-Transcript -Path $fallbackFile -Append -Force | Out-Null
                $LogFile = $fallbackFile
                $enabled = $true
                Write-Host -ForegroundColor Yellow ("WARNING: Using fallback log file: {0}" -f $LogFile)
            } catch {
                Write-Host -ForegroundColor Yellow ("WARNING: Failed to start transcript fallback at '{0}'. Error: {1}" -f $fallbackFile, $_.Exception.Message)
            }
        }
    }

    [pscustomobject]@{ LogFile = $LogFile; TranscriptEnabled = $enabled }
}

function Get-DescrFromResultCode([int]$rc) {
  switch ($rc) {
    0 { 'NotStarted' }
    1 { 'InProgress' }
    2 { 'Succeeded' }
    3 { 'SucceededWithErrors' }
    4 { 'Failed' }
    5 { 'Aborted' }
    default { 'Unknown' }
  }
}

function Get-DescrFromHResult([int]$hr) {
  if ($hr -eq 0) { return 'No error' }
  try {
    $ex = [System.Runtime.InteropServices.Marshal]::GetExceptionForHR($hr)
    if ($ex -and $ex.Message) { return $ex.Message }
  } catch { }
  'error'
}

# -------------------------------------------------------------------------------------------------
# END
#       Generic Helper Functions
# -------------------------------------------------------------------------------------------------

<#
.SYNOPSIS
Registers a scheduled task that runs this script later to force a reboot.

.DESCRIPTION
Creates or replaces a scheduled task named
WindowsUpdateHelper-ForcedReboot.

The task is configured to run this script with internal reboot arguments.
If registration fails, no task is available for the forced reboot path.

.OUTPUTS
Boolean.
True when the task is registered.
False when registration is not completed.
#>
function Register-WuForcedRebootTask {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$ScriptPath,[Parameter(Mandatory=$true)][int]$Minutes,[Parameter(Mandatory=$true)][datetime]$ArmedAt)
  $taskName='WindowsUpdateHelper-ForcedReboot'
  if(-not $ScriptPath){ Write-Host -ForegroundColor Red "ERROR: Tried to schedule a forced reboot but ScriptPath is empty."; return $false }
  try{
    $psExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $armedAtText=$ArmedAt.ToString('s')
    $argLine='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$ScriptPath+'" -XXX_RebootNow -XXX_RebootArmedAt "'+$armedAtText+'"'
    $action=New-ScheduledTaskAction -Execute $psExe -Argument $argLine
    $runAt=(Get-Date).AddMinutes($Minutes)
    $trigger=New-ScheduledTaskTrigger -Once -At $runAt
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    return $true
  } catch {
    Write-Host -ForegroundColor Yellow ("ERROR: [ForcedReboot] Failed to register task '{0}': {1}" -f $taskName,$_.Exception.Message)
    return $false
  }
}

<#
.SYNOPSIS
Registers startup continuation state for a post-reboot rerun.

.DESCRIPTION
Writes a continuation flag file and creates or replaces a startup task named
WindowsUpdateHelper-ResumeAfterReboot.

The function can leave one of the two resources present when the other one
fails to be created.

.OUTPUTS
Boolean.
True when both the flag file and the startup task are created.
False otherwise.
#>
function Register-WuResumeAfterRebootTask {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$ScriptPath,[Parameter(Mandatory=$true)][string]$FlagFilePath)
  $taskName='WindowsUpdateHelper-ResumeAfterReboot'
  $okFlag=$false;$okTask=$false
  try{
    $now=Get-Date
    Set-Content -LiteralPath $FlagFilePath -Value $now.ToString('s') -Encoding ASCII -Force
    Write-Output ("[ResumeAfterReboot] Created flag file: {0} (timestamp {1})" -f $FlagFilePath,$now.ToString('s'))
    $okFlag=$true
  } catch {
    Write-Host -ForegroundColor Yellow ("ERROR: [ResumeAfterReboot] Failed to create flag file '{0}': {1}" -f $FlagFilePath,$_.Exception.Message)
  }
  try{
    $psExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argLine='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$ScriptPath+'" -XXX_ResumeAfterReboot'
    $action=New-ScheduledTaskAction -Execute $psExe -Argument $argLine
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Output ("[ResumeAfterReboot] Registered startup task '{0}' to continue Windows Update after reboot." -f $taskName)
    $okTask=$true
  } catch {
    Write-Host -ForegroundColor Yellow ("ERROR: [ResumeAfterReboot] Failed to register startup task '{0}': {1}" -f $taskName,$_.Exception.Message)
  }
  return ($okFlag -and $okTask)
}

<#
.SYNOPSIS
Builds the reboot/continuation decision object for the current run.

.OUTPUTS
Produces one psCustomObject:
  RebootPendingAtStart   : Pending reboot state before install work.
  RebootPendingAtEnd     : Pending reboot state at evaluation time.
  InstalledSomething     : True when at least one update installed.
  WuaRequestsReboot      : True when install results request reboot.
  RebootIsNeeded         : Script decision about reboot necessity.
  InitiateReboot         : Script decision to trigger reboot now.
  RebootAnyway           : Echo of input policy switch.
  XXX_ResumeAfterReboot  : Echo of internal continuation switch.
  BestToRerunAfterReboot : True when another run after reboot is advised.
  Has80240030            : True when any result has HResult 0x80240030.
  HasFailures            : True when any result failed or had errors.
  HasSuccesses           : True when any result succeeded.
  FailedOrErrorResults   : Subset of result objects with failures/errors.
  AllUpdateResultsCount  : Count of supplied result objects.
  ShutdownDelaySeconds   : Delay used by reboot request path.
  ForcedRebootMinutes    : Delay used by forced reboot task path.

.PARAMETER InstalledSomething
When set to True, reboot decisions may consider install outcomes.

.PARAMETER WuaRequestsReboot
When set to True, reboot decisions may mark reboot as needed.

.PARAMETER RebootPendingAtStart
Pending reboot state captured before installation activity.

.PARAMETER AllUpdateResults
Per-update result objects used for failure and rerun signals.

.PARAMETER Reboot
When set, reboot may be initiated when the plan marks reboot as needed;
otherwise a reboot request is not initiated unless RebootAnyway is set.

.PARAMETER RebootAnyway
When set, the plan marks reboot initiation regardless of need.

.PARAMETER XXX_ResumeAfterReboot
Internal continuation marker included in the plan object.
#>
function Get-WuRebootPlan {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][bool]$InstalledSomething,
    [Parameter(Mandatory=$true)][bool]$WuaRequestsReboot,
    [Parameter(Mandatory=$true)][bool]$RebootPendingAtStart,
    [Parameter()][AllowNull()][object[]]$AllUpdateResults,
    [switch]$Reboot,
    [switch]$RebootAnyway,
    [switch]$XXX_ResumeAfterReboot
  )
  $RebootPendingAtEnd=Test-RebootPending
  $rebootIsNeeded=$InstalledSomething -and ($WuaRequestsReboot -or $RebootPendingAtEnd)

  $failedOrErrorResults=@();$successfulResults=@()
  if($AllUpdateResults -and $AllUpdateResults.Count -gt 0){
    $failedOrErrorResults=$AllUpdateResults | Where-Object { $_.ResultCode -in @('Failed','SucceededWithErrors') }
    $successfulResults=$AllUpdateResults | Where-Object { $_.ResultCode -eq 'Succeeded' }
  }
  $has80240030=$false
  if($AllUpdateResults -and $AllUpdateResults.Count -gt 0){
    $has80240030=(($AllUpdateResults | Where-Object { $_.HResult -eq '0x80240030' } | Measure-Object).Count -gt 0)
  }
  $hasFailures=(@($failedOrErrorResults)).Count -gt 0
  $hasSuccesses=(@($successfulResults)).Count -gt 0

  $bestToRerunAfterReboot=$has80240030 -or (
    $InstalledSomething -and $hasSuccesses -and $hasFailures -and (
      ((-not $RebootPendingAtStart) -and $RebootPendingAtEnd) -or $WuaRequestsReboot
    )
  )

  $initiateReboot=$false
  if($RebootAnyway){ $initiateReboot=$true }
  else { $initiateReboot=($rebootIsNeeded -and ($Reboot -or $RebootAnyway)) }

  [pscustomobject]@{
    RebootPendingAtStart=[bool]$RebootPendingAtStart
    RebootPendingAtEnd=[bool]$RebootPendingAtEnd
    InstalledSomething=[bool]$InstalledSomething
    WuaRequestsReboot=[bool]$WuaRequestsReboot
    RebootIsNeeded=[bool]$rebootIsNeeded
    InitiateReboot=[bool]$initiateReboot
    RebootAnyway=[bool]$RebootAnyway
    XXX_ResumeAfterReboot=[bool]$XXX_ResumeAfterReboot
    BestToRerunAfterReboot=[bool]$bestToRerunAfterReboot
    Has80240030=[bool]$has80240030
    HasFailures=[bool]$hasFailures
    HasSuccesses=[bool]$hasSuccesses
    FailedOrErrorResults=$failedOrErrorResults
    AllUpdateResultsCount=(@($AllUpdateResults)).Count
    ShutdownDelaySeconds=60
    ForcedRebootMinutes=5
  }
}

<#
.SYNOPSIS
Applies a reboot plan and performs related user-visible actions.

.DESCRIPTION
Writes decision details to the host, may register continuation state for a
post-reboot rerun, and may schedule a forced reboot task.

When the plan requests reboot initiation, the function issues a reboot
request and may not return before process termination. If continuation or
forced reboot registration fails, the function continues and instructs the
user to rerun after reboot when needed.

.OUTPUTS
None.
#>
function Invoke-WuApplyRebootPlan {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)]$Plan,[Parameter()][AllowNull()][string]$ScriptPath,[Parameter(Mandatory=$true)][string]$FlagFilePath)

  $askUserToReRun=$false

  if($Plan.InitiateReboot -and $Plan.BestToRerunAfterReboot){
    if($Plan.XXX_ResumeAfterReboot){
      Write-Host -ForegroundColor Yellow "WARNING: We probably need to rerun after the reboot but we already did once. We will NOT rerun a 2nd time."
      $askUserToReRun=$true
    } elseif(-not $ScriptPath){
      Write-Host -ForegroundColor Red "ERROR: We probably need to rerun after the reboot but ScriptPath is not valid (maybe you dot-sourced this script?)"
      $askUserToReRun=$true
    } else {
      Write-Host "Scheduling a continuation of installations after the reboot" -ForegroundColor Magenta
      $ok=Register-WuResumeAfterRebootTask -ScriptPath $ScriptPath -FlagFilePath $FlagFilePath
      if(-not $ok){ $askUserToReRun=$true }
    }
  }

  Write-Host "Done." -ForegroundColor Cyan
  
  # ---- Raw state / inputs to decision (facts) ----
  Write-Host "  [Policy] -RebootAnyway: $($Plan.RebootAnyway)" -ForegroundColor DarkGray
  Write-Host "  [Policy] -XXX_ResumeAfterReboot: $($Plan.XXX_ResumeAfterReboot)" -ForegroundColor DarkGray
  Write-Host "  [State ] Windows reboot pending at start: $([bool]$Plan.RebootPendingAtStart)" -ForegroundColor DarkGray
  Write-Host "  [State ] Windows reboot pending now:      $([bool]$Plan.RebootPendingAtEnd)" -ForegroundColor DarkGray
  Write-Host "  [State ] Installer requested reboot now:  $([bool]$Plan.WuaRequestsReboot)" -ForegroundColor DarkGray
  Write-Host "  [Run   ] Update result objects produced:  $($Plan.AllUpdateResultsCount)" -ForegroundColor Cyan
  Write-Host "  [Run   ] Installed at least one update:   $([bool]$Plan.InstalledSomething)" -ForegroundColor Cyan
  # ---- Script decision (current logic / policy outcome) ----
  Write-Host "  [Decide] Script computed RebootIsNeeded:  $([bool]$Plan.RebootIsNeeded)" -ForegroundColor Cyan
  Write-Host "  [Decide] Script will initiate reboot:     $([bool]$Plan.InitiateReboot)" -ForegroundColor Cyan
  if($Plan.RebootIsNeeded){
    Write-Host "  [Note  ] Current policy says a reboot is needed to finish installations from this run." -ForegroundColor Yellow
  } else {
    Write-Host "  [Note  ] Current policy says no reboot is needed to finish installations from this run." -ForegroundColor Green
    if($Plan.RebootPendingAtEnd){
      Write-Host "  [Note  ] Windows still reports a pending reboot state (this may be from an earlier operation/run)." -ForegroundColor Yellow
    }
    if($Plan.RebootAnyway){
      Write-Host "  [Note  ] -RebootAnyway overrides the above and forces a reboot." -ForegroundColor Yellow
    }
  }
  # ---- Extra signals / diagnostics ----
  if(( -not $Plan.RebootPendingAtStart) -and $Plan.RebootPendingAtEnd){
    Write-Host "  [Signal] RebootPending changed from False to True during this run."
  }
  if($Plan.WuaRequestsReboot){
    Write-Host "  [Signal] At least one installation reported 'reboot required'."
  }
  if($Plan.InstalledSomething -and $Plan.HasSuccesses){
    Write-Host "  [Signal] At least one update installed successfully." -ForegroundColor Green
  }
  if($Plan.Has80240030){
    Write-Host "  [Signal] At least one update failed with 0x80240030 (reboot typically required before more installs can continue)." -ForegroundColor Yellow
  }
  if($Plan.HasFailures){
    Write-Host "  [Signal] At least one update failed to install." -ForegroundColor Yellow
    Write-DbgDump -Json -Label 'failedOrErrorResults' -Obj $Plan.FailedOrErrorResults
  }
  if($Plan.BestToRerunAfterReboot){
    Write-Host "  [Advice ] Script suggests running again after reboot." -ForegroundColor Yellow
  }
  if($askUserToReRun){
    Write-Host "*****************************************" -ForegroundColor Magenta
    Write-Host "* Please run me again after the reboot. *" -ForegroundColor Magenta
    Write-Host "*****************************************" -ForegroundColor Magenta
  }
  
  if($Plan.InitiateReboot){
    Write-Host "-----------------------" -ForegroundColor Magenta
    Write-Host ("REBOOTING in {0} seconds" -f $Plan.ShutdownDelaySeconds) -ForegroundColor Magenta
    Write-Host "-----------------------" -ForegroundColor Magenta
    Write-Host "To abort, run:"
    if($ScriptPath){ Write-Host ('& "'+$ScriptPath+'" -AbortReboot') -ForegroundColor White }
    else { Write-Host "shutdown.exe /a" -ForegroundColor White }

    if($ScriptPath){
      Write-Host ("Scheduling a forced reboot in {0} minutes (just in case the normal reboot request is blocked)." -f $Plan.ForcedRebootMinutes)
      [void](Register-WuForcedRebootTask -ScriptPath $ScriptPath -Minutes $Plan.ForcedRebootMinutes -ArmedAt (Get-Date))
    } else {
      Write-Host -ForegroundColor Yellow "WARNING: Skipping forced reboot safety-net because ScriptPath is not available."
    }

    if($script:TranscriptEnabled){ try{ Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false }catch{} }
    Start-Sleep -Seconds 1
    shutdown.exe /r /t $Plan.ShutdownDelaySeconds /c "WindowsUpdatesHelper.ps1: reboot after installing Windows Updates (Not forced)" /d p:0:0
  } else {
    if($Plan.RebootIsNeeded){
      Write-Host "****************************************" -ForegroundColor Magenta
      Write-Host "* Please reboot to finish installation *" -ForegroundColor Magenta
      Write-Host "****************************************" -ForegroundColor Magenta
    }
  }
}

# -------------------------------------------------------------------------------------------------
# START
#       Function(s) that implememt the mode of operation:
#       "History"/"ShowHistory" (where we show windows updates history)
# -------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
Lists Windows Update history entries from the local update history store.

.DESCRIPTION
Returns update history rows after optional date and Defender-definition
filtering.

The scan is limited by MaxScanEntries. Result count is limited by MaxResults
unless MaxResults is 0 or negative.

.OUTPUTS
Produces one psCustomObject per matching history entry:
  Date       : History entry date/time.
  KB         : KB number parsed from the title, or empty string.
  Title      : History entry title text.
  Operation  : Operation code with text label.
  ResultCode : Result code with text label.
  HResult    : HResult with text description.

.PARAMETER MaxResults
Maximum number of matching rows to return. Use 0 or a negative value to
return all matches found within MaxScanEntries.

.PARAMETER LastDays
When set, only rows on or after now minus this number of days are returned.

.PARAMETER IncludeAV
When set, Defender definition entries are included; otherwise they are
excluded.

.PARAMETER MaxScanEntries
Maximum number of history rows to scan. Must be 1 or greater.

.EXAMPLE
Get-WindowsUpdateHistory -LastDays 14 -MaxResults 100
#>
function Get-WindowsUpdateHistory {
  [CmdletBinding()]
  param(
    [int]$MaxResults = 30,
    [int]$LastDays,
    [switch]$IncludeAV,
    [int]$MaxScanEntries = 10000
  )

  function _OpText([int]$op) {
    switch ($op) {
      1 { 'Install' }
      2 { 'Uninstall' }
      default { 'unknown' }
    }
  }

  if ($MaxScanEntries -lt 1) { throw "MaxScanEntries must be >= 1." }

  $cut = $null
  if ($PSBoundParameters.ContainsKey('LastDays')) {
    $cut = (Get-Date).AddDays(-1 * $LastDays)
  }

  $batchSize = 100
  $start = 0
  $scanned = 0
  $collected = New-Object System.Collections.Generic.List[object]

  $s = New-Object -ComObject Microsoft.Update.Session
  $searcher = $s.CreateUpdateSearcher()

  while ($scanned -lt $MaxScanEntries) {
    $remaining = $MaxScanEntries - $scanned
    $take = if ($remaining -lt $batchSize) { $remaining } else { $batchSize }

    $batch = $searcher.QueryHistory($start, $take)
    if (-not $batch -or $batch.Count -eq 0) { break }

    $scanned += $batch.Count
    $start += $batch.Count

    if ($cut) {
      $batch = $batch | Where-Object { $_.Date -ge $cut }
    }

    if (-not $IncludeAV) {
      $batch = $batch | Where-Object { $_.Title -notmatch 'KB2267602' }
    }

    foreach ($e in $batch) { [void]$collected.Add($e) }

    if ($MaxResults -gt 0 -and $collected.Count -ge $MaxResults) { break }

    if ($cut) {
      $oldestInReturned = ($searcher.QueryHistory($start-1,1) | Select-Object -First 1).Date
      if ($oldestInReturned -and $oldestInReturned -lt $cut) { break }
    }

    if ($batch.Count -lt $take) { break }
  }

  $final = $collected
  if ($MaxResults -gt 0 -and $final.Count -gt $MaxResults) {
    $final = $final | Select-Object -First $MaxResults
  }

  $final | Sort-Object Date | Select-Object `
    @{n='Date';e={$_.Date}},
    @{n='KB';e={ if ($_.Title -match '(KB\d{5,16})') { $matches[1] } else { '' } }},
    @{n='Title';e={$_.Title}},
    @{n='Operation';e={ "$($_.Operation)($(_OpText $_.Operation))" }},
    @{n='ResultCode';e={ "$($_.ResultCode)($(Get-DescrFromResultCode $_.ResultCode))" }},
    @{n='HResult';e={ "$($_.HResult)($(Get-DescrFromHResult $_.HResult))" }}
}
# -------------------------------------------------------------------------------------------------
# END
#       Function(s) that implememt the mode of operation:
#       "History"/"ShowHistory" (where we show windows updates history)
# -------------------------------------------------------------------------------------------------

# -------------------------------------------------------------------------------------------------
# START
#       Function(s) that implememt the mode of operation:
#       "Logs"/"ListRecentLogs" (where we list log files)
# -------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
Finds this script's transcript log files in known log locations.

.DESCRIPTION
Searches the configured log locations and returns files matching the script
log filename pattern, sorted by LastWriteTime ascending.

Listing failures in one location do not stop listing from other locations.
If no matching files are found, the function writes a host warning.

.OUTPUTS
Produces FileInfo objects sorted by LastWriteTime (oldest to newest).

.PARAMETER RecentCount
Maximum number of files returned when All is not set.

.PARAMETER All
When set, returns all matching files found; otherwise returns only the most
recent RecentCount files.
#>
function Get-WindowsUpdateHelperLogFiles {
    param([int]$RecentCount=10,[switch]$All)
    $roots=@()
    if(Test-Path 'C:\IT\LOG'){ $roots+='C:\IT\LOG' }
    if(Test-Path 'C:\IT\LOGS'){ $roots+='C:\IT\LOGS' }
    $tmp=[System.IO.Path]::GetTempPath().TrimEnd('\')
    if(Test-Path $tmp){ $roots+=$tmp }
    $files=@()
    foreach($r in $roots){
        try {
            $files += Get-ChildItem -LiteralPath $r -Filter 'WindowsUpdateHelper-*.log' -File -ErrorAction Stop
        } catch {
            Write-Host -ForegroundColor Yellow ("WARNING: Could not list log files in '{0}': {1}" -f $r, $_.Exception.Message)
        }
    }
    $files = $files | Sort-Object LastWriteTime
    if(-not $All){ $files = $files | Select-Object -Last $RecentCount }
    if(-not $files -or $files.Count -eq 0){ Write-Host -ForegroundColor Yellow "No WindowsUpdateHelper log files found in: $($roots -join ', ')" }
    $files
}
# -------------------------------------------------------------------------------------------------
# END
#       Function(s) that implememt the mode of operation:
#       "Logs"/"ListRecentLogs" (where we list log files)
# -------------------------------------------------------------------------------------------------


# -------------------------------------------------------------------------------------------------
# START
#       Function(s) that implememts -InstallOptional
# -------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
Downloads and installs one update selected by update identifier.

.DESCRIPTION
Searches for applicable updates, locates the requested update ID, downloads
it when needed, and installs it.

The function performs update installation work and writes status lines to the
host. A terminating error can occur after partial progress, including cases
where the target update was downloaded but not installed.

.OUTPUTS
None.

.PARAMETER UpdateId
Identifier of the target update to install. Braced and unbraced GUID text is
accepted.

.PARAMETER Interactive
When set, installation may present prompts; otherwise quiet installation is
requested.

.PARAMETER IncludeNonOptional
When set, the search also includes non-optional updates; otherwise only
optional updates are considered.

.EXAMPLE
Invoke-WuInstallOptionalByUpdateId -UpdateId $id -Interactive
#>
function Invoke-WuInstallOptionalByUpdateId {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$UpdateId,
    [switch]$Interactive,
    [switch]$IncludeNonOptional
  )

  function _NormGuid([string]$s){
    if(-not $s){ return '' }
    $t=$s.Trim()
    if($t.StartsWith('{') -and $t.EndsWith('}')){ $t=$t.Substring(1,$t.Length-2) }
    $t.ToLowerInvariant()
  }

  function _TryReleaseCom($o){ if($null -eq $o){return}; try{[void][Runtime.InteropServices.Marshal]::ReleaseComObject($o)}catch{} }

  Assert-Elevated
  $want=_NormGuid $UpdateId

  $session=$null;$searcher=$null;$results=$null
  $downloader=$null;$installer=$null
  try{
    $session=New-Object -ComObject Microsoft.Update.Session
    $searcher=$session.CreateUpdateSearcher()
    $searcher.Online=$true
    $searcher.ServerSelection=2  # ssWindowsUpdate

    $base="IsInstalled=0 and IsHidden=0"
    $criteria=if($IncludeNonOptional){
      "$base and (DeploymentAction='OptionalInstallation' or DeploymentAction='Installation')"
    } else {
      "$base and DeploymentAction='OptionalInstallation'"
    }

    Write-Host ("$(Get-Date) Searching WU with criteria: {0}" -f $criteria)
    $results=$searcher.Search($criteria)

    if(-not $results -or $results.Updates.Count -lt 1){
      throw "No matching updates returned by WUA for that criteria."
    }

    $uMatch=$null
    for($i=0;$i -lt $results.Updates.Count;$i++){
      $u=$results.Updates.Item($i)
      $id=_NormGuid ([string]$u.Identity.UpdateID)
      if($id -eq $want){ $uMatch=$u; break }
    }

    if(-not $uMatch){
      $avail=@()
      for($i=0;$i -lt $results.Updates.Count;$i++){
        $u=$results.Updates.Item($i)
        $avail += ("- {0}  {1}" -f $u.Title,([string]$u.Identity.UpdateID))
      }
      throw ("UpdateID not found among returned updates.`nAvailable:`n{0}" -f ($avail -join "`n"))
    }

    Write-Host ("$(Get-Date) Found update: {0}" -f $uMatch.Title)
	if ($uMatch.InstallationBehavior.CanRequestUserInput) {
      Write-Host "`nThe installation may need your feedback. Be available.`n"  -ForegroundColor Magenta
	}
    if(-not $uMatch.EulaAccepted){
      try{ $uMatch.AcceptEula() } catch { throw ("AcceptEULA failed: {0}" -f $_.Exception.Message) }
    }
    if(-not $uMatch.IsDownloaded){
      Write-Host "$(Get-Date) Downloading..."
      $dlColl=New-Object -ComObject Microsoft.Update.UpdateColl
      [void]$dlColl.Add($uMatch)

      $downloader=$session.CreateUpdateDownloader()
      $downloader.Priority=3
      $downloader.Updates=$dlColl

      $dr=$downloader.Download()
      $ur=$dr.GetUpdateResult(0)
      if(-not $uMatch.IsDownloaded){
          throw ("Download did not result in IsDownloaded=True. ResultCode={0} HResult=0x{1:X8}" -f $dr.ResultCode, $ur.HResult)
      }
    } else {
      Write-Host "Already downloaded." -ForegroundColor DarkGray
    }

    $instColl=New-Object -ComObject Microsoft.Update.UpdateColl
    [void]$instColl.Add($uMatch)

    $installer=$session.CreateUpdateInstaller()
    $installer.Updates=$instColl
    $installer.ForceQuiet = (-not $Interactive)
    $installer.AllowSourcePrompts = [bool]$Interactive

    Write-Host "$(Get-Date) Installing..."
    $ir=$installer.Install()
    $one=$ir.GetUpdateResult(0)

    $obj=[pscustomobject]@{
      Title          = $uMatch.Title
      UpdateID       = [string]$uMatch.Identity.UpdateID
      ResultCode     = [int]$ir.ResultCode
      HResult        = ('0x{0:X8}' -f $one.HResult)
      RebootRequired = [bool]$ir.RebootRequired -or [bool]$one.RebootRequired
    }

    Write-Host "ResultCode = $($obj.ResultCode)($(Get-DescrFromResultCode $obj.ResultCode))"
    Write-Host "HResult    = $($obj.HResult)($(Get-DescrFromHResult $obj.HResult))"
    if($obj.RebootRequired){
      Write-Host "****************************************" -ForegroundColor Magenta
      Write-Host "* Please reboot to finish installation *" -ForegroundColor Magenta
      Write-Host "****************************************" -ForegroundColor Magenta
    }
	  
    # return $obj
  }
  finally{
    _TryReleaseCom $installer
    _TryReleaseCom $downloader
    _TryReleaseCom $results
    _TryReleaseCom $searcher
    _TryReleaseCom $session
  }
}
# -------------------------------------------------------------------------------------------------
# END
#       Function(s) that implememts -InstallOptional
# -------------------------------------------------------------------------------------------------


# -------------------------------------------------------------------------------------------------
# START
#       Function(s) that implememt the NORMAL mode of operation
#       (where we install updates)
# -------------------------------------------------------------------------------------------------
function Format-WuResultCodeName([int]$code){
    switch ($code) {
        0 {'NotStarted'}
        1 {'InProgress'}
        2 {'Succeeded'}
        3 {'SucceededWithErrors'}
        4 {'Failed'}
        5 {'Aborted'}
        default { "$code" }
    }
}

<#
.SYNOPSIS
Runs install mode for this script, including search, optional download,
installation, and reboot handling.

.DESCRIPTION
High-level orchestrator for the Windows Update helper. In order, it:
 - Handles "continue after reboot" mode (flag cleanup + optional forced reboot switch)
 - Creates WUA session/searcher and performs update search (online only when -Download is used)
 - Partitions updates into already-downloaded vs not-downloaded (and filters out user-input updates unless -Interactive)
 - Downloads not-downloaded updates when -Download is set
 - Builds the final install pool from the same update objects (post-download state)
 - Accepts EULAs and splits updates into normal vs exclusive handling
 - Installs via Invoke-WuInstallPart
 - Decides and performs reboot/continuation via Invoke-WuRebootAndContinuePart

.OUTPUTS
None.

.PARAMETER Download
When set, online search and download are included before installation;
otherwise only already-downloaded updates are considered for install.

.PARAMETER Reboot
When set, the run may request reboot when the final plan marks reboot as
needed; otherwise reboot is not requested unless RebootAnyway is set.

.PARAMETER RebootAnyway
When set, the run may request reboot regardless of whether updates require
it.

.PARAMETER XXX_ResumeAfterReboot
Internal continuation switch for startup reruns after reboot.

.PARAMETER Interactive
When set, updates that may require user input are included; otherwise they
are skipped.

.EXAMPLE
Invoke-InstallPhase -Download -Reboot

.NOTES
Uses $script:AllUpdateResults as an accumulation store for per-update install results.
#>
function Invoke-InstallPhase {
    [CmdletBinding()]
    param(
        [switch]$Download,
        [switch]$Reboot,
        [switch]$RebootAnyway,
        [switch]$XXX_ResumeAfterReboot,
        [switch]$Interactive
    )

    # ---- START of DEBUG DUMP helpers (CLIXML, no gzip/b64) ----
    function Get-DbgOutSafe { param([scriptblock]$Sb) try { & $Sb } catch { "[EXCEPTION] $($_.Exception.Message)" } }
    function Get-DbgUpdateSnapshot {
        [CmdletBinding()]
        param([Parameter(Mandatory=$true)]$Updates)
        try {
            if($null -eq $Updates){ return @() }

            # $Updates is an array of update-objects
            if($Updates -is [System.Array]){
                $acc=@()
                foreach($x in $Updates){ $acc += (Get-DbgUpdateSnapshot -Updates $x) }
                return $acc
            }

            # $Updates is a Microsoft.Update.UpdateColl
            # (It has a .Count property and each update is stored in .Item(i))
            $hasCount = ($Updates -isnot [string]) -and ($Updates.PSObject.Properties.Name -contains 'Count')
            $hasItem  = ($Updates -isnot [string]) -and ($Updates.PSObject.Methods.Name -contains 'Item')
            if($hasCount -and $hasItem){
                $acc=@()
                for($i=0; $i -lt $Updates.Count; $i++){
                    $acc += (Get-DbgUpdateSnapshot -Updates ($Updates.Item($i)))
                }
                return $acc
            }

            # $Updates is a single update-object from a Microsoft.Update.UpdateColl collection
            $u=$Updates
            $kbs=@()
            $kbIds = Get-DbgOutSafe { $u.KBArticleIDs }
            if($kbIds -and $kbIds -isnot [string]){
                for($j=0; $j -lt $kbIds.Count; $j++){ $kbs += $kbIds.Item($j) }
            }
            [pscustomobject]@{
                Title        = Get-DbgOutSafe { $u.Title }
                UpdateID     = Get-DbgOutSafe { $u.Identity.UpdateID }
                KBs          = ($kbs -join ',')
                IsDownloaded = Get-DbgOutSafe { [bool]$u.IsDownloaded }
                EulaAccepted = Get-DbgOutSafe { [bool]$u.EulaAccepted }
                UserInput    = Get-DbgOutSafe { [bool]$u.InstallationBehavior.CanRequestUserInput }
                Exclusive    = Get-DbgOutSafe { [bool]$u.InstallationBehavior.RequiresExclusiveHandling }
                MaxDLSize    = Get-DbgOutSafe {
                              $vals=@()
                              $max=[decimal]$u.MaxDownloadSize
                              if($max -gt 0){ $vals += $max }

                              $recMb=[decimal]$u.RecommendedHardDiskSpace
                              if($recMb -gt 0){ $vals += ($recMb * 1MB) }  # MB -> bytes

                              if($vals.Count){ ($vals | Measure-Object -Minimum).Minimum } else { $null }
                }               
                MinDLSize    = Get-DbgOutSafe { $u.MinDownloadSize }
                Type 		 = Get-DbgOutSafe {switch ([int]$u.Type) { 1{'1(Software)'} 2{'2(Driver)'} default{[string]$u.Type} }}
            }
        } catch {
            Write-Host -ForegroundColor Red "Get-DbgUpdateSnapshot exception: $($_.Exception.Message)"
            return @()
        }
    }
    function Get-DbgInstallResultSnapshot {
        [CmdletBinding()]
        param([Parameter(Mandatory=$true)]$InstallResult,[int]$ExpectedCount=-1)
        try {
            $items=@()
            $n = $ExpectedCount
            if($n -lt 0){
                $n = Get-DbgOutSafe { $InstallResult.Updates.Count }
                if($n -is [string]){ $n = 0 }
            }
            for($i=0; $i -lt $n; $i++){
                try{
                    $ur = $InstallResult.GetUpdateResult($i)
                    $items += [pscustomobject]@{
                        Index          = $i
                        ResultCode     = Get-DbgOutSafe { (Format-WuResultCodeName $ur.ResultCode) }
                        HResult        = Get-DbgOutSafe { ('0x{0:X8}' -f $ur.HResult) }
                        RebootRequired = Get-DbgOutSafe { [bool]$ur.RebootRequired }
                    }
                } catch {
                    $items += [pscustomobject]@{ Index=$i; Exception=$_.Exception.Message }
                }
            }
            [pscustomobject]@{
                ResultCode      = Get-DbgOutSafe { (Format-WuResultCodeName $InstallResult.ResultCode) }
                RebootRequired  = Get-DbgOutSafe { [bool]$InstallResult.RebootRequired }
                ExpectedCount   = $ExpectedCount
                UpdateResults   = $items
            }
        } catch {
            Write-Host -ForegroundColor Red "Get-DbgInstallResultSnapshot exception: $($_.Exception.Message)"
            [pscustomobject]@{
                ResultCode      = $null
                RebootRequired  = $null
                ExpectedCount   = $null
                UpdateResults   = $null
            }
        }
    }
    function Get-DbgDownloadResultSnapshot {
        [CmdletBinding()]
        param([Parameter(Mandatory=$true)]$DownloadResult,[int]$ExpectedCount=-1)
        try {
            $items=@()
            $n = $ExpectedCount
            if($n -lt 0){ $n = 0 }
            for($i=0; $i -lt $n; $i++){
                try{
                    $ur = $DownloadResult.GetUpdateResult($i)
                    $items += [pscustomobject]@{
                        Index      = $i
                        ResultCode = Get-DbgOutSafe { (Format-WuResultCodeName $ur.ResultCode) }
                        HResult    = Get-DbgOutSafe { ('0x{0:X8}' -f $ur.HResult) }
                    }
                } catch {
                    $items += [pscustomobject]@{ Index=$i; Exception=$_.Exception.Message }
                }
            }
            [pscustomobject]@{
                ResultCode    = Get-DbgOutSafe { (Format-WuResultCodeName $DownloadResult.ResultCode) }
                HResult       = Get-DbgOutSafe { ('0x{0:X8}' -f $DownloadResult.HResult) }
                ExpectedCount = $ExpectedCount
                UpdateResults = $items
            }
        } catch {
            Write-Host -ForegroundColor Red "Get-DbgDownloadResultSnapshot exception: $($_.Exception.Message)"
            [pscustomobject]@{
                ResultCode    = $null
                HResult       = $null
                ExpectedCount = $null
                UpdateResults = $null
            }
        }
    }
    # ---- END of DEBUG DUMP helpers (CLIXML, no gzip/b64) ----

    function Invoke-WuaInstallWithProgress {
        <#
        .SYNOPSIS
          Installs Windows Updates via the WUA COM API while providing visible progress/heartbeats.

        .DESCRIPTION
          Wraps a WUA UpdateInstaller installation in a polling loop that periodically queries the WUA job
          for progress and prints indications of activity (Write-Progress plus periodic Write-Host heartbeats).
          Designed for long-running installs where the console would otherwise show only a "blinking cursor".

          Key behavior:
            - Prefers BeginInstall()/EndInstall() so we can poll progress during installation.
            - Falls back to synchronous Install() if BeginInstall() is unavailable/fails.
            - Tracks current update index/title and percent complete and emits "now working on ..." transitions.
            - Supports optional timeouts:
                * MaxMinutes: overall maximum wall-clock time for the install operation.
                * NoProgressMinutes: abort if update index/percent do not change for too long.
            - Supports external cancellation:
                * CancelFilePath: abort if a file appears.
                * ShouldStop: scriptblock that can signal cancellation (returns $true).
            - Attempts to be resilient in headless/limited hosts:
                * Can disable Write-Progress automatically if it throws.
                * Releases COM progress/job objects best-effort to reduce long-run COM wrapper buildup.

        .PARAMETER Installer
          A Microsoft.Update.Installer / UpdateInstaller COM object configured with .Updates and options
          (ForceQuiet, AllowSourcePrompts, etc.) prior to calling this function.

        .PARAMETER Updates
          The updates collection being installed (typically Microsoft.Update.UpdateColl). Used to snapshot
          identifying metadata (Title/UpdateID/KBs) so the progress loop avoids repeated COM property access.

        .PARAMETER Activity
          The activity text shown by Write-Progress.

        .PARAMETER ProgressId
          The Write-Progress Id used for updates to the same progress record.

        .PARAMETER PollMilliseconds
          How often to poll the WUA job for progress. Lower values are more responsive but increase overhead.

        .PARAMETER HeartbeatSeconds
          How often to emit a "still working..." line even when progress does not visibly change.

        .PARAMETER MaxMinutes
          Optional overall timeout. 0 means no overall timeout.

        .PARAMETER NoProgressMinutes
          Optional "stalled progress" timeout. 0 means no no-progress timeout.

        .PARAMETER CancelFilePath
          Optional "break-glass" cancellation: if this file exists, the function aborts the install.

        .PARAMETER ShouldStop
          Optional scriptblock to evaluate periodically. If it returns $true, the function aborts the install.

        .PARAMETER NoProgressBar
          If set, suppresses Write-Progress and relies on heartbeats/host output only.

        .OUTPUTS
          Returns the WUA installation result object (the same type returned by UpdateInstaller.Install()).

        .NOTES
          This function performs real installation work. On error/timeout/cancel it may request abort of the
          WUA job and then rethrows the exception so callers see a normal PowerShell error/stack trace.
        #>
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)]$Installer,
        [Parameter(Mandatory=$true)]$Updates,
        [string]$Activity='Installing Windows Updates',
        [int]$ProgressId=1,
        [int]$PollMilliseconds=800,
        [int]$HeartbeatSeconds=30,
        [int]$MaxMinutes=0,
        [int]$NoProgressMinutes=20,
        [string]$CancelFilePath='',
        [scriptblock]$ShouldStop=$null,
        [switch]$Interactive,
        [switch]$NoProgressBar
      )

      function Get-WuCount($c){ if($null -eq $c){0}else{try{[int]$c.Count}catch{try{[int]$c.Length}catch{0}}} }
      function Get-WuItem($c,[int]$i){ if($null -eq $c){$null}else{try{$c.Item($i)}catch{try{$c[$i]}catch{$null}}} }
      function Try-ReleaseCom($o){ if($null -eq $o){return}; try{[void][Runtime.InteropServices.Marshal]::ReleaseComObject($o)}catch{} }

      $count=Get-WuCount $Updates
      $countSafe=[math]::Max($count,1)

      $snap=@()
      $atLeastOneMayNeedUserInput=$false
      if($count -gt 0){
        for($i=0;$i -lt $count;$i++){
          $u=Get-WuItem $Updates $i
          $title='(unknown)';$id='(unknown)'
          if($u){
            try{$title=[string]$u.Title}catch{}
            try{$id=[string]$u.Identity.UpdateID}catch{}
            try{
                if ([bool]$u.InstallationBehavior.CanRequestUserInput) {$atLeastOneMayNeedUserInput=$true}
            } catch {
                $atLeastOneMayNeedUserInput=$true
            }
          }
          $snap += [pscustomobject]@{Index=$i;Title=$title;UpdateID=$id}
        }
      }

      $job=$null
      try{ 
        $job = $Installer.BeginInstall($null,$null) 
        Write-Host 'Debug: Used `$Installer.BeginInstall($null,$null)` to get progress bar' -ForegroundColor DarkGray
      }catch{ 
        try{ $job = $Installer.BeginInstall() }catch{} 
        Write-Host 'Debug: Used `$Installer.BeginInstall()` to get progress bar' -ForegroundColor DarkGray
      }

      if(-not $job){ 
        Write-Host "Notice: can not display update progress; will only anounce installation completion."
        if ($Interactive -and $atLeastOneMayNeedUserInput) {
            Write-Host -ForegroundColor Yellow "Notice: This update _may_ present GUI prompts, be ready to respond to them."
        }
        $result = $Installer.Install() 
        Write-Host "Installation completed."
        return $result
      }

      $sw=[Diagnostics.Stopwatch]::StartNew()
      $hb=[Diagnostics.Stopwatch]::StartNew()
      $lastSignal=Get-Date

      $spin=@('|','/','-','\');$spinI=0
      $lastIdx=$null;$lastPct=$null;$curTitle=''
      $canProgress=(-not $NoProgressBar)

      try {
        while($true){
          if($CancelFilePath -and (Test-Path -LiteralPath $CancelFilePath)){ throw ("Cancel requested (file exists): {0}" -f $CancelFilePath) }
          if($ShouldStop){ if(& $ShouldStop){ throw "Cancel requested (ShouldStop returned true)" } }

          $done=$false
          try{ $done=[bool]$job.IsCompleted; $lastSignal=Get-Date }catch{ $done=$false }
          if($done){ break }

          if($MaxMinutes -gt 0 -and $sw.Elapsed.TotalMinutes -ge $MaxMinutes){
            throw ("Timed out after {0} minute(s). Last known: {1}% update {2}/{3} '{4}'" -f $MaxMinutes,($lastPct -as [string]),([math]::Min((($lastIdx -as [int]) + 1),$countSafe)),$countSafe,$curTitle)
          }

          $p=$null
          $gotProgress=$false
          try{ $p=$job.GetProgress(); $gotProgress=$true; $lastSignal=Get-Date }catch{ $gotProgress=$false }

          if($NoProgressMinutes -gt 0){
            $mins=((Get-Date) - $lastSignal).TotalMinutes
            if($mins -ge $NoProgressMinutes){
              throw ("No signal from WUA job for {0} minute(s). Last known: {1}% update {2}/{3} '{4}'" -f $NoProgressMinutes,($lastPct -as [string]),([math]::Min((($lastIdx -as [int]) + 1),$countSafe)),$countSafe,$curTitle)
            }
          }

          if($gotProgress -and $p){
            $idx=0;$pct=0
            try{ $idx=[int]$p.CurrentUpdateIndex }catch{ $idx=0 }
            try{ $pct=[int]$p.PercentComplete }catch{ $pct=0 }

            if($pct -lt 0){$pct=0}; if($pct -gt 100){$pct=100}
            if($idx -lt 0){$idx=0}
            if($count -gt 0 -and $idx -ge $count){$idx=$count-1}

            if($null -eq $lastIdx -or $idx -ne $lastIdx){
              $curTitle=''
              if($count -gt 0 -and $idx -ge 0 -and $idx -lt $snap.Count){ $curTitle=[string]$snap[$idx].Title }
              if($curTitle){ Write-Host ("[Install] Now working on {0}/{1}: {2}" -f ([math]::Min($idx+1,$countSafe)),$countSafe,$curTitle) }
              $lastIdx=$idx
            }
            $lastPct=$pct

            if($canProgress){
              try{
                Write-Progress -Id $ProgressId -Activity $Activity -Status ("{0}/{1} {2}" -f ([math]::Min($lastIdx+1,$countSafe)),$countSafe,$curTitle) -PercentComplete $pct
              } catch { $canProgress=$false }
            }
          } else {
            $spinCh=$spin[$spinI % $spin.Count];$spinI++
            if($canProgress){
              try{ Write-Progress -Id $ProgressId -Activity $Activity -Status ("working... {0}" -f $spinCh) -PercentComplete (if($lastPct -is [int]){$lastPct}else{0}) }catch{ $canProgress=$false }
            }
          }

          if($hb.Elapsed.TotalSeconds -ge $HeartbeatSeconds){
            $pctText=if($lastPct -is [int]){"$lastPct%"}else{"?"}
            $idxText=if($lastIdx -is [int]){ "{0}/{1}" -f ([math]::Min($lastIdx+1,$countSafe)),$countSafe }else{ "?/$countSafe" }
            Write-Host ("[Install] still working... {0} (update {1})" -f $pctText,$idxText)
            $hb.Restart()
          }

          Try-ReleaseCom $p
          Start-Sleep -Milliseconds ([math]::Max($PollMilliseconds,250))
        }

        if($canProgress){ try{ Write-Progress -Id $ProgressId -Activity $Activity -Completed }catch{} }
        try { return $Installer.EndInstall($job) } catch { Write-Host -ForegroundColor Yellow ("EndInstall failed: {0}" -f $_.Exception.Message); throw }
      } catch {
        if($canProgress){ try{ Write-Progress -Id $ProgressId -Activity $Activity -Completed }catch{} }
        try{ $job.RequestAbort() | Out-Null }catch{}
        throw
      } finally {
        Try-ReleaseCom $job
      }
    }

    function Invoke-WuInstallPart {
        <#
        .SYNOPSIS
          Orchestrates the installation of updates

        .DESCRIPTION
          Orchestrates installation for two groups of already-downloaded updates:
            - NonExclusive: a WUA UpdateColl of non-exclusive updates installed as a single batch
            - Exclusive: an array of exclusive-handling updates installed individually

          Returns only the "facts" needed by later stages (reboot/continue logic)
          Detailed per-update results are accumulated in $script:AllUpdateResults.

        .PARAMETER Session
          A Microsoft.Update.Session COM object used for creating installers.

        .PARAMETER NonExclusive
          Microsoft.Update.UpdateColl containing non-exclusive (batchable) downloaded updates.

        .PARAMETER Exclusive
          object[] containing updates that require exclusive handling (installed one at a time).

        .PARAMETER Interactive
          Enables interactive installation behavior (see Invoke-WuaInstallBatch).

        .OUTPUTS
          PSCustomObject with properties:
            - InstalledSomething (bool)
            - WuaRequestsReboot  (bool)

        .NOTES
          Does not perform search or download; expects updates to already be downloaded.
        #>
        [CmdletBinding()]
        param(
          [Parameter(Mandatory=$true)]$Session,
          [Parameter()][AllowNull()]$NonExclusive,
          [Parameter()][AllowNull()]$Exclusive,
          [switch]$Interactive
        )

        function Invoke-WuaInstallBatch {
            <#
            .SYNOPSIS
              Installs a batch of Windows Updates using the WUA COM API.

            .DESCRIPTION
              Takes an UpdateColl (Microsoft.Update.UpdateColl) and installs it using a WUA UpdateInstaller created
              from the provided Microsoft.Update.Session.

              For each update, emits a human-readable per-update line and also constructs structured result objects.
              Appends those per-update result objects into $script:AllUpdateResults for later reboot/continuation logic.

            .PARAMETER WuaUpdateCol
              The WUA UpdateColl to install (Microsoft.Update.UpdateColl). Must contain one or more updates.

            .PARAMETER Session
              A Microsoft.Update.Session COM object used to create the UpdateInstaller.

            .PARAMETER Interactive
              When set, allows user interaction/source prompts (ForceQuiet off, AllowSourcePrompts on).
              When not set, runs silently (ForceQuiet on, no prompts).

            .OUTPUTS
              PSCustomObject with properties:
                - OverallResultCode   (numeric WUA overall result)
                - RebootRequired      (bool)
                - UpdateResults       (object[] per-update result objects)

            .NOTES
              Side effects:
                - Installs updates
                - Adds result objects to $script:AllUpdateResults
            #>
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$true)]$WuaUpdateCol,
                [Parameter(Mandatory=$true)]$Session,
                [switch]$Interactive
            )

            if (-not $WuaUpdateCol -or $WuaUpdateCol.Count -eq 0) { return $null }

            Write-DbgDump -Json -Label 'InstallBatch.Inputs' -Obj ([pscustomobject]@{
                UpdateCount = $WuaUpdateCol.Count
                Interactive = [bool]$Interactive
                UpdatesSnap = (Get-DbgUpdateSnapshot $WuaUpdateCol)
            })

            $inst = $Session.CreateUpdateInstaller()
            $inst.ForceQuiet = (-not $Interactive)
            $inst.AllowSourcePrompts = [bool]$Interactive
            $inst.Updates = $WuaUpdateCol

            if(Test-IsSystemAccount){
                # Blocking call without progress indication (but simple and robust)
                $r = $inst.Install()
            } else {
                # Async call with progress (but complicated and possibly fragile)
                $r = Invoke-WuaInstallWithProgress -Installer $inst -Updates $WuaUpdateCol -Interactive:$Interactive
            }

            Write-DbgDump -Json -Label 'InstallBatch.InstallResult.PreLoopSnapshot' -Obj ([pscustomobject]@{
                UpdateCount = $WuaUpdateCol.Count
                InstallResultSnapshot = (Get-DbgInstallResultSnapshot -InstallResult $r -ExpectedCount $WuaUpdateCol.Count)
            })

            $results = @()
            for ($i=0; $i -lt $WuaUpdateCol.Count; $i++) {
                $u = $WuaUpdateCol.Item($i)
                $ur = $r.GetUpdateResult($i)

                $obj = [pscustomobject]@{
                    Title          = $u.Title
                    UpdateID       = $u.Identity.UpdateID
                    HResult        = ('0x{0:X8}' -f $ur.HResult)
                    ResultCode     = (Format-WuResultCodeName $ur.ResultCode)
                    RebootRequired = $ur.RebootRequired
                }

                Write-Host ("[Install] {0} ID:{1} -> {2} {3}" -f $obj.Title, $obj.UpdateID, $obj.ResultCode, $obj.HResult)
                $results += $obj
            }

            if (-not $script:AllUpdateResults) { $script:AllUpdateResults = @() }
            $script:AllUpdateResults += $results

            Write-DbgDump -Json -Label 'InstallBatch.Results' -Obj ([pscustomobject]@{
                OverallResultCode = $r.ResultCode
                RebootRequired    = [bool]$r.RebootRequired
                UpdateResults     = $results
                AllUpdateResultsCount = (@($script:AllUpdateResults)).Count
            })

            [pscustomobject]@{
                OverallResultCode = $r.ResultCode
                RebootRequired    = $r.RebootRequired
                UpdateResults     = $results
            }
        }

        Write-DbgDump -Json -Label 'NonExclusive' -Obj (Get-DbgUpdateSnapshot $NonExclusive)
        Write-DbgDump -Json -Label 'Exclusive'    -Obj (Get-DbgUpdateSnapshot $Exclusive)

        $installedSomething = $false
        $wuaRequestsReboot = $false

        if ($NonExclusive -and $NonExclusive.Count -gt 0) {
            Write-Host ("$(Get-Date) Installing {0} normal(non-exclusive) update(s) as a batch..." -f $NonExclusive.Count)
            $res = Invoke-WuaInstallBatch -WuaUpdateCol $NonExclusive -Session $Session -Interactive:$Interactive
            if ($res) {
                $installedSomething = $true
                $wuaRequestsReboot = $wuaRequestsReboot -or [bool]$res.RebootRequired
            }
            Write-DbgDump -Json -Label 'InstallPart.AfterNonExclusive' -Obj ([pscustomobject]@{
                InstalledSomething=[bool]$installedSomething
                WuaRequestsReboot=[bool]$wuaRequestsReboot
                BatchResult=$res
            })
        }

        foreach ($u in @($Exclusive)) {
            Write-Host ("$(Get-Date) Installing exclusive update: {0}" -f $u.Title)
            $tmp = New-Object -ComObject 'Microsoft.Update.UpdateColl'
            [void]$tmp.Add($u)

            Write-DbgDump -Json -Label 'InstallPart.Exclusive.OneUpdateSnap' -Obj ([pscustomobject]@{
                Title = $u.Title
                UpdateSnap = (Get-DbgUpdateSnapshot $u)
            })

            $res = Invoke-WuaInstallBatch -WuaUpdateCol $tmp -Session $Session -Interactive:$Interactive
            if ($res) {
                $installedSomething = $true
                $wuaRequestsReboot = $wuaRequestsReboot -or [bool]$res.RebootRequired
            }
            Write-DbgDump -Json -Label 'InstallPart.AfterExclusiveOne' -Obj ([pscustomobject]@{
                InstalledSomething=[bool]$installedSomething
                WuaRequestsReboot=[bool]$wuaRequestsReboot
                BatchResult=$res
            })
        }

        [pscustomobject]@{
            InstalledSomething = $installedSomething
            WuaRequestsReboot  = $wuaRequestsReboot
        }
    }

    <#
    .SYNOPSIS
    Downloads the provided eligible updates by using the supplied update
    session.
    
    .DESCRIPTION
    Starts a download operation for all items in EligibleNotDownloaded and
    reports per-update results to the host.
    Writes diagnostic dump records before download, after download, and after
    result reporting. If a terminating error occurs, some updates may already
    be downloaded.
    
    .OUTPUTS No pipeline output.
    
    .PARAMETER Session
    Update session used to create the downloader.
    
    .PARAMETER EligibleNotDownloaded
    Updates to download in this phase. Each item must be accepted by the
    session downloader and support collection membership.
    #>
    function Invoke-DownloadPhase {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory=$true)]$Session,
        [Parameter(Mandatory=$true)][object[]]$EligibleNotDownloaded
      )

      Write-DbgDump -Json -Label 'DownloadPhase.Inputs' -Obj ([pscustomobject]@{
          Count = (@($EligibleNotDownloaded)).Count
          UpdatesSnap = (Get-DbgUpdateSnapshot $EligibleNotDownloaded)
      })

      $dlColl = New-Object -ComObject 'Microsoft.Update.UpdateColl'
      foreach ($u in $EligibleNotDownloaded) { [void]$dlColl.Add($u) }

      $maxGB = 0
      foreach ($u in $EligibleNotDownloaded) {
        if ($u.MaxDownloadSize) { $maxGB += [math]::Round($u.MaxDownloadSize/1GB,2) }
      }

      Write-Host ("$(Get-Date) Downloading {0} update(s) (at most {1} GB)..." -f $EligibleNotDownloaded.Count, ($maxGB -as [string]))

      $downloader = $Session.CreateUpdateDownloader()
      $downloader.Priority = 3
      $downloader.Updates  = $dlColl

      $dr = $downloader.Download()

      Write-DbgDump -Json -Label 'DownloadPhase.DownloadResult.PreLoopSnapshot' -Obj ([pscustomobject]@{
          UpdateCount = $dlColl.Count
          DownloadResultSnapshot = (Get-DbgDownloadResultSnapshot -DownloadResult $dr -ExpectedCount $dlColl.Count)
          UpdatesSnapPost = (Get-DbgUpdateSnapshot $dlColl)
      })

      for ($i=0; $i -lt $dlColl.Count; $i++) {
        $u  = $dlColl.Item($i)
        $ur = $dr.GetUpdateResult($i)

        Write-Host ("[Download] {0} ID:{1} -> {2} 0x{3:X8}" -f $u.Title,$u.Identity.UpdateID,(Format-WuResultCodeName $ur.ResultCode),$ur.HResult)
      }

      Write-DbgDump -Json -Label 'DownloadPhase.AfterLoop.EligibleNotDownloadedSnap' -Obj (Get-DbgUpdateSnapshot $EligibleNotDownloaded)

      Write-Host "Download phase complete.`n"
    }

    # Removes the "ResumeAfterReboot" ScheduledTask that has been created by Schedule-ContinueWUStartupTask
    function Clear-ContinueWUStartupTask {
        $taskName = 'WindowsUpdateHelper-ResumeAfterReboot'
        try {
            $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($t) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Write-Host ("[Continue] Removed startup task '{0}'." -f $taskName)
            }
        } catch {
            Write-Host -ForegroundColor Yellow ("ERROR: [Continue] Failed to remove startup task '{0}': {1}" -f 'WindowsUpdateHelper-ResumeAfterReboot', $_.Exception.Message)
        }
    }

    function Ensure-WuService {
        $svc = Get-Service wuauserv -ErrorAction Stop
        if ($svc.Status -eq 'Running') { return }
        $delays = 5,10,20
        for ($i=0; $i -lt $delays.Count; $i++) {
            try {
                Start-Service wuauserv
                $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(15)) | Out-Null
                $svc = Get-Service wuauserv
                if ($svc.Status -eq 'Running') { return }
            } catch {
                Write-Host ("[WUService] Attempt {0} failed: {1}" -f ($i+1), $_.Exception.Message)
            }
            Start-Sleep -Seconds $delays[$i]
        }
        throw "Failed to start 'wuauserv' after retries."
    }

    function Invoke-WuResumeAfterRebootPart {
        <#
        .SYNOPSIS
          Handles "continue after reboot" mode by clearing state and deciding whether to force a reboot.

        .DESCRIPTION
          If -XXX_ResumeAfterReboot is set:
            - Removes the startup task (Clear-ContinueWUStartupTask)
            - Reads a flag file timestamp (by file creation time)
            - If the flag file is "fresh" (<= MaxAgeHours), returns $true to force -Reboot for this run
            - Deletes the flag file (best-effort), and returns the decision

        .PARAMETER XXX_ResumeAfterReboot
          Enables this continuation logic. If not set, the function returns $false immediately.

        .PARAMETER FlagFilePath
          Full path to the continuation flag file.

        .PARAMETER MaxAgeHours
          Maximum age (hours) for the flag file to be considered valid for forcing reboot.

        .OUTPUTS
          Boolean. $true means "force reboot for this continuation run"; $false otherwise.
        #>

        [CmdletBinding()]
        param(
          [switch]$XXX_ResumeAfterReboot,
          [Parameter(Mandatory=$true)][string]$FlagFilePath,
          [int]$MaxAgeHours = 4
        )
      
        if (-not $XXX_ResumeAfterReboot) { return $false }
      
        Clear-ContinueWUStartupTask
      
        if (-not (Test-Path -LiteralPath $FlagFilePath)) {
          Write-Host -ForegroundColor Yellow ("WARNING: [Continue] Flag file not found at {0}; continuing without forcing -Reboot." -f $FlagFilePath)
          return $false
        }
      
        $ts=$null;$raw=$null
        try{
          $raw = (Get-Content -LiteralPath $FlagFilePath -ErrorAction Stop | Select-Object -First 1)
          $raw = ($raw -as [string]).Trim()
          if($raw){
            $ts = [datetime]::ParseExact($raw,'s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeLocal)
          }
        } catch {
          $ts=$null
        }
      
        $fi = Get-Item -LiteralPath $FlagFilePath
        if(-not $ts){
          Write-Host -ForegroundColor Yellow ("WARNING: [Continue] Flag file '{0}' has no parseable timestamp content ('{1}'). Falling back to LastWriteTime." -f $FlagFilePath, $raw)
          $ts = $fi.LastWriteTime
        }
      
        $age = (Get-Date) - $ts
        $ageHours = [math]::Round($age.TotalHours,2)
      
        $forceReboot = $false
        if ($age.TotalHours -le $MaxAgeHours) {
          Write-Host ("[Continue] Flag timestamp {0} (age {1}h) found in {2}; enabling -Reboot." -f $ts.ToString('s'), $ageHours, $FlagFilePath)
          $forceReboot = $true
        } else {
          Write-Host -ForegroundColor Yellow ("WARNING: [Continue] Flag timestamp {0} (age {1}h) in {2}; NOT forcing -Reboot." -f $ts.ToString('s'), $ageHours, $FlagFilePath)
        }
      
        try {
          Remove-Item -LiteralPath $FlagFilePath -Force -ErrorAction Stop
          Write-Host ("[Continue] Removed flag file {0}." -f $FlagFilePath)
        } catch {
          if (Test-Path -LiteralPath $FlagFilePath) {
            Write-Host -ForegroundColor Yellow ("WARNING: [Continue] Failed to remove flag file '{0}': {1}" -f $FlagFilePath, $_.Exception.Message)
          }
        }
      
        return $forceReboot
    }

    function Invoke-WuSearchAndDisplayPart {
        <#
        .SYNOPSIS
          Searches for applicable updates and displays a summary of the results.

        .DESCRIPTION
          Performs a WUA search using the provided Searcher (which should already have Online set appropriately).
          Builds a friendly table view for visibility (KBs, size, downloaded state, user-input flag, exclusive flag, EULA state).

          Returns the raw WUA search result object so the caller can partition and act on the update COM objects.

        .PARAMETER Searcher
          A WUA UpdateSearcher created from Microsoft.Update.Session. Its Online property controls online/offline scan.

        .OUTPUTS
          The WUA search result object returned by $Searcher.Search(...).
        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]$Searcher
        )

        Write-Host ("$(Get-Date) Searching for updates -- Online={0} ServerSelection={1} ServiceID='{2}'" -f $searcher.Online,[int]$searcher.ServerSelection,($searcher.ServiceID -as [string]))

        $searchResults = $Searcher.Search("IsInstalled=0 and IsHidden=0")

        if ($searchResults.Updates.Count -gt 0) {
            Write-Host ("$(Get-Date) Found {0} update(s)." -f $($searchResults.Updates.Count)) -ForegroundColor Magenta
            Write-DbgDump -Json -Label "The Updates" -Obj (Get-DbgUpdateSnapshot $searchResults.Updates)
        } else {
            Write-Host "$(Get-Date) Found no updates." -ForegroundColor Green
        }
        Write-Host ""
        return $searchResults
    }

    #------------------------------------------------------------------------
    # START OF MAIN PART OF FUNCTION
    #------------------------------------------------------------------------

    $script:ContinueflagFile = Join-Path "$env:windir\Temp" 'WindowsUpdateHelper.ResumeAfterReboot.flag'
    $script:AllUpdateResults = @()

    Write-DbgDump -Json -Label 'InstallPhase.ParamsAndEnv' -Obj ([pscustomobject]@{
        PSCommandPath=$PSCommandPath
        PID=$PID
        ComputerName=$env:COMPUTERNAME
        UserName=$env:USERNAME
        PSVersion=($PSVersionTable.PSVersion.ToString())
        OS=(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version)
    })

    $rebootPendingAtStart = Test-RebootPending
    if ($rebootPendingAtStart) {Write-Host "INFO: Windows indicates a reboot is already pending before performing any action"}

    if (-not $Download) {
        Write-Host "NOTE: Not doing an online check` and only installing already downloaded updates (Use -Download if you do want downloading and online check)"
    }


    # Handle "continue-after-reboot" mode
    $forceReboot = Invoke-WuResumeAfterRebootPart `
        -XXX_ResumeAfterReboot:$XXX_ResumeAfterReboot `
        -FlagFilePath $script:ContinueflagFile
    if ($forceReboot) { $Reboot = $true }

    Ensure-WuService

    $session  = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = [bool]$Download # will only look online if -Download is passed
	
    $searchResults = Invoke-WuSearchAndDisplayPart -Searcher $searcher

    # Partition initial results (and keep the eligible already-downloaded ones)
    $eligibleNotDownloaded = @()
    $eligibleDownloaded = @()
    $skippedUpdates = $false

    for ($i=0; $i -lt $searchResults.Updates.Count; $i++) {
        $u = $searchResults.Updates.Item($i)
        if ($u.InstallationBehavior.CanRequestUserInput -and -not $Interactive) {
            Write-Host "  Skipping $($u.Title) because it is flagged as 'CanRequestUserInput' (Add -Interactive to inlcude it, but be prepared to respond to GUI prompts)." -ForegroundColor Yellow
            $skippedUpdates = $true
            continue
        } elseif ($u.IsDownloaded) { 
            $eligibleDownloaded += $u 
        } else {
            $eligibleNotDownloaded += $u 
            if (-not $Download) {
                Write-Host "  Skipping $($u.Title) because it is not downloaded (add -Download to force)" -ForegroundColor Yellow
                $skippedUpdates = $true
            }
        }
    }

    if ($skippedUpdates) { Write-Host "" } # visual separation

    Write-DbgDump -Json -Label "eligibleDownloaded" -Obj (Get-DbgUpdateSnapshot $eligibleDownloaded)
    Write-DbgDump -Json -Label "eligibleNotDownloaded" -Obj (Get-DbgUpdateSnapshot $eligibleNotDownloaded)

    # Download updates (if needed)
    if ($Download -and $eligibleNotDownloaded -and $eligibleNotDownloaded.Count -gt 0) { 
        Invoke-DownloadPhase -Session $session -EligibleNotDownloaded $eligibleNotDownloaded
    }

    # Build pool from the SAME objects (post-download state, no refresh search)
    $pool = @()

    foreach ($u in @($eligibleDownloaded)) {
        if ($u.IsDownloaded) {
            $pool += $u
        } else {
            Write-Host -ForegroundColor Yellow ("WARNING: Update previously reported as downloaded is now not downloaded: {0}" -f $u.Title)
        }
    }

    foreach ($u in @($eligibleNotDownloaded)) {
        if ($u.IsDownloaded) {
            $pool += $u
        } else {
            if ($Download) { Write-Host "  Skipping $($u.Title) because it is not downloaded (download may have failed)" }
        }
    }

    Write-DbgDump -Json -Label "pool" -Obj (Get-DbgUpdateSnapshot $pool)

    # Partition pool: normal vs exclusive
    $nonExclusive = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    $exclusive = @()
    foreach ($u in $pool) {
        if (-not $u.EulaAccepted) {
            try { $u.AcceptEula() } catch {
                Write-Host -ForegroundColor Yellow ("WARNING: Failed to accept EULA for '{0}': {1}" -f $u.Title, $_.Exception.Message)
                continue
            }
        }
        if ($u.InstallationBehavior.RequiresExclusiveHandling) {$exclusive += $u} else {[void]$nonExclusive.Add($u)}
    }

    Write-DbgDump -Json -Label "nonExclusive" -Obj (Get-DbgUpdateSnapshot $nonExclusive)
    Write-DbgDump -Json -Label "exclusive" -Obj (Get-DbgUpdateSnapshot $exclusive)

    Write-DbgDump -Json -Label 'InstallPhase.BeforeInstall' -Obj ([pscustomobject]@{
        Interactive=[bool]$Interactive
        AllUpdateResultsCount=$script:AllUpdateResults.Count
    })

    $installFacts = Invoke-WuInstallPart -Session $session -NonExclusive $nonExclusive -Exclusive $exclusive -Interactive:$Interactive
    $installedSomething = [bool]$installFacts.InstalledSomething
    $wuaRequestsReboot = [bool]$installFacts.WuaRequestsReboot

    Write-DbgDump -Json -Label 'InstallPhase.AllUpdateResults' -Obj $script:AllUpdateResults

	if ($Interactive -and $script:AllUpdateResults.Count -eq 0) {
		# No udpates found and this is an -Interactive run; let's check if optional updates are available
		Write-Host "Checking if there are any OPTIONAL updates available (will not download nor install)."
		$s=New-Object -ComObject Microsoft.Update.Session
		$searcher=$s.CreateUpdateSearcher()
		$searcher.Online=$true
		$searcher.ServerSelection=2  # Windows Update (not Microsoft Update)

		$results=$searcher.Search("IsInstalled=0 and IsHidden=0 and DeploymentAction='OptionalInstallation'")
		if ($results.Updates.Count -gt 0){
			Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor DarkGreen
			Write-Host "Note that there are some *OPTIONAL* updates available (the command to install them is also shown):" -ForegroundColor DarkGreen
			$results.Updates | %{
				Write-Host "  * $($_.Title) "-ForegroundColor DarkGreen
				Write-Host "    & '$PSCommandPath' -InstallOptional $($_.Identity.UpdateID)" -ForegroundColor DarkGray
			}
			Write-Host ""
			Write-Host "These you must install manually." -ForegroundColor DarkGreen
			Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor DarkGreen
			Write-Host ""
		}
	}

    # Post-install reboot handling
    $plan=Get-WuRebootPlan `
      -InstalledSomething:$installedSomething `
      -WuaRequestsReboot:$wuaRequestsReboot `
      -RebootPendingAtStart:$rebootPendingAtStart `
      -AllUpdateResults:$script:AllUpdateResults `
      -Reboot:$Reboot `
      -RebootAnyway:$RebootAnyway `
      -XXX_ResumeAfterReboot:$XXX_ResumeAfterReboot

    Invoke-WuApplyRebootPlan -Plan $plan -ScriptPath $PSCommandPath -FlagFilePath $script:ContinueflagFile

}

# -------------------------------------------------------------------------------------------------
# END
#       Function(s) that implememt the NORMAL mode of operation
#       (where we install updates)
# -------------------------------------------------------------------------------------------------

# ----- Logging / transcript -----
$script:TranscriptEnabled = (Start-WuTranscript).TranscriptEnabled
Write-Host "Degug: Command: $($MyInvocation.Line)" -ForegroundColor DarkGray
Write-Host "Degug: Arguments:" -ForegroundColor DarkGray
$MyInvocation.BoundParameters.GetEnumerator() |
  Sort-Object Key |
  ForEach-Object{
    Write-Host ("  -{0} = {1}" -f $_.Key,$_.Value) -ForegroundColor DarkGray
  }
for($i=0;$i -lt $args.Count;$i++){
  Write-Host ("  args[{0}] = {1}" -f $i,$args[$i]) -ForegroundColor DarkGray
}

# Cleanup forced reboot Scheduled Task if any (see calls to Schedule-ForcedReboot)
$taskName='WindowsUpdateHelper-ForcedReboot'
try{
  if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  }
} catch {}

#-------------------------------------------------------------------------------
# Implement -AbortReboot
#-------------------------------------------------------------------------------
if($AbortReboot){
    Assert-Elevated
    shutdown.exe /a
    if ($LASTEXITCODE -eq 0) {Write-Host -ForegroundColor green "Reboot aborted."}
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
    return
}

#-------------------------------------------------------------------------------
# Implement -XXX_RebootNow
#-------------------------------------------------------------------------------
# MAYBE TODO: postpone reboot for a few minutes if we suspect an installation 
# is still going on (maybe from high CPU or disk activity or from processess 
# related to installations).
# Rationale: I observed a case, where after the windows updated some Lenovo 
# drivers/firmware, some other Lenovo udpates kicked of. 
if($XXX_RebootNow){
  if(-not $XXX_RebootArmedAt){
    Write-Host -ForegroundColor Red "WARNING: -XXX_RebootNow was passed without -XXX_RebootArmedAt. Will NOT reboot."
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
    return
  }
  Assert-Elevated

  $armedText=(($XXX_RebootArmedAt -as [string]).Trim())
  $armed=[datetime]::MinValue
  if(-not [datetime]::TryParseExact($armedText,'s',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeLocal,[ref]$armed)){
    Write-Host -ForegroundColor Red ("WARNING: -XXX_RebootNow was passed but -XXX_RebootArmedAt is not a valid timestamp ('{0}'). Refusing to reboot." -f $armedText)
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
    return
  }

  $taskName='WindowsUpdateHelper-ForcedReboot'
  try{
    if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){
      Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
  } catch {}

  try{
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $boot=[datetime]$os.LastBootUpTime
    if($boot -gt $armed){
      Write-Host -ForegroundColor Yellow ("Skipping forced reboot because we already rebooted (system boot time {0} is after armed-at {1})." -f $boot.ToString('s'),$armed.ToString('s'))
      if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
      return
    }
  } catch {
    Write-Host -ForegroundColor Yellow ("[ForcedReboot] WARNING: Could not read system boot time ({0}). Proceeding with forced reboot." -f $_.Exception.Message)
  }

  write-Host "Executing shutdown.exe /f /r /t 0 /c ..."
  if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
  shutdown.exe /f /r /t 0 /c "WindowsUpdatesHelper.ps1: reboot after installing Windows Updates (FORCED)" /d p:0:0
  return
}

#-------------------------------------------------------------------------------
# Implement -Logs / -ListRecentLogs
#-------------------------------------------------------------------------------
if($ListRecentLogs){
    Get-WindowsUpdateHelperLogFiles -RecentCount 10 -All:$ListAll
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
    return
}

if($InstallOptional){
    Invoke-WuInstallOptionalByUpdateId -UpdateId:$InstallOptional -Interactive
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
    return
}

#-------------------------------------------------------------------------------
# Implement -History / -ShowHistory (where we show windows updates history)
#-------------------------------------------------------------------------------
if ($ShowHistory) {
    $p = @{ MaxResults = $MaxResults; IncludeAV = $IncludeAV; MaxScanEntries = $MaxScanEntries }
    if ($PSBoundParameters.ContainsKey('LastDays')) { $p.LastDays = $LastDays }
    Get-WindowsUpdateHistory @p
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
    return
}

#-------------------------------------------------------------------------------
# Implement normal "Install" mode of operation (where we install updates)
#-------------------------------------------------------------------------------
Assert-Elevated
$srcForceSystemToNotSleep=@"
using System;
using System.Runtime.InteropServices;
public static class Awake {
  [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint es);
  public const uint ES_CONTINUOUS=0x80000000, ES_SYSTEM_REQUIRED=0x00000001, ES_DISPLAY_REQUIRED=0x00000002;
}
"@
if(-not ("Awake" -as [type])){ Add-Type -TypeDefinition $srcForceSystemToNotSleep -ErrorAction Stop }
[Awake]::SetThreadExecutionState([Awake]::ES_CONTINUOUS -bor [Awake]::ES_SYSTEM_REQUIRED) | Out-Null
try {
    $ErrorActionPreference = 'Stop'
    Invoke-InstallPhase `
        -Download:$Download `
        -Reboot:$Reboot `
        -RebootAnyway:$RebootAnyway `
        -XXX_ResumeAfterReboot:$XXX_ResumeAfterReboot `
        -Interactive:$Interactive
} finally {
    [Awake]::SetThreadExecutionState([Awake]::ES_CONTINUOUS) | Out-Null
    if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}
}

if($script:TranscriptEnabled){try{Stop-Transcript|Out-Null;$script:TranscriptEnabled=$false}catch{}}