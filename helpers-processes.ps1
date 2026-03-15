##############################################################
#
# A collection of helper functions for Processes & Tasks
#
##############################################################

<#
.DESCRIPTION
Quotes a string so it can be safely passed as a single argument to a Windows process via CreateProcess, following the exact Win32 command-line parsing rules. It ensures arguments containing spaces, quotes, or trailing backslashes are preserved exactly as intended when reconstructed by the target program.

	'simple'				=> simple
	'hello world'			=> "hello world"
	'He said "hello"'		=> "He said \"hello\""
	'C:\Temp\'				=> "C:\Temp\\"
	'C:\Path With Spaces\'	=> "C:\Path With Spaces\\"
	'C:\X\"Y"\Z\'			=> "C:\X\\\"Y\\\"\Z\\"
#>
function Quote-Win32Arg([AllowNull()][string]$s){
  if ($null -eq $s) { return '""' }
  if ($s.Length -eq 0) { return '""' }
  if ($s -notmatch '[\s"]') { return $s }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  $i=0
  while($i -lt $s.Length){
    $ch=$s[$i]
    if($ch -eq '\'){
      $bs=0
      while($i -lt $s.Length -and $s[$i] -eq '\'){ $bs++; $i++ }
      if($i -eq $s.Length){ [void]$sb.Append(('\' * ($bs*2))); break }
      if($s[$i] -eq '"'){ [void]$sb.Append(('\' * ($bs*2+1))); [void]$sb.Append('"'); $i++ }
      else { [void]$sb.Append(('\' * $bs)) }
      continue
    }
    if($ch -eq '"'){ [void]$sb.Append('\\"'); $i++; continue }
    [void]$sb.Append($ch); $i++
  }
  [void]$sb.Append('"')
  $sb.ToString()
}

<#
.SYNOPSIS
Constructs a valid Win32 command-line string from a list of arguments.

.DESCRIPTION
Iterates through a collection of arguments, applies Win32 escaping to each (via Quote-Win32Arg), and joins them with spaces. This creates a single string safe for use with APIs like System.Diagnostics.Process or CreateProcess.

    ['git', 'commit', '-m', 'Msg']           => git commit -m Msg
    ['app.exe', 'C:\Program Files\', '/v']   => app.exe "C:\Program Files\\" /v
    ['echo', '', 'foo']                      => echo "" foo

.PARAMETER ArgumentList
The collection of objects (strings) to be joined. Objects are converted to strings before quoting.
#>
function Join-Win32CommandLine {
  param([Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$ArgumentList)
  (($ArgumentList | ForEach-Object { Quote-Win32Arg ([string]$_) }) -join ' ')
}

function New-ScheduledTaskForPSScript {
<#
.SYNOPSIS
Registers a Windows Scheduled Task that runs a PowerShell script as SYSTEM.

.DESCRIPTION
Creates or updates a scheduled task that runs the script specified by
-ScriptPath using Windows PowerShell (powershell.exe).

The task is registered under -TaskPath and -TaskName (a default name is
chosen when -TaskName is not provided). If a task with the same name
already exists at that path, it is replaced.

The task runs as the built-in SYSTEM account with highest run level. Task
settings limit concurrent executions by ignoring new starts while an
instance is already running, and apply -ExecutionTimeLimit to each run.

Depending on the script path and provided arguments, the function MAY
create a .cmd wrapper file in the script's folder and configure the task
to execute that wrapper instead of invoking powershell.exe directly.

If -ScheduleType is Manual, the task is created without a trigger and
will only run when started manually (or by other tooling).

Supports -WhatIf and -Confirm. If confirmation is declined (or -WhatIf is
used), no task is registered and no wrapper file is created.

.OUTPUTS
Microsoft.Management.Infrastructure.CimInstance
A scheduled task object returned by Register-ScheduledTask when the task
is registered. If ShouldProcess declines the action, no output is
produced.

.PARAMETER ScriptPath
Path to an existing PowerShell script file. The path MUST exist or the
function throws before making changes.

.PARAMETER ScheduleType
Selects how (or whether) the task is triggered.

Valid values:
- Startup: runs at system startup.
- Daily: runs daily at -Time.
- Weekly: runs weekly on -Day at -Time.
- Hourly: repeats every hour starting shortly after creation time.
- EveryMinute: repeats every minute starting shortly after creation time.
- Manual: no trigger is created.

.PARAMETER Time
Time of day in HH:mm (24-hour) format. Required for Daily and Weekly.

.PARAMETER Day
One or more weekdays. Required for Weekly.

.PARAMETER TaskPath
Scheduled task folder path in Task Scheduler (for example '\enLogic\').
Defaults to '\enLogic\'.

.PARAMETER TaskName
Scheduled task name. If omitted, a name is derived from the script file
name.

.PARAMETER ScriptArguments
Argument values passed to the script. Provide either -ScriptArguments or
-RawArgumentsAvoidMe, not both.

Elements MAY be $null. How the script receives $null depends on the
invocation mode chosen by the function.

.PARAMETER RawArgumentsAvoidMe
A raw argument string appended to the invocation. Intended for advanced
cases. Provide either -ScriptArguments or -RawArgumentsAvoidMe, not both.

.PARAMETER ExecutionTimeLimit
Maximum runtime allowed for each task invocation. Defaults to 2 hours.

.PARAMETER StartItNow
If set, the function attempts to start the task immediately after it is
registered. If starting fails, the task remains created and an error is
written.

.EXAMPLE
New-ScheduledTaskForPSScript -ScriptPath 'C:\Ops\Health.ps1' `
  -ScheduleType Startup -TaskPath '\enLogic\'

.EXAMPLE
New-ScheduledTaskForPSScript -ScriptPath 'C:\Ops\Report.ps1' `
  -ScheduleType Daily -Time '02:30' -TaskName 'Daily Report' `
  -ScriptArguments @('Full','EU')

.EXAMPLE
New-ScheduledTaskForPSScript -ScriptPath 'C:\Ops\Cleanup.ps1' `
  -ScheduleType Weekly -Day Monday,Thursday -Time '03:00' `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartItNow

.EXAMPLE
New-ScheduledTaskForPSScript -ScriptPath 'C:\Ops\OnDemand.ps1' `
  -ScheduleType Manual -TaskName 'Run On Demand'

.NOTES
Registers the task to run as SYSTEM with highest privileges, and sets
MultipleInstances to IgnoreNew.

For Hourly and EveryMinute schedules, the first run is anchored to a
start time shortly after the function is invoked (not aligned to clock
boundaries).
#>
  [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Generic')]
  param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Generic')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Daily')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Weekly')]
    [ValidateSet('Startup','Daily','Weekly','Hourly','EveryMinute','Manual')]
    [string]$ScheduleType,

    [Parameter(Mandatory = $true, ParameterSetName = 'Daily')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Weekly')]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$Time,

    [Parameter(Mandatory=$true, ParameterSetName='Weekly')]
    [DayOfWeek[]]$Day,

    [string]$TaskPath = '\enLogic\',
    [string]$TaskName,
    [string[]]$ScriptArguments,
    [string]$RawArgumentsAvoidMe,
    [TimeSpan]$ExecutionTimeLimit = (New-TimeSpan -Hours 2),
    [switch]$StartItNow
  )

  if ($RawArgumentsAvoidMe -and $ScriptArguments) {
    throw "Use either -ScriptArguments (recommended) or -RawArgumentsAvoidMe (for advanced users), not both."
  }

  $ScriptFullName = $ScriptPath
  if (Test-Path -LiteralPath $ScriptFullName) {
    try { $ScriptFullName = (Resolve-Path -LiteralPath $ScriptFullName).ProviderPath }
    catch { throw "Failed to resolve script path: $ScriptPath. Error: $_" }
  } else {
    throw "Script not found: $ScriptPath"
  }

  $scriptFolder = Split-Path -Parent $ScriptFullName
  $scriptFile   = Split-Path -Leaf  $ScriptFullName
  $baseName     = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile)

  if (-not $TaskName) { $TaskName = "Execute $scriptFile" }
  $TaskDescription = "Run script $ScriptFullName"

  $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  if (-not (Test-Path -LiteralPath $psExe)) { throw "powershell.exe not found at expected path: $psExe" }

  $needsBatchWrapper  = $false
  $scriptUnsafePattern = '[\"`^&|<>()]'
  $argUnsafePattern    = '[\s\"`^&|<>()]'
  $rawUnsafePattern    = '[\"`^]'

  if ($ScriptFullName -match $scriptUnsafePattern) { $needsBatchWrapper = $true }

  if (-not $needsBatchWrapper -and $ScriptArguments) {
    foreach ($a in $ScriptArguments) {
      if ($null -ne $a -and $a -match $argUnsafePattern) { $needsBatchWrapper = $true; break }
    }
  }

  if (-not $needsBatchWrapper -and $RawArgumentsAvoidMe) {
    if ($RawArgumentsAvoidMe -match $rawUnsafePattern) { $needsBatchWrapper = $true }
  }

  $Action    = $null
  $batchPath = $null

  if ($needsBatchWrapper) {
    $escapedScript = $ScriptFullName.Replace("'", "''")
    if ($ScriptArguments) {
      $escapedArgs = @()
      foreach ($a in $ScriptArguments) {
        if ($null -eq $a) { $escapedArgs += '$null' }
        else { $escapedArgs += "'" + $a.Replace("'", "''") + "'" }
      }
      $argLiteral = '@(' + ($escapedArgs -join ',') + ')'
      $code = "& '$escapedScript' $argLiteral"
    } elseif ($RawArgumentsAvoidMe) {
      $code = "& '$escapedScript' $RawArgumentsAvoidMe"
    } else {
      $code = "& '$escapedScript'"
    }

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
    $enc   = [Convert]::ToBase64String($bytes)

    $batchBase = "{0}-{1}-task" -f $baseName, $ScheduleType
    $batchName = "$batchBase.cmd"
    $batchPath = Join-Path $scriptFolder $batchName
    $counter   = 1
    while (Test-Path -LiteralPath $batchPath) {
      $batchName = "{0}-{1}-task-{2}.cmd" -f $baseName, $ScheduleType, $counter
      $batchPath = Join-Path $scriptFolder $batchName
      $counter++
    }

    $singleLineCode = $code -replace '(\r?\n)+','; '
    $decodeHint = "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$enc'))"

    $batchContent =
      "@echo off`r`n" +
      "REM Auto-generated by New-ScheduledTaskForPSScript`r`n" +
      "REM Decoded PowerShell command:`r`n" +
      "REM   $singleLineCode`r`n" +
      "REM To decode the Base64 payload in PowerShell, run:`r`n" +
      "REM   $decodeHint`r`n" +
      '"' + $psExe + '"' +
      " -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand " +
      $enc + "`r`n"

    try { [System.IO.File]::WriteAllText($batchPath, $batchContent, [System.Text.Encoding]::ASCII) }
    catch { throw "Failed to create batch wrapper '$batchPath'. Error: $_" }

    $Action = New-ScheduledTaskAction -Execute $batchPath -ErrorAction Stop
  }
  else {
    $argParts = @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$ScriptFullName)
    if ($ScriptArguments) { $argParts += $ScriptArguments }
    elseif ($RawArgumentsAvoidMe) { $argParts += $RawArgumentsAvoidMe }
  
    $argString = Join-Win32CommandLine -ArgumentList $argParts
    if ([string]::IsNullOrWhiteSpace($argString)) { throw "Internal error: produced empty argument string for task action." }
  
    $Action = New-ScheduledTaskAction -Execute $psExe -Argument $argString -ErrorAction Stop
  }

  if (-not $Action) {
    throw "Internal error: Scheduled task action was not created."
  }
  
  $Trigger = $null
  switch ($ScheduleType) {
    'Startup' { $Trigger = New-ScheduledTaskTrigger -AtStartup }
    'Daily'   { $Trigger = New-ScheduledTaskTrigger -Daily  -At $Time }
    'Weekly'  { $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $Time }
    'Hourly' {
      $start   = (Get-Date).AddMinutes(1)
      $Trigger = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Hours 1)
      $Trigger.Repetition.Duration = [TimeSpan]::Zero
    }
    'EveryMinute' {
      $start   = (Get-Date).AddMinutes(1)
      $Trigger = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval (New-TimeSpan -Minutes 1)
      $Trigger.Repetition.Duration = [TimeSpan]::Zero
    }
    'Manual' { $Trigger = $null }
  }

  $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

  $Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit $ExecutionTimeLimit

  $taskPathWithSlash = if ($TaskPath.EndsWith('\')) { $TaskPath } else { $TaskPath + '\' }
  $targetDisplay = "$taskPathWithSlash$TaskName"
  
  $registerParams = @{
    TaskName    = $TaskName
    TaskPath    = $taskPathWithSlash
    Action      = $Action
    Principal   = $Principal
    Settings    = $Settings
    Description = $TaskDescription
    Force       = $true
  }
  if ($Trigger) { $registerParams['Trigger'] = $Trigger }

  if (-not $PSCmdlet.ShouldProcess($targetDisplay, 'Register scheduled task')) { return }

  try{
    $registerParams | Format-Table | Out-String | Write-Host -ForegroundColor DarkGray
  } catch {
    Write-Verbose ($registerParams | Out-String)
  }
  $task = Register-ScheduledTask @registerParams -ErrorAction Stop

  Write-Host "Success! Created Task: '$targetDisplay'" -ForegroundColor Green

  if ($needsBatchWrapper) {
    Write-Host ""
    Write-Host "Note: A batch wrapper was created due to complex/unsafe characters in the script path or arguments." -ForegroundColor Yellow
    Write-Host "      Batch file: $batchPath"
    Write-Host "      The scheduled task runs this .cmd, which in turn calls:" -ForegroundColor Yellow
    Write-Host "          $psExe -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64 script>"
    Write-Host "      The .cmd file also includes a comment with the decoded PowerShell command" -ForegroundColor Yellow
    Write-Host "      and a PowerShell one-liner you can use to decode the Base64 payload." -ForegroundColor Yellow
  }

  if ($StartItNow) {
    try {
      Start-ScheduledTask -TaskPath $taskPathWithSlash -TaskName $TaskName
      Write-Host "Task started immediately." -ForegroundColor Cyan
    } catch {
      Write-Error "Task '$taskPathWithSlash$TaskName' was created but failed to start. Error: $_"
    }
  }

  Write-Host ""
  Write-Host "To remove this task, run:" -ForegroundColor Yellow
  Write-Host "Unregister-ScheduledTask -TaskPath '$taskPathWithSlash' -TaskName '$TaskName' -Confirm:`$false"

  $task
}


function Invoke-DetachedPSScript {
<#
.SYNOPSIS
Executes a PowerShell script on a remote host as a detached process
without leaving a disconnected session after execution completes.

.DESCRIPTION
The script or script block is executed on the remote host. Unlike 
`Invoke-Command -InDisconnectedSession` once the execution terminates 
it does not leave a disconnected session on the target.

.OUTPUTS
Produces a PSCustomObject representing the process start result:
  ComputerName  : The target host name.
  ProcessId     : The ID of the newly created remote process.
  ReturnValue   : The system code from the process creation attempt.
  Status        : The outcome of the initiation (e.g., "Success").
  ExecutionPath : The path to the script being executed on the target.
}
#>
    [CmdletBinding(DefaultParameterSetName='FilePath')]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,

        [Parameter(Mandatory=$true, ParameterSetName='FilePath')]
        [ValidateNotNullOrEmpty()]
        [string]$Script,

        [Parameter(Mandatory=$true, ParameterSetName='ScriptBlock')]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [string]$LogFile
    )

    $wmiReturnCodes = @{
        0  = "Successful completion"
        2  = "Access denied"
        3  = "Insufficient privilege"
        8  = "Unknown failure"
        9  = "Path not found"
        21 = "Invalid parameter"
    }

    $localNames = @('localhost', '127.0.0.1', '::1', $env:COMPUTERNAME, [System.Net.Dns]::GetHostName())
    if ($localNames -contains $Computer) {
        throw "Invoke-DetachedPSScript is intended for remote hosts. Skipping local machine: $Computer"
    }

    $tempFilePrefix = "InvokeDetachedPSScript_AutoGenerated_"
    $localTempFileToCleanup = $null

    # --- STEP 1: Determine Script Paths & Generate Temp File if Needed ---
    if ($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
        $uniqueId = [guid]::NewGuid().ToString()
        $tempFileName = "$tempFilePrefix$uniqueId.ps1"
        
        $localScriptPath = Join-Path $env:TEMP $tempFileName
        $localTempFileToCleanup = $localScriptPath
        
        Write-Verbose "Writing ScriptBlock to local temp file: $localScriptPath"
        $ScriptBlock.ToString() | Out-File -FilePath $localScriptPath -Encoding UTF8 -Force
    } else {
        $localScriptPath = (Resolve-Path -LiteralPath $Script -ErrorAction Stop).ProviderPath
    }

    # --- STEP 2: Pre-check, Cleanup, and Copy via PSSession ---
    $psSession = $null
    try {
        Write-Verbose "Establishing PSSession to $Computer for cleanup and file transfer..."
        $psSession = New-PSSession -ComputerName $Computer -ErrorAction Stop
        
        Write-Verbose "Running cleanup job for old temporary script files..."
        Invoke-Command -Session $psSession -ScriptBlock {
            $prefix = $using:tempFilePrefix
            $targetDir = $env:TEMP
            $cutoffTime = (Get-Date).AddHours(-24)
            
            Get-ChildItem -Path $targetDir -Filter "$prefix*.ps1" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoffTime } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }

        if ($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
            $remoteTempDir = Invoke-Command -Session $psSession -ScriptBlock { $env:TEMP }
            $remoteScriptPath = Join-Path $remoteTempDir $tempFileName
        } else {
            $remoteScriptPath = $localScriptPath
        }

        $fileExists = Invoke-Command -Session $psSession -ScriptBlock { Test-Path -LiteralPath $using:remoteScriptPath }
        
        if (-not $fileExists) {
            Write-Verbose "Script not found on target. Copying to $remoteScriptPath..."
            $remoteDir = Split-Path -Path $remoteScriptPath -Parent
            
            Invoke-Command -Session $psSession -ScriptBlock {
                if (-not (Test-Path -LiteralPath $using:remoteDir)) {
                    New-Item -ItemType Directory -Path $using:remoteDir -Force | Out-Null
                }
            }
            
            Copy-Item -Path $localScriptPath -Destination $remoteScriptPath -ToSession $psSession -ErrorAction Stop
        } else {
            Write-Verbose "Script already exists on remote machine."
        }
    } catch {
        throw "Failed during remote file operations (cleanup/copy) on $Computer : $_"
    } finally {
        if ($null -ne $psSession) { Remove-PSSession $psSession -ErrorAction SilentlyContinue }
        
        if ($localTempFileToCleanup -and (Test-Path $localTempFileToCleanup)) {
            Write-Verbose "Cleaning up local temporary file: $localTempFileToCleanup"
            Remove-Item -Path $localTempFileToCleanup -Force -ErrorAction SilentlyContinue
        }
    }

    # --- STEP 3: Execute as Detached Process via CIM/WMI ---
    $cimSession = $null
    try {
        Write-Verbose "Establishing CIM session to execute process on $Computer"
        $cimSession = New-CimSession -ComputerName $Computer -ErrorAction Stop

        $psPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

        # Using Start/Stop-Transcript via -Command
        if ([string]::IsNullOrWhiteSpace($LogFile)) {
            $cmd = "`"$psPath`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$remoteScriptPath`""
        } else {
            $cmd = "`"$psPath`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"Start-Transcript -Path '$LogFile' -Append -Force; try { & '$remoteScriptPath' } finally { Stop-Transcript }`""
        }

        Write-Verbose "Executing command via WMI: $cmd"
        $r = Invoke-CimMethod -CimSession $cimSession -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
        
        if ($r.ReturnValue -ne 0) {
            $reason = if ($wmiReturnCodes.ContainsKey([int]$r.ReturnValue)) { $wmiReturnCodes[[int]$r.ReturnValue] } else { "Unknown WMI Error" }
            throw "Process creation failed. ReturnValue=$($r.ReturnValue) ($reason)."
        } elseif (-not $r.ProcessId) {
            throw "Process creation failed. No ProcessId was returned by WMI."
        }

        [pscustomobject]@{
            ComputerName  = $Computer
            ProcessId     = $r.ProcessId
            ReturnValue   = $r.ReturnValue
            Status        = "Success"
            ExecutionPath = $remoteScriptPath
        }

    } catch {
        Write-Error "Failed to execute detached process on $Computer : $_"
    } finally {
        if ($null -ne $cimSession) { Remove-CimSession $cimSession -ErrorAction SilentlyContinue }
    }
}

function Get-ProcessesWithMatchingCommandLine($likeExpression) {
<#
.DESCRIPTION
List processes with command lines matching a like expression (e.g. "*myScript.ps1*")
.EXAMPLE
Get-ProcessesWithMatchingCommandLine "*myScript.ps1*" 
#>
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" `
        |Sort-Object CreationDate `
        |Select-Object ProcessId,CreationDate,CommandLine `
        |?{$_.commandline -like $likeExpression}
}

<#
.SYNOPSIS
  Tests whether an executable can be resolved either as a full path or via PATH/PATHEXT.

.DESCRIPTION
  Accepts either:
    - A rooted path (e.g. C:\Tools\uchardet or C:\Tools\uchardet.exe), in which case it checks existence and,
      if no extension was given, also tries common executable extensions (.exe/.cmd/.bat/.com).
    - A bare command name (e.g. uchardet), in which case it resolves it the same way PowerShell would when
      launching a process (Get-Command + PATHEXT).
  Returns $true if the executable can be found, otherwise $false.
#>
function Test-ExeFound {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,Position=0)][string]$Exe
  )

  if([string]::IsNullOrWhiteSpace($Exe)){ return $false }
  $x = $Exe.Trim()

  if([IO.Path]::IsPathRooted($x)){
    if(Test-Path -LiteralPath $x){ return $true }
    $ext = [IO.Path]::GetExtension($x)
    if([string]::IsNullOrWhiteSpace($ext)){
      foreach($e in @('.exe','.cmd','.bat','.com')){
        if(Test-Path -LiteralPath ($x + $e)){ return $true }
      }
    }
    return $false
  }

  $c = Get-Command -Name $x -CommandType 'Application' -ErrorAction SilentlyContinue
  if($c){ return $true }

  $pathext = ($env:PATHEXT -split ';' | Where-Object { $_ } | ForEach-Object { $_.Trim() })
  if($x -match '\.'){ return $false }
  foreach($e in $pathext){
    if(Get-Command -Name ($x + $e) -ErrorAction SilentlyContinue){ return $true }
  }
  return $false

}

