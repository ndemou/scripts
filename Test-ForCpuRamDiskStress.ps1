<#
.SYNOPSIS
Prints a detailed warning every time it finds RAM, CPU or Disks are stressed

.EXAMPLE
C:> c:\it\bin\Test-ForCpuRamDiskStress.ps1 | Tee-Object "C:\it\temp\CpuRamDiskStress.log"

20:12:47 HIGH <HOSTNAME> Reasons:
 - Available memory minimum 0,5% is below the 5% threshold while average Page Reads/sec is  319, above the 150 threshold. Low headroom with active hard faults indicates real stress.
 - High classification gate satisfied: Available memory(%) minimum 0,5 is below the 10% gate threshold.
Measurements:
 - Time window: 18 secs (9 samples)
 - Available memory: average 68,3%, minimum 0,5%
 - Committed memory: average 31,9%, maximum 67,0%
 - Paging file usage: maximum 73%
 - Page Reads/sec (hard faults): average 319, maximum 1.789
 - Page Writes/sec: average 23, maximum 203
 - Transition Faults/sec: average 1.281, maximum 6.797
 - Disk read latency: average 0,0 ms
 - Disk write latency: average 0,0 ms
 - Disk queue length: average 7,3
 - Standby cache memory: Normal 58 MB, Reserve 222 MB, Core 0 MB
 - File cache memory: 4 MB
 - Modified page list: 134 MB
 - Compressed memory: 0 MB

.DESCRIPTION
There are two modes of operation: monitoring and log file analysis.

In monitor mode (the default) it prints a detailed warning every
time it finds RAM, CPU or Disks are stressed.

In monitor mode these switches may be used.
    -MonitorVolumes:   Will also monitor IO stress of Volumes
    -DontMonitorDisks: Will NOT monitor  IO stress of disks

In log analysis (invoked if you supply a -LogFile) it creates a
summary report based on the contents of the log file.

In log analysis mode these arguments may be used.
    -Granularity
    -LogsToIgnoreRegex
#>

param(
    [string]$Granularity = "1h",
    [string]$LogFile = "",
    [string]$LogsToIgnoreRegex = 'Last check took|High stress on volume|High per-core CPU',
    [switch]$MonitorVolumes,
    [switch]$DontMonitorDisks,
    [string]$LogBaseName="CpuRamDiskStress",
    [string]$LogDir
)

<#
********************************************
 Thresholds Reference for the Memory Stress Classifier
********************************************
Sampling & Window
- Sample cadence: 4 seconds per sample (99% of time it's enough for CIM to return results).
- Window size: last 9 samples (~=18 seconds).
- "Sustained" means a condition is met for >=6 consecutive samples (~=12 seconds).

Core Signals (what they mean)
- Page Reads/sec (hard faults): OS reading paged-out/mapped pages back into RAM.
- Page Writes/sec: OS evicting pages to pagefile due to stress.
- Available memory (%): free+zero+reclaimable standby as percent of total RAM.
- Commit %: committed bytes as percent of commit limit (RAM + pagefile).
- Paging File %: pagefile space utilization.
- Transition Faults/sec: working-set trimming/churn (early stress indicator).
- Disk Latency (ms): impact of paging on storage; >=10ms is concerning on modern SSDs.

Gating Rule for "HIGH"
- "HIGH" requires at least one "context gate" to be true:
  * Available memory(%) minimum < 10   OR
  * Committed memory(%) average >= 80   OR
  * Disk read latency (ms) average >= 10

Classification Rules (in order)
1) EXTREME
   - E1: Sustained Page Reads/sec >= 150 AND (Avg Read ms >= 20 OR Avg Write ms >= 20)
     (Users feel stalls; paging is bound by slow storage.)
   OR
   - E2: Available memory(%) minimum <= 3 AND Commit% maximum >= 92 AND Paging File% maximum >= 85
     (Imminent/active virtual memory exhaustion.)

2) HIGH  (only if the HIGH gate above is satisfied)
   Any of:
   - H1: Sustained Page Reads/sec >= 150
   - H2: Avg Page Reads/sec >= 500
   - H3: Available memory(%) minimum <= 5 AND (Avg Page Reads/sec >= 150 OR Avg Transition Faults/sec >= 2000)
   - H4: Commit% maximum >= 90

3) MEDIUM
   Any of:
   - M1: Available memory(%) minimum <= 10 AND (Avg Page Reads/sec >= 50 OR Avg Transition Faults/sec >= 1200)
   - M2: Avg Page Reads/sec >= 150
   - M3: Commit% average >= 80

4) LOW
   Any of:
   - L1: Available memory(%) minimum <= 15 AND Avg Page Reads/sec < 50 AND Commit% average < 80
   - L2: Avg Transition Faults/sec >= 800

5) NONE
   - No thresholds exceeded.

Reason Strings (style guidance)
- Always state: observed value, exact threshold, and short meaning.
  Example:
  "Average Page Reads/sec over the time window is ~= 612, which exceeds the 500 threshold.
   A Page Read occurs on a hard page fault--fetching a page from disk back into RAM."

Operational Notes
- "High" is designed to avoid false positives from harmless, fast paging by requiring
  either low headroom (Avail% <10), elevated commit (>=80%), or slow storage (>=10ms read).
- Transition Faults highlight churn before true paging; interpret alongside Page Reads/sec.
- Page Writes/sec > 0 typically signals eviction under stress; watch if it coincides with low Avail%.
- Disk latency averages are over the same 18s window; spikes may be smoothed--use with the sustained rule.


********************************************
********************************************
********************************************
EXAMPLE OF HOW TO DOWNLOAD, INSTALL (setup scheduled task) AND START
********************************************
********************************************
********************************************
    $folder          = "C:\it\bin"
    $scriptName      = "Test-ForCpuRamDiskStress.ps1"
    $arguments       = '-LogBaseName "CpuRamDiskStress" -LogDir "C:\it\log"'
    $scriptFullName  = "$folder\$scriptName"
    $taskName        = "$($scriptName -replace '\.ps1$') (enLogic)"
    $taskDescription = "Run $scriptFullName on system startup"

    # DOWNLOAD
    #----------------------------
    iwr -useb https://wiki.enlogic.gr/pub/KnowledgeBase/PublicFiles/$scriptName -OutFile "$scriptFullName"

    # CREATE SCHEDULED TASK that runs the script on startup using the SYSTEM account
    #-------------------------------------------------------------------------------
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoLogo -NoProfile -ExecutionPolicy Bypass ' +
        '-File "' + $scriptFullName + '" ' +
        $arguments
    )

    $trigger   = New-ScheduledTaskTrigger  -AtStartup

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
                                            -LogonType ServiceAccount `
                                            -RunLevel Highest

    $settings  = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName $taskName `
                           -Action $action `
                           -Trigger $trigger `
                           -Principal $principal `
                           -Settings $settings `
                           -Description $taskDescription `
                           -Force

    Start-ScheduledTask -TaskName $taskName 
    
    # You can remove the scheduled task like this:
    # Unregister-ScheduledTask -TaskName $taskName

********************************************
********************************************
********************************************
                   TODO
********************************************
********************************************
********************************************

After my laptop wakes up it gives a lot of RAM & CPU pressure events for 
a bit less than a minute. I should probably ignore pressure for the 
1st minute or so after resume and for 2-3mins after boot. 

Detect sustained stresses (consecutive samples with high stress) and
append a note at the stress log: e.g.:
   ". This stress is sustained for the last 0.2min." 
Also detect periods of "overal" stress. I.e. consecutive samples with
at least one subsystem under high stress. 
If during a sample no specific subsystem is at high stress but we
are under "overal" stress we log this warning:
"For every sample during the last 0.9min one or more subsystems were under stress".

On every sample write a log line like this:
    15:14:23 CPU:100 Memory:98 Storage:90 single-core:H
(Storage = Disk or Volume stress).

I want something that will allow me to compare days between them.
It's nice to know how many sustained stress events we had per day 
(e.g. 5 times) and the longest period of sustained stress 
(e.g. 126 sec). We must ignore non-office hours.


===========================================================
Review in-code TODO notes before looking at the following. 
===========================================================

---
Win32_PerfFormattedData_PerfDisk_LogicalDisk will yield things like HarddiskVolume1, _Total, and sometimes mount-point names. You exclude _Total, but you keep HarddiskVolume*, which are often meaningless to operators and can drown real problems. Filter to drive-letter volumes only:

Keep only names matching ^[A-Z]:$.

Or build a map from Win32_LogicalDisk (DriveType=3) and intersect with that set before stressing.
---
CurrentDiskQueueLength >= 1 or 2 as "medium/high" is brittle: it depends on the device's queue depth, NCQ, #paths, and workload. A single queue depth of 1 on a modern NVMe is normal. If you keep QLen in the rule, couple it with latency and IO presence (you already do); otherwise deprioritize QLen and prefer latency+IO thresholds.
---
You gate PF health on $pfKnown via _Total %Usage. _Total can be non-null even when individual files are missing (rare class quirks), and your per-PF checks rely on Build-PagefileInstances mapping to Win32_LogicalDisk. If a PF sits on a mount-point path under C:\Mounts\..., the letter extraction via Substring(0,1)+':' maps it to C: and produces wrong free-space readings. Prefer resolving the PF path to the actual volume (e.g., Get-Item $pf.Path | Get-Volume) and then compare by UniqueId rather than letters.
---
if (($now-$lastT).TotalSeconds -gt (4*$SAMPLE_EVERY_SEC)) { $script:MemPressHistory=@() }
A brief GC pause or CIM stall >4s wipes the context and you'll miss "sustained" gates. Consider soft-decay (cap window at last 9 by time, not hard reset), or allow one grace gap before clearing.
---
You derive DiskStressPerVolume but memory classification gates only look at averaged totals (P95ReadMs/P95WriteMs derived from ReadMs/WriteMs in the history, which come from totals). If a single hot volume is slow but totals look fine, HIGH may not trigger. Consider using the max of per-disk/volume latencies (or the worst disk named in $metrics.Data.WorstDiskAt) for the IO gate.
---

#>

################################################
#
#   CONFIGURATION
#
    $PF_FREE_PCT_WARN    = 5
    $PF_FREE_GB_WARN     = 5
    $PF_USAGE_HIGH_PCT   = 85

    $SAMPLE_EVERY_SEC    = 6  
    # The limit on how low you can go is the time needed to collect all metrics from the OS
    # Also going low increases CPU usages
    # Most systems I have tested need at most 2-3sec with 1-2% CPU utilization.
    # (it *seems* that domain controllers need 60-90% more time)
    # But I settled for 6 because it gives a nice 10 samples/min, 60 samples/hr
    # If you change it, adjust $MinEventsPerPeriod accordingly (they are inversely proportional)
    # and also adjust SUSTAINED_SECONDS to be an exact multiple

    $SUSTAINED_SECONDS   = 3 * $SAMPLE_EVERY_SEC 
    # Must be a multiple of $SAMPLE_EVERY_SEC
#
#   CONFIGURATION
#
################################################

$script:MemPressHistory     = @()
$script:WarnNext            = @{}
$script:PFVolumeLetters     = $null
$script:PFLogicalDiskInfo   = $null

<# 
.Synopsis
Function to output error details in a catch {...} block
.Example
 try {$x=1/0} catch {Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name}
#>
function Write-ErrorDetails {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Context = ''
    )
    $e = $ErrorRecord
    Write-ThrottledLog -HighPriority "Message : $($e.Exception.Message); Type : $($e.Exception.GetType().FullName) Context: $Context"
    if ($e.InvocationInfo) {
        Write-ThrottledLog -HighPriority "Line #$($e.InvocationInfo.ScriptLineNumber): $($e.InvocationInfo.Line.Trim())"
    }
    if ($e.ScriptStackTrace) {
        Write-ThrottledLog "Stack   : $($e.ScriptStackTrace)"
    }
}

function Fmt([object]$n,[string]$fmt='N1'){
  $ci=[System.Globalization.CultureInfo]::InvariantCulture
  if ($null -eq $n) { return 'n/a' }
  try { [string]::Format($ci,"{0:$fmt}",[double]$n) } catch { 'n/a' }
}

function Get-Percentile { param([double[]]$Values,[double]$Percentile)
  if (-not $Values -or $Values.Count -eq 0) { return [double]::NaN }
  $arr=@($Values | Sort-Object); $p=[math]::Min([math]::Max($Percentile,0),100)
  $idx=[math]::Floor(($p/100.0)*([double]($arr.Count-1))); if($idx -lt 0){$idx=0}; if($idx -ge $arr.Count){$idx=$arr.Count-1}
  [double]$arr[$idx]
}

<#
.SYNOPSIS
Line-based, burst-friendly, rate-limited warning emitter with separate budgets for normal and high-priority messages.

.DESCRIPTION
Write-ThrottledLog enforces output discipline when many warnings could flood the logs. 
It counts **lines** (not messages) and applies an **all-or-nothing** policy: if the entire 
message (all lines) fits in the current budget, it writes the whole message to the log file
otherwise, it prints nothing.

Two independent token buckets are maintained:

1) Normal bucket (the "background" rate limit)
   - Capacity: 30 lines
   - Refill rate: ~1 line per minute
   - Used by calls without -HighPriority.
   - Also serves as a secondary reservoir for -HighPriority when its own budget is insufficient (see below).

2) High-priority bucket (the "urgent" fast lane)
   - Capacity: 60 lines
   - Refill rate: ~60 lines per minute (~=1 line/second)
   - Used first by calls **with** -HighPriority.
   - If the high bucket lacks enough tokens to cover the entire message, the function will borrow the remainder
     from the normal bucket. If not, the message is dropped (no partial prints).

Refill happens on each call based on real elapsed minutes since the last refill timestamp, up to each bucket's max
capacity. Time math is continuous (fractional minutes are allowed) and uses the process clock at the moment of call.

STATE & SCOPE
- Uses three **script** variables for easy interactive diagnostics:
  - `$script:WTL_MainTokens`     - current tokens in the normal bucket
  - `$script:WTL_HighTokens`     - current tokens in the high-priority bucket
  - `$script:WTL_LastRefill`     - [DateTime] of last refill calculation
- If these variables do not exist, the function initializes them to full capacity at first call. Subsequent calls
  reuse and update the same global state.

PARAMETERS
- `-Message [string]` (required): The text to emit via Write-Warning if accepted. May contain multiple lines.
- `-HighPriority` (switch): Uses the high-priority bucket; may borrow from the normal bucket if High is short.

RATES & CAPACITIES (defaults)
- Normal: Capacity = 30 lines; Refill = 1 line/minute (soft cap ~1 line per minute over time).
- High:   Capacity = 60 lines; Refill = 60 lines/minute (~=1 per second, intended for urgent bursts).
- Design intent: high-priority can surface bursts quickly; normal maintains a low steady trickle. Allowing high
  to borrow from normal ensures urgent messages can still pass when high budget is momentarily short-without
  complicating the code. 

REFILL DETAILS
- On each call: `deltaMin = (Now - $script:WTL_LastRefill).TotalMinutes`
- Apply: `Main += deltaMin * 1.0`, `High += deltaMin * 60.0`; clamp each to its capacity.
- Update `$script:WTL_LastRefill` to `Now`.

EDGE CASES & NOTES
- Clock skew (e.g., manual system time change) affects refill calculations at the next call. Minor inaccuracies are
  acceptable for throttling.
- State is **per-process**; different PowerShell processes have independent budgets.
- If you prefer module-scoped state, switch `$script:` variables to `$script:` inside your module and export setter/getter helpers.

TUNING
- To reduce overall verbosity: lower capacities or refill rates.

#>
function Write-ThrottledLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Message,
        [switch]$HighPriority,
        [switch]$AlwaysLog,
        [string]$LogDir,
        [string]$LogBaseName
    )

    # ---- Config ----
    $MainCapacity=30.0; $MainRefillPerMinute=1.0
    $HighCapacity=60.0; $HighRefillPerMinute=60.0

    # ---- Persist logging targets globally (pass once) ----
    if ($PSBoundParameters.ContainsKey('LogDir'))      { $script:WTW_LogDir = $LogDir }
    if ($PSBoundParameters.ContainsKey('LogBaseName')) { $script:WTW_LogBaseName = $LogBaseName }

    if (-not (Get-Variable -Name WTW_LogDir      -Scope Script -ErrorAction SilentlyContinue)) { $script:WTW_LogDir = $null }
    if (-not (Get-Variable -Name WTW_LogBaseName -Scope Script -ErrorAction SilentlyContinue)) { $script:WTW_LogBaseName = $null }

    # ---- Token buckets (script for continuity) ----
    if (-not (Get-Variable -Name WTW_MainTokens -Scope Script -ErrorAction SilentlyContinue)) { $script:WTW_MainTokens = $MainCapacity }
    if (-not (Get-Variable -Name WTW_HighTokens -Scope Script -ErrorAction SilentlyContinue)) { $script:WTW_HighTokens = $HighCapacity }
    if (-not (Get-Variable -Name WTW_LastRefill -Scope Script -ErrorAction SilentlyContinue)) { $script:WTW_LastRefill = Get-Date }

    if ([string]::IsNullOrEmpty($Message)) { return }
    if (-not $script:WTW_LogDir -or -not $script:WTW_LogBaseName) { return }

    # ---- Split into logical lines (ignore trailing empty) ----
    $parts = [regex]::Split($Message, "\r?\n")
    $lineCount = $parts.Length
    if ($lineCount -gt 0 -and $parts[$parts.Length-1] -eq '') { $lineCount = $lineCount - 1 }
    if ($lineCount -le 0) { return }

    $now  = Get-Date
    $date = $now.ToString('yyyy-MM-dd')
    $file = Join-Path $script:WTW_LogDir ("{0}.{1}.log" -f $script:WTW_LogBaseName, $date)

    if (-not (Test-Path $script:WTW_LogDir)) {
        New-Item -Path $script:WTW_LogDir -ItemType Directory -Force | Out-Null
    }

    # ---- Prepare final text lines (timestamp + computer + message line) ----
    $linesToWrite = @()
    for ($i=0; $i -lt $lineCount; $i++) {
        $linesToWrite += ("{0} {1} {2}" -f $now.ToString('s'), $env:COMPUTERNAME, $parts[$i])
    }

    # ---- Helper: write to log (UTF-8, no BOM) ----
    function _writeFile([string[]]$lines,[string]$path) {
        $enc = New-Object System.Text.UTF8Encoding($false)
        $sw  = New-Object System.IO.StreamWriter($path, $true, $enc)
        try { foreach($l in $lines){ $sw.WriteLine($l) } } finally { $sw.Dispose() }
    }

    # ---- Helper: write to console with colors ----
    function _writeConsole([string[]]$lines,[bool]$isHigh,[bool]$isAlways) {
        $msgColor = 'DarkGray'
        if ($isAlways) { $msgColor = 'Red' }
        elseif ($isHigh) { $msgColor = 'White' }

        foreach($l in $lines){
            # l is "YYYY-MM-DDTHH:mm:ss COMPUTER message"
            $sp = $l.IndexOf(' ')
            if ($sp -lt 0) { Write-Host $l -ForegroundColor $msgColor; continue }
            $ts = $l.Substring(0,$sp)
            $rest = $l.Substring($sp+1)
            $sp2 = $rest.IndexOf(' ')
            if ($sp2 -lt 0) {
                Write-Host -NoNewline $ts -ForegroundColor Green
                Write-Host (" " + $rest) -ForegroundColor $msgColor
                continue
            }
            $comp = $rest.Substring(0,$sp2)
            $msg  = $rest.Substring($sp2+1)

            Write-Host -NoNewline $ts -ForegroundColor Green
            Write-Host -NoNewline (" " + $comp + " ") -ForegroundColor Cyan
            Write-Host $msg -ForegroundColor $msgColor
        }
    }

    _writeConsole $linesToWrite $HighPriority.IsPresent $AlwaysLog.IsPresent

    # ---- AlwaysLog path: bypass buckets entirely ----
    if ($AlwaysLog.IsPresent) {
        _writeFile $linesToWrite $file
        return
    }

    # ---- Refill buckets ----
    $mins = ($now - $script:WTW_LastRefill).TotalMinutes
    if ($mins -gt 0) {
        $script:WTW_MainTokens = [math]::Min($MainCapacity, $script:WTW_MainTokens + ($mins * $MainRefillPerMinute))
        $script:WTW_HighTokens = [math]::Min($HighCapacity, $script:WTW_HighTokens + ($mins * $HighRefillPerMinute))
        $script:WTW_LastRefill = $now
    }

    # ---- Spend tokens (all-or-nothing for the whole message) ----
    if ($HighPriority.IsPresent) {
        $useHigh   = [int][math]::Floor([math]::Min($lineCount, $script:WTW_HighTokens))
        $remainder = $lineCount - $useHigh
        if ($remainder -le [int][math]::Floor($script:WTW_MainTokens)) {
            $script:WTW_HighTokens -= $useHigh
            $script:WTW_MainTokens -= $remainder
            _writeFile $linesToWrite $file
            return
        }
        Write-Host "`t`t`tABOVE MESSAGE WAS THROTLED; MainTokens=$($script:WTL_MainTokens) HighTokens=$($script:WTL_HighTokens) $($script:WTL_LastRefill)" -ForegroundColor magenta
        return
    } else {
        if ($lineCount -le [int][math]::Floor($script:WTW_MainTokens)) {
            $script:WTW_MainTokens -= $lineCount
            _writeFile $linesToWrite $file
            return
        }
        Write-Host "`t`t`tABOVE MESSAGE WAS THROTLED; MainTokens=$($script:WTL_MainTokens) $($script:WTL_LastRefill)" -ForegroundColor magenta
        return
    }
}



# per-disk metrics (PhysicalDisk instances, including _Total)
# RETURNS: { '<inst>'=@{QLen,ReadMs,WriteMs,Busy}... }
function Get-CimDiskPerDisk {
  $diskStressPerDisk = @{}
  $result=@{}; $q='none'
  $rows = @()
  # Ignored these: DiskReadsPerSec,DiskWritesPerSec,AvgDisksecPerRead,AvgDisksecPerWrite
  $rows = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk `
          -Property Name,PercentIdleTime,CurrentDiskQueueLength `
          -ErrorAction SilentlyContinue | Where-Object Name -ne '_Total'
  foreach($r in $rows){
    $inst=$r.Name
    $result[$inst]=@{
      QLen   = $r.CurrentDiskQueueLength
      ReadMs = $r.AvgDisksecPerRead*1000
      WriteMs= $r.AvgDisksecPerWrite*1000
      Busy   = 100-$r.PercentIdleTime
    }
  }
  return $result
}

# RETURNS: { '<inst>'=@{QLen,ReadMs,WriteMs,Busy}... }
# Exactly as Get-CimDiskPerDisk but for storage Volumes
function Get-CimDiskPerVolume{
  $result=@{}; $q='none'
  $rows = @()
  $rows = Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk `
          -Property Name,PercentIdleTime,CurrentDiskQueueLength `
          -ErrorAction SilentlyContinue
  foreach($r in $rows){
    $n=$r.Name
    $result[$n]=@{
      QLen   = $r.CurrentDiskQueueLength
      ReadMs = $r.AvgDisksecPerRead*1000
      WriteMs= $r.AvgDisksecPerWrite*1000
      Busy   = 100-$r.PercentIdleTime
    }
  }
  if($result.Count -gt 0){ $q='cim' }
  return $result
}


# classify instantaneous disk stress using totals 'low ...', 'medium ...', 'high ...', 'unknown'
function Get-DiskStressString($qLen,$readMsec,$WriteMsec,$Busy){
  $allMetrics = "All metrics: Busy=$Busy%, qLen=$qLen, ReadMsec=$readMsec, WriteMsec=$writeMsec"
  if ($Busy -and ($Busy -gt 90)) {return "High   Trigered by: Busy=$Busy%. $allMetrics"}
  if ($Busy -and ($Busy -ge 75)) {return "Medium Trigered by: Busy=$Busy%. $allMetrics"}
  if ($Busy -and ($Busy -lt 75)) {return "Low    Trigered by: Busy=$Busy%. $allMetrics"}
  if ($WriteMsec -or $readMsec) {
      $WriteMsec=[int]$WriteMsec
      $readMsec=[int]$readMsec
      if ($readMsec -ge 20)      {return "High   Trigered by: ReadMsec=$readMsec. $allMetrics"}
      if ($WriteMsec -ge 20)     {return "High   Trigered by: WriteMsec=$writeMsec. $allMetrics"}
      if ($readMsec -ge 10)      {return "Medium Trigered by: ReadMsec=$readMsec. $allMetrics"}
      if ($WriteMsec -ge 10)     {return "Medium Trigered by: WriteMsec=$writeMsec. $allMetrics"}
  }
  return 'Unkown'
}

# RETURNS: @{'Total'=int; 'CoreN'=int; ...}
function Get-CimCpuUtil {
  $result=@{}
  try {
    $rows = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor `
              -Property Name,PercentProcessorTime -ErrorAction Stop |
              Where-Object {
                # Skip aggregate and any Hyper-V pseudo or malformed names
                $_.Name -ne '_Total' -and $_.Name -match '^\d+$'
              }
    # If none matched, fallback to numeric-prefix cleanup for Hyper-V host cases
    if (-not $rows -or $rows.Count -eq 0) {
      $rows = $null
      $rows = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor `
                 -Property Name,PercentProcessorTime -ErrorAction SilentlyContinue |
                 Where-Object {
                   $_.Name -match '^\d+' -and $_.Name -notmatch 'Hyper-V'
                 }
    }
    if ($rows) {
      foreach ($r in $rows) {
        $idx = [regex]::Match($r.Name,'^\d+').Value
        if ($idx -ne '') {
          $result["Core$idx"] = [int][math]::Round([double]$r.PercentProcessorTime)
        }
      }
    }
    $total = $null
    $total = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor `
                -Property Name,PercentProcessorTime -Filter "Name='_Total'" -ErrorAction SilentlyContinue
    if ($total) { $result['Total'] = [int][math]::Round([double]$total.PercentProcessorTime) }

  } catch {Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name}
  return $result
}

# RETURNS: [pscustomobject[]] of @{ Path, AllocatedMB, CurrentMB, PeakMB, Drive=<Win32_LogicalDisk or $null> }
function Build-PagefileInstances { param($PFUsage,$PFDisks)
  $ldById=@{}
  if($PFDisks){
    foreach($ld in $PFDisks){
      $ldById[$ld.DeviceID]=$ld
    }
  }
  $pfInst=@()
  if ($PFUsage){
    foreach($p in $PFUsage){
      $drive=$null
      if ($p.Name){ $letter=($p.Name.Substring(0,1)+':')
      if ($ldById.ContainsKey($letter)){
        $drive=$ldById[$letter] }
      }
      $pfInst += [pscustomobject]@{
        Path=$p.Name
        AllocatedMB=[double]$p.AllocatedBaseSize
        CurrentMB=[double]$p.CurrentUsage
        PeakMB=[double]$p.PeakUsage
        Drive=$drive
      }
    }
  }
  $pfInst
}

# local helper to derive Memory record & quality (PDH or OS)
function Get-CimMemoryMetrics {
  $mem = $null
  $mem = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction SilentlyContinue -Property `
         AvailableMBytes,PageReadsPerSec,PageWritesPerSec,TransitionFaultsPerSec,CommittedBytes,CommitLimit, `
         SystemCacheResidentBytes,StandbyCacheNormalPriorityBytes,StandbyCacheReserveBytes,StandbyCacheCoreBytes, `
         ModifiedPageListBytes `
         | Select -Property `
         AvailableMBytes,PageReadsPerSec,PageWritesPerSec,TransitionFaultsPerSec,CommittedBytes,CommitLimit, `
         SystemCacheResidentBytes,StandbyCacheNormalPriorityBytes,StandbyCacheReserveBytes,StandbyCacheCoreBytes, `
         ModifiedPageListBytes
  if ($mem) {
    return $mem
  } else {
    Write-ThrottledLog "Degraded mode: No info for Page File."
    return $null
  }
}

<#
.SYNOPSIS
Lightweight one-shot snapshot of memory, paging, CPU, and disk metrics with minimal overhead.

EXAMPLE RETURN VALUE
    Time                : 2025-11-11 22:14:22
    TotalMB             : 15591.42578125
    AvailMB             : 4969
    AvailPct            : 31.8700808361968
    PageR               : 0
    PageW               : 0
    TransF              : 22
    CommitGB            : 21.1262893676758
    CommitLimitGB       : 34.226001739502
    CommitPct           : 61.7258467070457
    PFPct               : 6
    PFPeak              : 10
    PFInstances         : @{Path=C:\pagefile.sys; AllocatedMB=19456; CurrentMB=1358; PeakMB=1992; Drive=Win32_LogicalDisk
                          (DeviceID = "C:")}
    CacheMB             : 841.875
    StandbyNMB          : 2767.09765625
    StandbyRMB          : 1551.51171875
    StandbyCMB          : 91.8203125
    ModListMB           : 81.97265625
    DiskQLen            : 0
    ReadMs              : 0
    WriteMs             : 0
    DiskStressPerDisk   : {0 C:}
    DiskStressPerVolume : {HarddiskVolume1, C:, HarddiskVolume4}
    WorstDiskStress     : low
    WorstDiskAt         : 0 C:
    CPUUtil             : {Total, Core6, Core0, Core4...}
#>
function Get-PerfSnapshot {
  $pfAll=$null; $pfUsage=$null

  $missingInfo=@()

  $basicOSinfo=$null
  $basicOSinfo = Get-CimInstance Win32_OperatingSystem `
        -Property TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory `
        -ErrorAction SilentlyContinue `
        |Select -Property TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory
  if (-not $basicOSinfo)  {
    $missingInfo+='OperatingSystem'
    Write-ThrottledLog "No basic OS info metrics available. THIS IS CRITICAL."
  }

  $pfAll  = Get-CimInstance Win32_PerfFormattedData_PerfOS_PagingFile `
        -Property Name,PercentUsage,PercentUsagePeak `
        -Filter "Name='_Total'" -ErrorAction SilentlyContinue `
        | Select -Property Name,PercentUsage,PercentUsagePeak

  $pfUsage= Get-CimInstance Win32_PageFileUsage `
        -Property Name,AllocatedBaseSize,CurrentUsage,PeakUsage `
        -ErrorAction SilentlyContinue `
        | select -Property Name,AllocatedBaseSize,CurrentUsage,PeakUsage

  # ---------- pagefile backing volumes (cached) ----------
  if ($pfUsage) {
    $letters=@()
    foreach($p in $pfUsage){ if ($p.Name -and $p.Name.Length -ge 2){ $letters += ($p.Name.Substring(0,1)+':') } }
    $letters = $letters | Sort-Object -Unique
    if ($letters.Count -gt 0){
      $key  = ($letters -join '|')
      $need = $true
      if ($script:PFVolumeLetters -ne $null -and $script:PFVolumeLetters -eq $key) { $need=$false }
      if ($need) {
        $or = ($letters | ForEach-Object { "DeviceID='$_'" }) -join ' OR '
        $script:PFLogicalDiskInfo = $null
        $script:PFLogicalDiskInfo = Get-CimInstance Win32_LogicalDisk -Property DeviceID,Size,FreeSpace `
            -Filter ("DriveType=3 AND ({0})" -f $or) -ErrorAction SilentlyContinue `
            | Select -Property DeviceID,Size,FreeSpace
        echo "OR", $or
        echo "PFLogicalDiskInfo", $script:PFLogicalDiskInfo
        $script:PFVolumeLetters = $key
      }
    }
  }

  # ---------- Memory via helper (CIM or OS-aprox) ----------
  $mem = Get-CimMemoryMetrics
  if (-not $mem) {
    Write-ThrottledLog "Memory metrics unavailable from CIM/OS; classification may be 'unknown'."
    $missingInfo+='PerfOS_Memory'
  }
  # ---------- Normalize Memory Info into the final shape with $null for unknowns ----------
  $availMB     = if($mem){ [double]$mem.AvailableMBytes                                                                         } else { $null }
  $pageR       = if($mem -and $mem.PageReadsPerSec        -ne $null){ [double]$mem.PageReadsPerSec                              } else { $null }
  $pageW       = if($mem -and $mem.PageWritesPerSec       -ne $null){ [double]$mem.PageWritesPerSec                             } else { $null }
  $transF      = if($mem -and $mem.TransitionFaultsPerSec -ne $null){ [double]$mem.TransitionFaultsPerSec                       } else { $null }
  $commitB     = if($mem){ [double]$mem.CommittedBytes                                                                          } else { $null }
  $commitLimB  = if($mem){ [double]$mem.CommitLimit                                                                             } else { $null }
  $cacheMB     = if($mem -and $mem.SystemCacheResidentBytes        -ne $null){ [double]$mem.SystemCacheResidentBytes/1MB        } else { $null }
  $standbyNMB  = if($mem -and $mem.StandbyCacheNormalPriorityBytes -ne $null){ [double]$mem.StandbyCacheNormalPriorityBytes/1MB } else { $null }
  $standbyRMB  = if($mem -and $mem.StandbyCacheReserveBytes        -ne $null){ [double]$mem.StandbyCacheReserveBytes/1MB        } else { $null }
  $standbyCMB  = if($mem -and $mem.StandbyCacheCoreBytes           -ne $null){ [double]$mem.StandbyCacheCoreBytes/1MB           } else { $null }
  $modListMB   = if($mem -and $mem.ModifiedPageListBytes           -ne $null){ [double]$mem.ModifiedPageListBytes/1MB           } else { $null }
  $commitGB    = if($commitB   -ne $null){ $commitB/1GB                                                                         } else { $null }
  $commitLimGB = if($commitLimB -ne $null){ $commitLimB/1GB                                                                     } else { $null }
  $commitPct   = if($commitLimB -ne $null -and $commitLimB -gt 0 -and $commitB -ne $null){ ($commitB/$commitLimB)*100           } else { $null }
  $pfPct       = if($pfAll){ [double]$pfAll.PercentUsage                                                                        } else { $null }
  $pfPeak      = if($pfAll){ [double]$pfAll.PercentUsagePeak                                                                    } else { $null }
  $totalMB     = if($basicOSinfo){  [double]$basicOSinfo.TotalVisibleMemorySize/1024                                            } else { $null }
  $availPct    = if($totalMB -ne $null -and $totalMB -gt 0 -and $availMB -ne $null){ ($availMB/$totalMB)*100                    } else { $null }

  # Per-disk stress map: instance -> 'low'|'medium'|'high'
  $result  = Get-CimDiskPerDisk
  $diskStressPerDisk = @{}
  $worstName = $null; $worstRank = -1
  foreach($name in @($result.Keys)){
    $m = $result[$name]
    $p = Get-DiskStressString -qLen $m.QLen -readMsec $m.ReadMs -WriteMsec $m.WriteMs -Busy $m.busy
    $diskStressPerDisk[$name] = $p
    $rank = switch($p -replace ' .*'){ 'low' {0} 'medium' {1} 'high' {2} default {0} }
    # TODO: As we do for worstRank, also derive and report to metrics the max of all these values:
    # $m.QLen $m.ReadMs $m.WriteMs $m.busy
    if ($rank -gt $worstRank){
       $worstRank=$rank; $worstName=$name
    }
  }

  # Per-volume stress map: instance -> 'low'|'medium'|'high'
  $result = Get-CimDiskPerVolume
  $diskStressPerVolume=@{}
  foreach($name in @($result.Keys)){
    $m=$result[$name]
    $diskStressPerVolume[$name]=Get-DiskStressString -qLen $m.QLen -readMsec $m.ReadMs -WriteMsec $m.WriteMs -Busy $m.busy
  }

  $pfInst = Build-PagefileInstances -PFUsage $pfUsage -PFDisks $script:PFLogicalDiskInfo

  $DiskQLen=$null; $DiskRps=$null; $DiskWps=$null; $ReadMs=$null; $WriteMs=$null

  $data = [pscustomobject]@{
    Time = (Get-Date)
    TotalMB = $totalMB
    AvailMB = $availMB
    AvailPct = $availPct
    PageR = $pageR
    PageW = $pageW
    TransF = $transF
    CommitGB = $commitGB
    CommitLimitGB = $commitLimGB
    CommitPct = $commitPct
    PFPct = $pfPct
    PFPeak = $pfPeak
    PFInstances = $pfInst
    CacheMB = $cacheMB
    StandbyNMB = $standbyNMB
    StandbyRMB = $standbyRMB
    StandbyCMB = $standbyCMB
    ModListMB = $modListMB
    DiskStressPerDisk = $diskStressPerDisk
    DiskStressPerVolume = $diskStressPerVolume
    WorstDiskStress = $worstRank
    WorstDiskAt = $worstName
    CPUUtil = Get-CimCpuUtil
  }

  return @{
    Ok=([bool]$basicOSinfo -and [bool]$mem)
    Missing=$missingInfo
    Data=$data
  }
}

# TODO: rewrite the code so that reasons imidiately follow conditions
# e.g.:
#
# $level = ''
# if ($lowPhisicalOrCommitPct -and ($AvgPageR     -ge 500)) {
#   $level = 'high'
#   $reason = "Avg PageReads/Sec >= 500 and $ctxGateReason"
# } elif ($MaxCommitPct -ge 90)  {
#   $level = 'high'
#   $reason = "Memory Commited>=90% of total RAM+Max.Swap and $ctxGateReason"
# } elif (...
#   ...
# if (!$level) {
# ...

<#
.SYNOPSIS
Determines memory-stress level based on 9 samples.

.DESCRIPTION
Given the last-9-sample window aggregates (averages/min/max and a sustained PageReads counter),
applies explicit, documented thresholds to classify stress into:
- extreme: (sustained hard faults AND high disk latency) OR (very low Avail% AND near-commit AND high PF%)
- high:    sustained/strong hard faults BUT only if at least one "context gate" is true:
           Avail% < 10 OR Commit% > 80 OR Read latency > 10 ms; reasons always include exceeded limits
- medium:  moderate signals (e.g., Avg PageReads >= 150, or Commit% avg >= 80, or Avail% <= 10 with churn)
- low

.PARAMETER ConsecHighReads
Consecutive samples with PageReads/sec >= 150, counted backwards from most recent.

.PARAMETER AvgPageR, MaxPageR, AvgPageW, MaxPageW
Aggregated paging IO rates over the window.

.PARAMETER AvgAvailPct, MinAvailPct
Available memory percentage over the window (average and minimum).

.PARAMETER AvgTransF, MaxTransF
Transition faults/sec (working-set trimming/churn) over the window.

.PARAMETER AvgCommitPct, MaxCommitPct
Committed memory as percent of commit limit (average and maximum).

.PARAMETER MaxPFPct
Maximum paging file percent usage over the window.

.PARAMETER AvgReadMs, AvgWriteMs
Average disk read/write latency (milliseconds) over the window.

.OUTPUTS
Hashtable with:
  Level   : 'low'|'medium'|'high'|'extreme'
  Reasons : string (why code chose this level)

.NOTES
This function is intentionally side-effect free and CPU-light; it evaluates already-collected aggregates.

.EXAMPLE
$result = Invoke-DetermineMemoryStress -ConsecHighReads $c -AvgPageR $aPR -MaxPageR $mPR -AvgAvailPct $aAv -MinAvailPct $mAv -AvgCommitPct $aCm -MaxCommitPct $mCm -MaxPFPct $mPF -AvgReadMs $aR -AvgWriteMs $aW
#>
function Invoke-DetermineMemoryStress {
  param(
    [int]$MinSustainedSamplesForExtreme, [int]$SampleCount,
    [double]$AvgPageR,     [double]$MaxPageR,
    [double]$AvgPageW,     [double]$MaxPageW,
    [double]$AvgAvailPct,  [double]$MinAvailPct,
    [double]$MinAvailMB,   [double]$AvgTransF,
    [double]$MaxTransF,    [double]$AvgCommitPct,
    [double]$MaxCommitPct, [double]$MaxPFPct,
    [double]$P95ReadMs,    [double]$P95WriteMs,
    [bool]$HasReadIO,      [bool]$HasWriteIO,
    [bool]$PFKnown
  )
  
  # helper booleans to write smaller human-readable ifs
  $highLatency = ($HasReadIO -and $P95ReadMs -ge 10) -or ($HasWriteIO -and $P95WriteMs -ge 10)
  $veryHighLatency = ($HasReadIO -and $P95ReadMs -ge 20) -or ($HasWriteIO -and $P95WriteMs -ge 20)
  $enoughSamplesForExtreme = ($SampleCount -ge $MinSustainedSamplesForExtreme)
  
  $isStressExtreme = ($enoughSamplesForExtreme -and (($AvgPageR -ge 150 -and $MaxPageR -ge 150) -and $veryHighLatency))
  if ($isStressExtreme) {
    return @{ 
        Level='extreme'
        Reasons="Sustained hard page-ins with slow storage: Avg Reads/sec>=150 and p95 latency>=20 ms."
    }
  }
  
  # another case of extreme stress
  $isStressExtreme = ($enoughSamplesForExtreme -and ($PFKnown -and ($MinAvailPct -le 3 -and $MaxCommitPct -ge 92 -and $MaxPFPct -ge 85)))
  if ($isStressExtreme) {
    return @{ 
        Level='extreme'
        Reasons="Virtual memory exhaustion: Avail min<=3%, Commit max>=92%, Pagefile max>=85%."
    }
  }
  
  $isStressHigh = (
      (($MinAvailPct -le 10) -or ($AvgCommitPct -ge 80) -or $highLatency) -and (
              ($AvgPageR     -ge 500) `
          -or ($MinAvailPct  -le 5   -and ($AvgPageR -ge 150 -or $AvgTransF -ge 2000)) `
          -or ($MaxCommitPct -ge 90) `
          -or ($AvgPageR     -ge 150 -and $HasReadIO)
      )
  )
  if ($isStressHigh) {
      $reasons = ""
      if ($MinAvailPct  -le  10)                         { $reasons += " * High gate: Avail min<= 10%." }
      if ($AvgCommitPct -ge  80)                         { $reasons += " * High gate: Commit avg>= 80% of limit." }
      if ($highLatency)                                  { $reasons += " * High gate: Read or write p95 latency>= 10 ms." }
      if ($AvgPageR     -ge 500)                         { $reasons += " * Avg Page Reads/sec>= 500." }
      if ($MinAvailPct  -le   5 -and $AvgPageR  -ge  150){ $reasons += " * Avail min<= 5% with Avg Reads/sec>= 150." }
      if ($MinAvailPct  -le   5 -and $AvgTransF -ge 2000){ $reasons += " * Avail min<= 5% with Transition Faults avg>= 2000." }
      if ($MaxCommitPct -ge  90)                         { $reasons += " * Commit peaked>= 90% of limit." }
      return @{ Level='high'; Reasons=($reasons) }
  } 

  $isStressMedium = (
          (($MinAvailPct  -le 10) -and ($AvgPageR -ge 50 -or $AvgTransF -ge 1200)) `
      -or  ($AvgPageR     -ge 150) `
      -or  ($AvgCommitPct -ge 80)
  )
  if ($isStressMedium) {
      $reasons = ""
      if ($MinAvailPct  -le 10 -and $AvgPageR -ge 50)    { $reasons += " * Avail min<= 10% and Avg Reads/sec>= 50." }
      if ($MinAvailPct  -le 10 -and $AvgTransF -ge 1200) { $reasons += " * Avail min<= 10% and Transition Faults avg>= 1200." }
      if ($AvgPageR     -ge 150)                         { $reasons += " * Avg Page Reads/sec>= 150." }
      if ($AvgCommitPct -ge 80)                          { $reasons += " * Commit avg>= 80% of limit." }
      return @{ Level='medium'; Reasons=($reasons) }
  } 
  
  return @{ Level='low'; Reasons="" }
  
}

<#
.SYNOPSIS
classifies memory stress based on the supplied metrics

.DESCRIPTION
Takes a single snapshot Get-PerfSnapshot
adds it to a rolling window (last 9 samples),
computes window statistics, and then calls Invoke-DetermineMemoryStress
to derive a stress level: none, low, medium, high, extreme.

For levels high/extreme, returns a verbose human-readable Explanation that starts with detailed Reasons
(including the exact thresholds crossed) followed by one-per-line measurements with plain-English labels.

Key signals: PageReads/sec (hard faults), PageWrites/sec, Available memory %, Commit % of limit,
Transition faults/sec, Paging file %, disk latencies, standby/cache/modified lists, compressed memory.

.OUTPUTS
[pscustomobject] with:
  Estimation  : 'none'|'low'|'medium'|'high'|'extreme'
  Explanation : string (non-empty only for 'high' and 'extreme' by default)

.NOTES
- Uses only PerfFormattedData providers for minimal overhead.
- History is process-local in $script:MemPressHistory; cleared with: $script:MemPressHistory=$null
- "High" is gated: it requires at least one of these context conditions: Avail% < 10 OR Commit% > 80 OR Read latency > 10 ms.

.EXAMPLE
$memResults = Get-MemoryStressEstimate Get-PerfSnapshot
if ($memResults.Estimation -in 'high','extreme') { $memResults.Explanation | Out-String }
#>
function Get-MemoryStressEstimate($snapshot) {
  function avg($p){ if($n){ ($h | % { $_.$p } | ? { $_ -ne $null } | Measure-Object -Average).Average } else { [double]::NaN } }
  function maxv($p){ if($n){ ($h | % { $_.$p } | ? { $_ -ne $null } | Measure-Object -Maximum).Maximum } else { [double]::NaN } }
  function minv($p){ if($n){ ($h | % { $_.$p } | ? { $_ -ne $null } | Measure-Object -Minimum).Minimum } else { [double]::NaN } }

  $now=Get-Date
  if ($script:MemPressHistory.Count -gt 0) {
    $lastT=$script:MemPressHistory[-1].Time
    if (($now-$lastT).TotalSeconds -gt (2*$SAMPLE_EVERY_SEC)) { $script:MemPressHistory=@() }
  }

  if (-not $snapshot.Ok) {
    $missingInfo = ($snapshot.Missing -join ', ')
    return [pscustomobject]@{ Estimation='unknown'; Explanation=("Reasons:`n - Memory counters unavailable; skipping classification (missing: {0}).`nMeasurements:`n - Time window: ~0 secs (0 samples)" -f $missingInfo) }
  }

  $d=$snapshot.Data
  $script:MemPressHistory += $d
  if ($script:MemPressHistory.Count -gt 9) { $script:MemPressHistory = $script:MemPressHistory[-9..-1] }

  $h=$script:MemPressHistory
  $n=$h.Count
  $winSec = $n * $SAMPLE_EVERY_SEC
  $avgPageR=avg 'PageR'
  $maxPageR=maxv 'PageR'
  $avgPageW=avg 'PageW'
  $maxPageW=maxv 'PageW'
  $avgAvailPct=avg 'AvailPct'
  $minAvailPct=minv 'AvailPct'
  $avgTransF=avg 'TransF'
  $maxTransF=maxv 'TransF'
  $avgCommitPct=avg 'CommitPct'
  $maxCommitPct=maxv 'CommitPct'
  $maxPFPct = maxv 'PFPct'

  $reads  = @($h | % { $_.ReadMs }  | ? { $_ -ne $null })
  $writes = @($h | % { $_.WriteMs } | ? { $_ -ne $null })
  $rpsArr = @($h | % { $_.DiskRps } | ? { $_ -ne $null })
  $wpsArr = @($h | % { $_.DiskWps } | ? { $_ -ne $null })
  $sumR = ($rpsArr | Measure-Object -Sum).Sum
  $sumW = ($wpsArr | Measure-Object -Sum).Sum
  $hasReadIO  = ($sumR -gt 0)
  $hasWriteIO = ($sumW -gt 0)
  $p95ReadMs  = Get-Percentile -Values $reads  -Percentile 95
  $p95WriteMs = Get-Percentile -Values $writes -Percentile 95

  $totalMB = if ($n -and $h[-1].TotalMB -ne $null) { [double]$h[-1].TotalMB } else { [double]::NaN }
  $minAvailMB = if ([double]::IsNaN($totalMB) -or [double]::IsNaN($minAvailPct)) { [double]::NaN } else { ($minAvailPct/100.0)*$totalMB }
  $avgQLen = avg 'DiskQLen'
  $avgIOps = ([double](avg 'DiskRps') + [double](avg 'DiskWps'))

  $pfKnown=$true
  if ($n -gt 0) { 
    $val=$h[-1].PFPct
    if ($null -eq $val -or [double]::IsNaN([double]$val)) { $pfKnown=$false } 
  } else { 
    $pfKnown=$false 
  }

  $commitLimitApproxRAM=$false
  if ($n -gt 0) {
    $tMB=$h[-1].TotalMB
    $limGB=$h[-1].CommitLimitGB
    if ($tMB -ne $null -and $limGB -ne $null) {
      $limMB=$limGB*1024
      if ($tMB -gt 0) {
        $ratio=$limMB/$tMB
        if ([math]::Abs($ratio-1.0) -lt 0.05) { $commitLimitApproxRAM=$true }
      }
    }
  }

  $pfFindings=@()
  if ($n -gt 0 -and $h[-1].PFInstances){
    foreach($pf in $h[-1].PFInstances){
      $pct=0.0; if ($pf.AllocatedMB -gt 0){ $pct=(100.0*$pf.CurrentMB)/$pf.AllocatedMB }
      $driveL=$null; $freePct=[double]::NaN; $freeGB=[double]::NaN
      if ($pf.Drive){ $driveL=$pf.Drive.DeviceID; $size=[double]$pf.Drive.Size; $free=[double]$pf.Drive.FreeSpace; if($size -gt 0){ $freePct=(100.0*$free)/$size; $freeGB=$free/1GB } }
      if ($pct -ge $PF_USAGE_HIGH_PCT -and ($freePct -le $PF_FREE_PCT_WARN -or $freeGB -le $PF_FREE_GB_WARN)) {
        $pfFindings += [pscustomobject]@{ Path=$pf.Path; Pct=$pct; Volume=$driveL; FreePct=$freePct; FreeGB=$freeGB }
      } elseif ($freePct -le $PF_FREE_PCT_WARN) {
        $pfFindings += [pscustomobject]@{ Path=$pf.Path; Pct=$pct; Volume=$driveL; FreePct=$freePct; FreeGB=$freeGB }
      }
    }
  }

  $requiredSustain=[int][math]::Ceiling($SUSTAINED_SECONDS / $SAMPLE_EVERY_SEC)
  $result = Invoke-DetermineMemoryStress `
    -MinSustainedSamplesForExtreme $requiredSustain `
    -SampleCount $n `
    -AvgPageR $avgPageR `
    -MaxPageR $maxPageR `
    -AvgPageW $avgPageW `
    -MaxPageW $maxPageW `
    -AvgAvailPct $avgAvailPct `
    -MinAvailPct $minAvailPct `
    -MinAvailMB $minAvailMB `
    -AvgTransF $avgTransF `
    -MaxTransF $maxTransF `
    -AvgCommitPct $avgCommitPct `
    -MaxCommitPct $maxCommitPct `
    -MaxPFPct $maxPFPct `
    -P95ReadMs $p95ReadMs `
    -P95WriteMs $p95WriteMs `
    -HasReadIO $hasReadIO `
    -HasWriteIO $hasWriteIO `
    -PFKnown $pfKnown

  $level=$result.Level; $reasons=$result.Reasons

  $lines=@()
  if($reasons){ $lines+="`tReasons: $reasons" }
  $lines+="`tMeasurements:"
  $lines+=("`tAvail. RAM: avg {0}% (~{1} MB), min {2}% (~{3} MB)" -f (Fmt $avgAvailPct),(Fmt $( if ([double]::IsNaN($totalMB) -or [double]::IsNaN($avgAvailPct)) {$null} else {($avgAvailPct/100.0)*$totalMB} ) 'N0'),(Fmt $minAvailPct),(Fmt $minAvailMB 'N0'))
  $lines+=("`tCommitted Memory (% of RAM+Max.Swap): avg {0}%, max {1}%" -f (Fmt $avgCommitPct),(Fmt $maxCommitPct))
  $lines+=("`tPaging file usage: {0}" -f $( if ($pfKnown){ "max " + (Fmt $maxPFPct 'N0') + "%" } else { "n/a (no pagefile or metric unavailable)" } ))
  $lines+=("`tPage Reads/s : avg {0}, max {1}" -f (Fmt $avgPageR 'N0'),(Fmt $maxPageR 'N0'))
  $lines+=("`tPage Writes/s: avg {0}, max {1}" -f (Fmt $avgPageW 'N0'),(Fmt $maxPageW 'N0'))
  $lines+=("`tTransition Faults/sec: avg {0}, max {1}" -f (Fmt $avgTransF 'N0'),(Fmt $maxTransF 'N0'))
  $lines+= "`tDisk latency p95: reads $p95ReadMs, writes $p95WriteMs (ms)"
  $lines+= "`tDisk queue: avg length $avgQLen, avg IOps $avgIOps"
  if ($n -gt 0) {
    $last=$h[-1]
    if ($last.DiskStressPerDisk -and $last.DiskStressPerDisk.Count -gt 0){
      $pairs = $last.DiskStressPerDisk.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
      $lines+=("`tPer-disk stress: {0}" -f ($pairs -join ', '))
    }
  }

  $explain = ($lines -join [Environment]::NewLine)
  if ($level -in 'high','extreme','unknown') { [pscustomobject]@{ Estimation=$level; Explanation=$explain } }
  else { [pscustomobject]@{ Estimation=$level; Explanation='' } }
}

function Get-FirstCharsOfStr($inp, $length=120){
    if ($null -eq $inp) {return ''}
    if ($inp.Length -gt $length) {
      return $inp.Substring(0, [math]::Min($length -3, $inp.Length)) + "..."
    } else {
      return $inp
    }
}

function Get-TopIOProcess {
    [CmdletBinding(DefaultParameterSetName='TopN')]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$Top = 20
    )

    Write-Verbose "Querying WMI performance classes and process list via Get-Process..."

    $PerfData = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop

    $ProcessMap = @{}
    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            $ProcessMap[$_.Id] = $_
        }
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
        return
    }

    $CmdLineMap = @{}
    try {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            ForEach-Object {
                if ($null -ne $_.ProcessId) {
                    $CmdLineMap[[int]$_.ProcessId] = $_.CommandLine
                }
            }
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
    }

    Write-Verbose "Found $($PerfData.Count) performance instances, $($ProcessMap.Count) processes, $($CmdLineMap.Count) command lines. Mapping..."

    $IOStats = foreach ($Instance in $PerfData) {

        $TotalBytes   = $Instance.IOReadBytesPersec + $Instance.IOWriteBytesPersec
        $ProcID       = [int]$Instance.IDProcess
        $InstanceName = $Instance.Name
        $IsMapped     = $ProcessMap.ContainsKey($ProcID)

        if (
            $TotalBytes -gt 0 -and
            $InstanceName -ne '_Total' -and
            $IsMapped
        ) {
            $ProcessInfo = $ProcessMap[$ProcID]
            $CommandLine = $null
            if ($CmdLineMap.ContainsKey($ProcID)) { $CommandLine = $CmdLineMap[$ProcID] }

            [PSCustomObject]@{
                FilePath    = $ProcessInfo.Path
                CommandLine = $CommandLine
                ProcessName = $ProcessInfo.ProcessName
                PID         = $ProcID
                ReadBPS     = [long]$Instance.IOReadBytesPersec
                WriteBPS    = [long]$Instance.IOWriteBytesPersec
                TotalBPS    = [long]$TotalBytes
            }
        }
    }

    Write-Verbose "Found $($IOStats.Count) processes with I/O activity."

    $IOStats |
        Sort-Object -Property TotalBPS -Descending |
        Select-Object -First $Top |
        Select-Object CommandLine, ProcessName, PID, ReadBPS, WriteBPS, TotalBPS
}

# condensed print version of Get-TopIOProcess
function Write-TopIOProcess {
    try{
        $cumulative = 0 # will help suppress lines with less than 5% influence on the total
        Get-TopIOProcess | %{
            if ($_.TotalBPS -gt ($cumulative * 5 /100)) {
                Write-ThrottledLog  "`t$([int]($_.TotalBPS/1MB)) MBps, $($_.ProcessName), $(Get-FirstCharsOfStr         $_.CommandLine)"
                $cumulative = $cumulative  + $_.TotalBPS
            } else {
                return
            }
            
        }
    } catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
    }
}

function Get-TopCPUProcess {
    [CmdletBinding(DefaultParameterSetName='TopN')]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$Top = 20
    )

    Write-Verbose "Querying per-process CPU usage via Win32_PerfFormattedData_PerfProc_Process..."

    $PerfData = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfProc_Process -ErrorAction Stop

    $ProcessMap = @{}
    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            $ProcessMap[$_.Id] = $_
        }
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
        return
    }

    $CmdLineMap = @{}
    try {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            ForEach-Object {
                if ($null -ne $_.ProcessId) {
                    $CmdLineMap[[int]$_.ProcessId] = $_.CommandLine
                }
            }
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
    }

    Write-Verbose "Found $($PerfData.Count) performance instances, $($ProcessMap.Count) processes, $($CmdLineMap.Count) command lines. Mapping..."

    $CPUStats = foreach ($Instance in $PerfData) {

        $ProcID       = [int]$Instance.IDProcess
        $InstanceName = $Instance.Name

        if ($InstanceName -eq '_Total') { continue }
        if (-not $ProcessMap.ContainsKey($ProcID)) { continue }

        $cpu = [double]$Instance.PercentProcessorTime
        if ($cpu -le 0) { continue }$ProcessInfo = $ProcessMap[$ProcID]
        $CommandLine = $null
        if ($CmdLineMap.ContainsKey($ProcID)) { $CommandLine = $CmdLineMap[$ProcID] }

        [PSCustomObject]@{
            FilePath    = $ProcessInfo.Path
            CommandLine = $CommandLine
            ProcessName = $ProcessInfo.ProcessName
            PID         = $ProcID
            CpuPct      = [math]::Round($cpu, 1)
        }
    }

    Write-Verbose "Found $($CPUStats.Count) processes with CPU activity."

    $CPUStats |
        Sort-Object -Property CpuPct -Descending |
        Select-Object -First $Top |
        Select-Object FilePath, CommandLine, ProcessName, PID, CpuPct
}

# condensed print version of Get-TopCPUProcess
# TODO: Move the smart detection of when to stop printing
# details for more processes to Get-TopCPUProcess. 
# As it is now Get-TopCPUProcess get's bothered to return 
# information for 20 processes and then this function may 
# only print the first 5. It's a waste of CPU at a moment
# where it is already stressed.
# Maybe do it only if $Top is left to its default $null value.
function Write-TopCPUProcess {
    try{
        $cumulative = 0 # will help suppress lines with less than 5% influence on the total
        # PID 0 is the idle process
        Get-TopCPUProcess | ?{$_.PID -ne 0} | %{
            if ($_.CpuPct -gt ($cumulative * 5 /100)) {
                $cumulative = $cumulative  + $_.CpuPct
                Write-ThrottledLog "`t$($_.CpuPct)%, $($_.ProcessName), $(Get-FirstCharsOfStr $_.CommandLine)"
            } else {
                return
            }
        }
    } catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
    }
}

function Get-TopMemProcess {
    [CmdletBinding(DefaultParameterSetName='TopN')]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$Top = 20
    )

    Write-Verbose "Querying processes for memory usage via Get-Process..."

    $ProcessMap = @{}
    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            $ProcessMap[$_.Id] = $_
        }
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
        return
    }

    $CmdLineMap = @{}
    try {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            ForEach-Object {
                if ($null -ne $_.ProcessId) {
                    $CmdLineMap[[int]$_.ProcessId] = $_.CommandLine
                }
            }
    }
    catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
    }

    Write-Verbose "Found $($ProcessMap.Count) processes, $($CmdLineMap.Count) command lines. Mapping..."

    $MemStats = foreach ($procId in $ProcessMap.Keys) {
        $p  = $ProcessMap[$procId]
        $ws = [long]$p.WorkingSet64
        if ($ws -le 0) { continue }

        $priv = $null
        if ($p.PrivateMemorySize64 -gt 0) { $priv = [long]$p.PrivateMemorySize64 }

        $cmd = $null
        if ($CmdLineMap.ContainsKey($procId)) { $cmd = $CmdLineMap[$procId] }

        [PSCustomObject]@{
            FilePath       = $p.Path
            CommandLine    = $cmd
            ProcessName    = $p.ProcessName
            PID            = [int]$procId
            WorkingSetMB   = [math]::Round($ws / 1MB, 1)
            PrivateBytesMB = if ($priv) { [math]::Round($priv / 1MB, 1) } else { $null }
        }
    }

    Write-Verbose "Found $($MemStats.Count) processes with non-zero working set."

    $MemStats |
        Sort-Object -Property WorkingSetMB -Descending |
        Select-Object -First $Top |
        Select-Object FilePath, CommandLine, ProcessName, PID, WorkingSetMB, PrivateBytesMB
}

# condensed print version of Get-TopMemProcess
function Write-TopMemProcess {
    try{
        $cumulative = 0 # will help suppress lines with less than 5% influence on the total
        Get-TopMemProcess | %{
            if ($_.WorkingSetMB -gt ($cumulative * 5 /100)) {
                $cumulative = $cumulative  + $_.WorkingSetMB
                Write-ThrottledLog "`t$($_.WorkingSetMB) MB, $($_.ProcessName), $(Get-FirstCharsOfStr $_.CommandLine)"
            } else {
                return
            }
        }
    } catch {
        Write-ErrorDetails -ErrorRecord $_ -Context $MyInvocation.MyCommand.Name
    }
}

if ($LogFile) {
    ###################################################################
    #
    #  L O G   F I L E   A N A L Y S I S   M O D E
    #
    ###################################################################
    # View evens per hour, per day, etc
    # $GranularityRegex=""           = per 1 minute
    # $GranularityRegex="\d"         = per 10 minutes
    # $GranularityRegex=":\d\d"      = per hour
    # $GranularityRegex="T\d\d:\d\d" = per day
    #
    # We ignore periods if all event categories have less than MinEventsPerPeriod each
    # $MinEventsPerPeriod=4 # 4/10min seems good or 24/hour or 1/min
    
    if ($Granularity -eq "1d") {
        $MinEventsPerPeriod=0
        $GranularityRegex="T\d\d:\d\d"
    } elseif ($Granularity -eq "1h") {
        $MinEventsPerPeriod=18
        $GranularityRegex=":\d\d"
    } elseif ($Granularity -eq "10m") {
        $MinEventsPerPeriod=3
        $GranularityRegex="\d"
    } elseif ($Granularity -eq "1m") {
        $MinEventsPerPeriod=1
        $GranularityRegex=""
    } else {
        throw "Invalid -Granularity (select one of these: 1d, 2h, 10m, 1m)"
    }

    $total_lines = (cat $LogFile | measure).count



    $host_name = $env:COMPUTERNAME
    $relevant_lines = (cat $LogFile|sls -NotMatch " $host_name([\s,]?\t|\t| +- | +Measurements:| +Reasons:)|Test-ForCpuRamDiskStress started|\bmonitoring\b|$LogsToIgnoreRegex").line
    $events_per_type_total = ($relevant_lines `
        -replace '^[^ ]* [^ ]* ' `
        -replace '(: |=)9[0-4]%',': 9L%' `
        -replace '(: |=)9[5-9]%',': 9H%' `
        -replace '\..*$' `
        -replace '2\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[, ]*' `
        | sort | group|select -Property count,name)
    if (-not $relevant_lines){
        write-host -for darkgreen "Zero stress events ($total_lines lines in total in $LogFile)"
        return
    }

    $mem =((sls "^\d\d\d\d-\d\d-\d\dT.*HIGH Memory"         $LogFile).line -replace "$($GranularityRegex):\d\d,? $host_name[, ].*" | group|select count,name)
    $cpu =((sls "^\d\d\d\d-\d\d-\d\dT.*High total CPU"      $LogFile).line -replace "$($GranularityRegex):\d\d,? $host_name[, ].*" | group|select count,name)
    $disk=((sls "^\d\d\d\d-\d\d-\d\dT.*High stress on disk" $LogFile).line -replace "$($GranularityRegex):\d\d,? $host_name[, ].*" | group|select count,name)

    # $mem, $cpu, $disk has .Name with and .Count like this:
    # Name is the 10minute period where the events occured
    # Count is the number of events that occured
    #
    #    Count Name
    #    ----- ----
    #        6 2025-11-11T23:0
    #        1 2025-11-11T23:1
    #        1 2025-11-11T23:2

    # Join all events in one table
    #------------------------------
    $memMap  = @{}; foreach($r in $mem){  if($null -ne $r -and $r.Name){ $memMap[$r.Name]  = [int]$r.Count } }
    $cpuMap  = @{}; foreach($r in $cpu){  if($null -ne $r -and $r.Name){ $cpuMap[$r.Name]  = [int]$r.Count } }
    $diskMap = @{}; foreach($r in $disk){ if($null -ne $r -and $r.Name){ $diskMap[$r.Name] = [int]$r.Count } }

    $joinedTimes = @($memMap.Keys + $cpuMap.Keys + $diskMap.Keys) | Sort-Object -Unique

    $joined = foreach($t in $joinedTimes){
      $mc = if($memMap.ContainsKey($t))  {$memMap[$t]}  else {0}
      $dc = if($diskMap.ContainsKey($t)) {$diskMap[$t]} else {0}
      $cc = if($cpuMap.ContainsKey($t))  {$cpuMap[$t]}  else {0}
      [pscustomobject]@{ time=$t; mem=$mc; disk=$dc; cpu=$cc }
    }

    # Time periods where we have at least $MinEventsPerPeriod stress events (either CPU, Mem or Disk)
    $interesting_periods = ($joined | Sort-Object time | ?{ $_.mem -ge $MinEventsPerPeriod -or $_.cpu -ge $MinEventsPerPeriod -or $_.disk -ge $MinEventsPerPeriod})

    write-host -for darkgray "$total_lines lines in total in $LogFile"
    if ($LogsToIgnoreRegex) {$comment = " (excluding '$LogsToIgnoreRegex')"} else {$comment=""}
    write-host -for darkcyan "Total events per type$comment"
    $events_per_type_total|%{"$($_.count)`t$($_.name)"}
    if ($interesting_periods) {
      write-host -for darkcyan "`n$Granularity periods with >=$MinEventsPerPeriod events of high MEM,CPU or DISK stress"
      $interesting_periods|ft
    } else {
      write-host -for darkgray "`nNo $Granularity periods with >=$MinEventsPerPeriod events of high MEM,CPU or DISK stress"
    }
} elseif ($LogDir -and (test-path $LogDir)) {
    ###################################################################
    #
    #  N O R M A L   M O D E   (Report high stress events)
    #
    ###################################################################
    Write-ThrottledLog "Test-ForCpuRamDiskStress started. Sampling period is $SAMPLE_EVERY_SEC sec." -LogBaseName $LogBaseName -LogDir $LogDir
    Write-ThrottledLog "When RAM, CPU or disks are stressed I will show you details."

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
      Write-Warning "Not running elevated; some CIM providers may be unavailable."
    }

    $lastSampleHour=-1 # detect hour change
    while ($true) {
      try {
        $loopStart = Get-Date
        $timestamp = ($loopStart).ToString('s')
        $sampleHour = $loopStart.Hour
        if ($sampleHour -ne $lastSampleHour) {
            # log this once every hour
            $file = Join-Path $script:WTW_LogDir ("{0}.{1}.log" -f $script:WTW_LogBaseName, $loopStart.ToString('yyyy-MM-dd'))
            write-ThrottledLog -AlwaysLog "Info: Monitoring. Sampling period is $SAMPLE_EVERY_SEC sec. Logging to $file"
            $lastSampleHour = $sampleHour
        }
      
        $metrics = Get-PerfSnapshot
        $memResults = Get-MemoryStressEstimate $metrics
        # This part of the code of Get-MemoryStressEstimate
        # must be moved here (inside the main loop)
        #     Take a single snapshot Get-PerfSnapshot
        #     adds it to a rolling window (last 9 samples),
        # The full rolling window must be passed to Get-MemoryStressEstimate
        # I want this because it's best to pass the same rolling window to Test-DiskStress
        # The below code that generates the high disk stress warning will become Test-DiskStress.
        # Test-DiskStress may use the full window to determine stress
        # It should also add details like Get-MemoryStressEstimate does
        # Same for Test-CpuStress which may opt to only report high CPU when
        # it's sustained for a few samples
      
        # TODO move this warning inside Get-MemoryStressEstimate which should
        # return nothing and be renamed to Test-MemoryStress
        if ($memResults.Explanation) {
          if ($memResults.Estimation -eq 'unknown') {
            Write-ThrottledLog -HighPriority "UNKNOWN Memory stress"
          } else{
            Write-ThrottledLog -AlwaysLog "STRESS: $($memResults.Estimation.ToUpperInvariant()) Memory stress"
            Write-ThrottledLog -HighPriority $memResults.Explanation
            Write-TopMemProcess
          }
        }
      
        $cpu=$null; $suppressPerCore = $false
      
        if (-not $metrics) {
          Write-ThrottledLog "Metrics object is $null."
        } elseif (-not $metrics.Data) {
          Write-ThrottledLog "Metrics.Data is $null."
        } else {
            
          #----------------------------
          # REGARDING CPU
          #----------------------------
          $TOTAL_CPU_UTILIZATION_LIMIT=90
          $PER_CORE_UTILIZATION_LIMIT=98
          
          $cpu  = $metrics.Data.CPUUtil
          if (-not $cpu) {
            Write-ThrottledLog "CPUUtil is missing."
          } elseif (-not $cpu.ContainsKey('Total')) {
            # TODO: I get this a lot in a few servers AC,AC-test,Audit
            # (in fact I get missing for CPUUtil['Total'] & DiskStressPerDisk)
            Write-ThrottledLog "CPUUtil['Total'] is missing."
          } else {
            $totalCpu = [int]$cpu['Total']
            if ($totalCpu -gt $TOTAL_CPU_UTILIZATION_LIMIT) {
              Write-ThrottledLog -AlwaysLog "STRESS: High total CPU utilization: $totalCpu%."
              $suppressPerCore = $true
              Write-TopCPUProcess 
            }
          }
          
          if ($cpu -and -not $suppressPerCore) {
            if (-not $script:CoreHot) { $script:CoreHot=@{} }
            $sustainNeeded = [int][math]::Ceiling($SUSTAINED_SECONDS / $SAMPLE_EVERY_SEC)
            $totalCpu = 0
            if ($cpu.ContainsKey('Total')) { $totalCpu = [int]$cpu['Total'] }
      
            foreach ($k in ($cpu.Keys | Where-Object { $_ -like 'Core*' })) {
              $v = [int]$cpu[$k]
              if (-not $script:CoreHot.ContainsKey($k)) { $script:CoreHot[$k]=0 }
              if ($v -ge $PER_CORE_UTILIZATION_LIMIT) { $script:CoreHot[$k]++ } else { $script:CoreHot[$k]=0 }
      
              if ($script:CoreHot[$k] -ge $sustainNeeded -and $totalCpu -lt $TOTAL_CPU_UTILIZATION_LIMIT) {
                Write-ThrottledLog -HighPriority "High single-core usage. $k ~= $v% for ~$($sustainNeeded*$SAMPLE_EVERY_SEC)s while Total ~= $totalCpu%."
                Write-TopCPUProcess
              }
            }
          }
      
          #----------------------------
          # REGARDING DISKS
          #----------------------------
          if (!$DontMonitorDisks) {
            # per-disk stress warnings
            $diskPressMap = $metrics.Data.DiskStressPerDisk
            if ($null -eq $diskPressMap -or $diskPressMap.Count -eq 0) {
              # TODO: I get this a lot in a few servers AC,AC-test,Audit
              # (in fact I get missing for CPUUtil['Total'] & DiskStressPerDisk)          
              Write-ThrottledLog "DiskStressPerDisk is missing."
            } else {
              foreach($kv in $diskPressMap.GetEnumerator()){
                if ($kv.Value -like 'high *' -and $kv.Key -ne '_Total') {
                  $name = $kv.Key
                  # fetch the instantaneous metrics for that disk if available
                  $q = $metrics.Data.DiskQLen; $r = $metrics.Data.ReadMs; $w = $metrics.Data.WriteMs
                  Write-ThrottledLog -AlwaysLog "STRESS: High stress on disk $name. $($kv.Value -replace '^[^ ]* +')"
                  Write-TopIOProcess
                }
              }
            }
          }
      
          #----------------------------
          # REGARDING VOLUMES
          #----------------------------
          if ($MonitorVolumes) {
            # per-Volume stress warnings
            # MAYBE TODO: Suppress warnings if they refer to a disk that is also in warning state
            $diskPressMap = $metrics.Data.DiskStressPerVolume
            if ($null -eq $diskPressMap -or $diskPressMap.Count -eq 0) {
              Write-ThrottledLog "DiskStressPerVolume is missing."
            } else {
              foreach($kv in $diskPressMap.GetEnumerator()){
                if ($kv.Value -like 'high *' -and $kv.Key -ne '_Total') {
                  $name = $kv.Key
                  Write-ThrottledLog -AlwaysLog "STRESS: High stress on Volume $name. $($kv.Value -replace '^[^ ]* +')"
                  Write-TopIOProcess
                }
              }
            }
          }
        }
      
      } catch {Write-ErrorDetails -ErrorRecord $_ -Context "main_loop"}
      
      try {
        $elapsedSec = ((Get-Date) - $loopStart).TotalSeconds
        $remainMSec  = [int][math]::Floor(($SAMPLE_EVERY_SEC - $elapsedSec)*1000)
        if ($remainMSec -gt 0) { Start-Sleep -MilliSeconds $remainMSec } else {
          if ($elapsedSec -gt $SAMPLE_EVERY_SEC*1.1) {
            Write-ThrottledLog -AlwaysLog ("WARNING: Last check took {0} seconds" -f (Fmt $elapsedSec 'N3'))
          }
        }
      } catch {Write-ErrorDetails -ErrorRecord $_ -Context "sleep_after_main_loop"; sleep $SAMPLE_EVERY_SEC}
    }
} else {
    throw "Specify either -LogDir and -LogBaseName where to log events, or -LogFile to analyze"
}