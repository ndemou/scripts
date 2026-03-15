<# 
.SYNOPSIS
    Safe* and automatic DISM + SFC repairs made easy.

.DESCRIPTION
    Runs CHKDSK, DISM(CheckHealth/RestoreHealth) and SFC with preflight checks, concise console output, and logging. 
    Designed to minimize risk* and be thourough.
    
    *: REGARDING SAFETY
    
    This script is safe to run on Windows installations with no weird customizations, 
    Don't use it on boxes with OEM-customized, but still WRP-protected components, 
    or older apps that replace protected system binaries.

.PARAMETER Source
    Optional, one or more DISM sources, e.g. 'WIM:D:\sources\install.wim:1','ESD:E:\sources\install.esd:6'.

.PARAMETER ScratchDirectory
    Optional scratch directory for servicing if supported (offloads staging from C:).

.PARAMETER MinFreeSystemGB
    Minimum free GB on system drive before running heavy servicing (default 4GB).

.PARAMETER MinFreeScratchGB
    Minimum free GB on ScratchDirectory if provided. (default 4GB)

.PARAMETER LimitAccess
    Use only -Source and avoid Windows Update (WU/WSUS). Use this along with -Source. PREFER TO AVOID THIS OPTION. 

.EXAMPLE
    .\Run-DismSfc.ps1 -Source 'WIM:D:\sources\install.wim:1'
#>

<#
TODO
====
* Find the drive letter of the O.S. instead of guessing it's C:.
* Maybe: Before chckdsk check if filesystem is indeed NTFS and adjust parameters if it's not.
#>
[CmdletBinding()]
param(
    [string[]]$Source,
    [switch]$LimitAccess,
    [string]$ScratchDirectory,
    [int]$MinFreeSystemGB = 4,
    [int]$MinFreeScratchGB = 4,
    [switch]$SkipChkDsk
)

# ----------------------------- CONFIG / PREP -----------------------------
$LogDir = 'C:\IT\Log'
$null = New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction SilentlyContinue
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Base  = Join-Path $LogDir "DismSfc_$stamp"
$LogFile        = "$Base.log"              
$TranscriptFile = "$Base.transcript.txt"   

Set-StrictMode -Version 2
try { Start-Transcript -Path $TranscriptFile -Append -ErrorAction Stop | Out-Null } catch {}

$systemDrive = [Environment]::GetEnvironmentVariable("SystemDrive")
if (-not $systemDrive) { $systemDrive = "C:" }

trap {
    # Show and log messages when an error is thrown
    # Quiet when Abort-Script is used, Rich diagnostics for unexpected errors
    $e = $_

    if ($e.Exception -is [System.OperationCanceledException]) {
        # Quiet path for intentional aborts
        $msg = $e.Exception.Message
        try { Write-Host ("Fatal: {0}" -f $msg) -ForegroundColor Red } catch {}
        try { Write-Log 'Fatal' $msg } catch {}
        try { Stop-Transcript | Out-Null } catch {}
        exit 1
    }

    # Rich diagnostics for unexpected errors
    try {
        Write-Host ""
        Write-Host ("FATAL: {0}" -f $e.Exception.Message) -ForegroundColor Red
        if ($e.InvocationInfo) {
            Write-Host ("At: {0}:{1}" -f $e.InvocationInfo.ScriptName,$e.InvocationInfo.ScriptLineNumber) -ForegroundColor Yellow
            Write-Host ($e.InvocationInfo.PositionMessage) -ForegroundColor DarkYellow
        }
        if ($e.ScriptStackTrace) {
            Write-Host "Stack:" -ForegroundColor DarkGray
            Write-Host $e.ScriptStackTrace -ForegroundColor DarkGray
        }
        Write-Log 'Fatal' ($e | Out-String)
    } catch {}
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}

# ----------------------------- UTILITIES -----------------------------

function Abort-Script([string]$Message,[string]$Detail=''){
    try { 
        if($Detail){
                Write-Host ""
                Write-Host "We need to abort execution. Details regarding why follow" -ForegroundColor 'DarkGray'
                Say Bad "" $Detail -OnlyShowDetail # Message will be shown be throw
        } 
    } catch {}
    throw [System.OperationCanceledException]::new( $Message )
}

<#
.SYNOPSIS
    Append one structured line to the script log.

.DESCRIPTION
    Writes a single timestamped log line to $LogFile. If Add-Content fails with IOException (e.g., antivirus scanning
    or sharing conflict), it falls back to raw .NET file I/O with FileShare.ReadWrite to reduce lock contention.

.PARAMETER Level
    Short level string, e.g. Debug | Info | Good | Warn | Bad.
#>
function Write-Log([string]$Level, [string]$Message){
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[{0}] [{1}] {2}" -f $ts,$Level,$Message
    try {
        Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch [System.IO.IOException] {
        $fs = [System.IO.File]::Open($LogFile,[System.IO.FileMode]::Append,[System.IO.FileAccess]::Write,[System.IO.FileShare]::ReadWrite)
        try { $sw = New-Object System.IO.StreamWriter($fs); $sw.WriteLine($line); $sw.Flush(); $sw.Dispose() } finally { $fs.Dispose() }
    }
}

<#
.SYNOPSIS
    Print a concise colored message and optionally a technical detail; log both.

.PARAMETER Level
    Debug | Info | Good | Warn | Bad (controls console color).

.PARAMETER Concise
    Short, user-friendly message.

.PARAMETER Detail
    Optional technical detail line.
#>
function Say(
        [ValidateSet('Debug','Info','Good','Warn','Bad')][string]$Level,
        [string]$Concise,
        [string]$Detail='',
        [switch]$OnlyShowDetail) {
    $color = switch($Level){ Debug{'DarkGray'} Info{'darkcyan'} Good{'Green'} Warn{'Yellow'} Bad{'Red'} }
    if (!$OnlyShowDetail) {Write-Host $Concise -ForegroundColor $color}
    if ($Detail) { Write-Host "  $Detail" -ForegroundColor 'DarkGray' }
    Write-Log $Level $Concise
    if ($Detail) { Write-Log 'Detail' $Detail }
}

<#
.SYNOPSIS
    Abort the script if any given path exists.
#>
function Abort-IfPathExists {
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)][string[]]$Path)
    process {
        foreach($p in $Path){
            if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
                Abort-Script ("Aborting: a reboot or some other operation is pending; Found '{0}'" -f $p)
            }
        }
    }
}


<#
.SYNOPSIS
    Print lines from CBS.log that may help you diagnose issues. Looks only at lines refering to the last session.

.DESCRIPTION
    Is needed only to help the user debug issues.
    This is read-only; no changes are made to the system.
#>
function Get-InterestingCBSLogLines {
    $path = "$env:windir\Logs\CBS\CBS.log"

    $line_nr = (Select-String -Path $path -Pattern '\sCBS\s+Session:\s' | Select-Object -Last 1).LineNumber
    if (-not $line_nr) { throw "Failed to locate the start of the last session in CBS.log" }

    $interesting = Get-Content $path | Select-Object -Skip ($line_nr-1) |
        Select-String 'Error|Error 0x[0-9A-Fa-f]+|\b0x(800|c0)[0-9a-f]{5}\b|Failed|Reboot|Cannot repair|\[SR\]|PendingXmlIdentifier|Mark store corruption|Hash mismatch|Payload not found|State:\s*(Staged|Install Pending|Uninstall Pending)|pending\.xml'

    if ($interesting) {
        $lines = ($interesting.Line | Select-Object -Unique) `
            -replace 'PID=\d+\s+TID=\d+\s+', '' `
            -replace '\s+', ' '

        Write-Host -ForegroundColor Cyan "The last CBS.log session starts at line $line_nr. You can view its log lines with:"
        Write-Host -ForegroundColor Cyan "Get-Content '$path' | Select-Object -Skip ($line_nr-1)"
        Write-Host -ForegroundColor Cyan "---START Lines that look like they may refer to issues---"
        Write-Host ""
        $lines | ForEach-Object { Write-Host -ForegroundColor White $_ }
        Write-Host -ForegroundColor Cyan "---END  Lines that look like they may refer to issues---"
        return $lines
    }

    return @()
}

<#
.SYNOPSIS
    Print lines from DISM.log that may help you diagnose issues. Looks only at lines refering to the last session.

.DESCRIPTION
    Is needed only to help the user debug issues.
    This is read-only; no changes are made to the system.
    TODO: the pattern used is from CBS.LOG -- needs tweeking
#>
function Get-InterestingDISMLogLines {
    $path = "$env:windir\Logs\DISM\DISM.log"

    $include = @(
        '^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\s+(?:Error|Warning)\s+DISM\b',
        '\b(?:hr|hresult|error:)\s*0x[0-9a-f]{8}\b',
        '\bfailed(?:\s+to)?\s+(?:mount|add|remove|process|open|apply|commit|finali[sz]e|start|stop|load|enable|disable|install|uninstall)\b',
        '\bfail(?:ed|ure)\b',
        '\bencountered\s+(?:an\s+)?error\b',
        '\bcannot\s+(?:repair|find|open|load)\b',
        '\bsource files?\s+could not be found\b',
        '\bcorrupt(?:ion)?\b|\bmismatch\b|\bnot found\b|\bunable\b',
        '\bDISM\s+(?:Package Manager|OSProvider|CBS):.*(?:Error|Failed|0x[0-9a-f]{8})',
        '\bDISM\.EXE:.*(?:failed|error|0x[0-9a-f]{8})'
    )

    $exclude = '(?i)Lookup in table by path failed|CTransactionalImageTable::LookupImagePath'

    $line_nr = (Select-String -Path $path -Pattern 'Host machine information' | Select-Object -Last 1).LineNumber
    if (-not $line_nr) { throw "Failed to locate the start of the last session in DISM.log" }

    $interesting = Get-Content $path | Select-Object -Skip ($line_nr-1) |
        Select-String -Pattern $include |
        Select-String -NotMatch $exclude

    if ($interesting) {
        $lines = ($interesting.Line | Select-Object -Unique) `
            -replace 'PID=\d+\s+TID=\d+\s+', '' `
            -replace '\bInfo\s+DISM\s+', '' `
            -replace '\s+', ' '

        Write-Host -ForegroundColor Cyan "The last DISM.log session starts at line $line_nr. View with:"
        Write-Host -ForegroundColor Cyan "Get-Content '$path' | Select-Object -Skip ($line_nr-1)"
        Write-Host -ForegroundColor Cyan "---START Lines that look like they may refer to issues---`n"
        $lines | ForEach-Object { Write-Host -ForegroundColor White $_ }
        Write-Host -ForegroundColor Cyan "`n---END  Lines that look like they may refer to issues---"
        return $lines
    }

    return @()
}



<#
.SYNOPSIS
    Return free space in GB for a drive or path.

.OUTPUTS
    System.Double
    Returns a double representing GB free, or $null if not determinable.
#>
function Get-FreeGB {
    param([Parameter(Mandatory)][string]$PathOrDrive)

    # Resolve to a drive root like 'C:\'
    $root = $null
    if ($PathOrDrive -match '^[A-Za-z]:\\?$' -or $PathOrDrive -match '^[A-Za-z]:$') {
        $root = ($PathOrDrive.Substring(0,2) + '\')
    } else {
        try {
            $resolved = Resolve-Path -LiteralPath $PathOrDrive -ErrorAction Stop
            $root = [System.IO.Path]::GetPathRoot($resolved.Path)
        } catch { return $null }
    }

    # Try PSDrive first
    try {
        $name = $root.TrimEnd('\').TrimEnd(':')
        $psd  = Get-PSDrive -Name $name -PSProvider FileSystem -ErrorAction Stop
        if ($null -ne $psd.Free) { return [math]::Round(([double]$psd.Free)/1GB,2) }
    } catch {}

    # Fallback to .NET DriveInfo
    try {
        $di = [System.IO.DriveInfo]::new($root)
        if ($di.IsReady) { return [math]::Round($di.AvailableFreeSpace/1GB,2) }
    } catch {}

    return $null
}


function Abort-IfFreeDiskLow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0)][string]$Path,
        [Parameter(Mandatory,Position=1)][double]$MinGB
    )
    $free = Get-FreeGB $Path
    if ($null -eq $free) {
        Abort-Script "Aborting: cannot determine free space." ("Path '{0}' is invalid or inaccessible." -f $Path)
    }
    if ($free -lt $MinGB) {
        Abort-Script "Aborting: insufficient free space." ("Path '{0}': {1} GB free < required {2} GB (You can adjust the required GB with -MinFreeSystemGB or -MinFreeScratchGB)." -f $Path,$free,$MinGB)
    }
    Say debug "OK: free space on $Path is $free > $MinGB GB."
}

<#
.SYNOPSIS
    Return $true if HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations is non-empty.

.OUTPUTS
    System.Boolean
#>
function Test-PendingFileRenameOperations {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $prop    = 'PendingFileRenameOperations'

    try {
        $val = Get-ItemPropertyValue -Path $regPath -Name $prop -ErrorAction Stop
    }
    catch {
        # If the key or property doesn't exist, there are no pending renames
        return $false
    }

    $pending = @($val) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return $pending.Count -gt 0
}



<#
.SYNOPSIS
    Capture host identity (build, product, arch, languages).

.OUTPUTS
    Reads CurrentVersion (build + UBR), WindowsProductName, PROCESSOR_ARCHITECTURE, and parses 'dism /online /get-intl'
    to return PSCustomObject {Build, Product, Arch, Languages}
#>
function Get-HostIdentity {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = "{0}.{1}" -f $cv.CurrentBuild,$cv.UBR
    $prod  = (Get-ComputerInfo).WindowsProductName
    $arch  = $env:PROCESSOR_ARCHITECTURE
    $intl  = (dism /online /get-intl) 2>&1 | Out-String
    $langs = ($intl -split "`n" | Where-Object {$_ -match '^(Installed language|Default system UI language)'})
    [pscustomobject]@{ Build=$build; Product=$prod; Arch=$arch; Languages=($langs -join '; ') }
}

<#
.SYNOPSIS
    Parse a DISM source spec string.

.DESCRIPTION
    Accepts 'WIM:<path>:<index>' or 'ESD:<path>:<index>' and returns a structured object, or $null if invalid.

.OUTPUTS
    PSCustomObject: { Kind, Path, Index }, or $null if the spec is invalid.

.NOTES
    Only used by Test-DismSource.
#>
function Parse-SourceSpec([string]$Spec){
    $m = [regex]::Match($Spec,'^(WIM|ESD):(.+):(\d+)$',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if(-not $m.Success){ return $null }
    [pscustomobject]@{ Kind=$m.Groups[1].Value.ToUpper(); Path=$m.Groups[2].Value; Index=[int]$m.Groups[3].Value }
}

<#
.SYNOPSIS
    Validate a WIM/ESD source index and extract basic metadata.

.DESCRIPTION
    Runs 'dism /Get-WimInfo /Index:<n>' and parses Name, Architecture, Version. Returns Valid=$false with Reason on failure.
    Read-only; does not mount or modify the image.

.PARAMETER Spec
    'WIM:<path>:<index>' or 'ESD:<path>:<index>'.

.OUTPUTS
    PSCustomObject {Spec, Valid, Name, Arch, Version, Kind, Path, Index, Reason} 
#>
function Test-DismSource {
    param([string]$Spec)
    $p = Parse-SourceSpec $Spec
    if(-not $p){ return [pscustomobject]@{ Spec=$Spec; Valid=$false; Reason='Invalid format (use WIM:<path>:<index> or ESD:<path>:<index>)' } }
    if(-not (Test-Path -LiteralPath $p.Path)){ return [pscustomobject]@{ Spec=$Spec; Valid=$false; Reason='File not found' } }
    $cmd = "dism /Get-WimInfo /WimFile:`"$($p.Path)`" /Index:$($p.Index)"
    $out = (& cmd /c $cmd) 2>&1 | Out-String
    if([string]::IsNullOrWhiteSpace($out)){ return [pscustomobject]@{ Spec=$Spec; Valid=$false; Reason='dism output empty' } }
    $name = ($out -split "`n" | Where-Object {$_ -match '^\s*Name\s*:\s*(.+)$'} | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
    $arch = ($out -split "`n" | Where-Object {$_ -match '^\s*Architecture\s*:\s*(.+)$'} | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
    $ver  = ($out -split "`n" | Where-Object {$_ -match '^\s*Version\s*:\s*(.+)$'} | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
    [pscustomobject]@{ Spec=$Spec; Valid=$true; Name=$name; Arch=$arch; Version=$ver; Kind=$p.Kind; Path=$p.Path; Index=$p.Index }
}

<#
.SYNOPSIS
    Run SFC and classify its result.

.DESCRIPTION
    Executes 'sfc /verifyonly' or 'sfc /scannow', captures raw output, and maps it to a compact Result value:
    NoViolations | Repaired | NotRepaired | PendingReboot | WrpFailure | Unknown.

.PARAMETER Arg
    '/verifyonly' or '/scannow'.

.OUTPUTS
    PSCustomObject with: Arg, Result (NoViolations|Repaired|NotRepaired|PendingReboot|WrpFailure|Unknown), Raw, ExitCode

.NOTES
    Risk: In the unlikely case that you have OEM/customized components, '/scannow' can replace WRP-protected files and revert these OEM/customized components.
#>
function Invoke-Sfc([string]$Arg){
    $tmp1 = [IO.Path]::GetTempFileName()
    $tmp2 = [IO.Path]::GetTempFileName()
    $proc = Start-Process -FilePath sfc.exe -ArgumentList $Arg -NoNewWindow -Wait `
        -RedirectStandardOutput $tmp1 -RedirectStandardError $tmp2 -PassThru
    $exitCode = $proc.ExitCode

    $out = Get-Content -LiteralPath $tmp1 -Raw -Encoding Unicode -ErrorAction SilentlyContinue
    $err = Get-Content -LiteralPath $tmp2 -Raw -Encoding Unicode -ErrorAction SilentlyContinue
    Remove-Item $tmp1 -Force
    Remove-Item $tmp2 -Force
    
    if ($null -eq $out) { $out = '' } else { $out = $out -replace "`0","" }
    if ($null -eq $err) { $err = '' } else { $err = $err -replace "`0","" }

    $ignore_patterns = @(
        '(?i)\b\d{1,3}\s*%\s*complete\b',
        '(?i)this process will take some time',
        '^ *$'
    )
    $cleanLines = foreach($l in ($out -split '\r?\n')) {
        $t = $l.Trim(); if ($t -and -not ($ignore_patterns | Where-Object { $t -match $_ })) { $l }
    }
    $outClean = ($cleanLines -join [Environment]::NewLine)

    Write-Log 'Output' $outClean.Trim()

    $rawCombined = if ($err.Trim()) {
        if ($outClean.Trim()) { $outClean + [Environment]::NewLine + $err } else { $err }
    } else {
        $outClean
    }

    switch ($exitCode) {
        0 { $result = 'NoViolations' }
        1 { $result = 'Repaired' }
        2 {
            $outClean -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -Last 5 | Write-Host -ForegroundColor Yellow
            $result = 'NotRepaired'
        }
        3 { $result = 'PendingReboot' }
        4 {
            $outClean -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -Last 5 | Write-Host -ForegroundColor Yellow
            $result = 'WrpFailure'
        }
        default {
            $outClean -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -Last 5 | Write-Host -ForegroundColor Yellow
            $result = 'Unknown'
        }
    }

    return [pscustomobject]@{
        Arg      = $Arg
        Result   = $result
        Raw      = $rawCombined
        ExitCode = $exitCode
    }
}



# ----------------------------- Elevation check -----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say Bad "You must run this script as Administrator." "Open an ELEVATED terminal (A.K.A. 'admin terminal') and re-run."
    try { Stop-Transcript | Out-Null } catch {}
    return
}

Say Debug "Keeping a structured log in '$LogFile', and a transcript in '$TranscriptFile'"

# ----------------------------- CHKDSK -----------------------------
if (!$SkipChkDsk) {
    say info "$(Get-Date) Starting: 'chkdsk $systemDrive /scan'"
    & chkdsk "$systemDrive" /scan
    $chkCode = $LASTEXITCODE
    # (bitmask): 0 = clean, any other bit = some kind of issue
    if ($chkCode -eq 0) {
        say good  "Disk check finished. No errors were reported on $systemDrive."
    } else {
        say bad "Disk check reported problems on $systemDrive (CHKDSK exit code: $chkCode).`nA deeper disk check will be scheduled to run before Windows starts."
        "Y" | & chkdsk "$systemDrive" /f 
        Abort-Script "Please restart your computer, *WAIT* for chkdsk to complete, then run this script again."
    }
}

# ----------------- Preflight checks before heavy servicing of the system --------------------
Say Info "$(Get-Date) Starting: Preflight checks"

# Abort if Repair-WindowsImage cmdlet is not available
if (-not (Get-Command Repair-WindowsImage -ErrorAction SilentlyContinue)) {
    Abort-Script "Aborting: Repair-WindowsImage cmdlet not available on this host/session." "Use Windows PowerShell 5.1 or enable WinPS compat."
}


# Abort if ScratchDirectory invalid or not writable
if ($ScratchDirectory) {
    if (-not (Test-Path -LiteralPath $ScratchDirectory)) {
        Abort-Script "Aborting: ScratchDirectory does not exist." "Path: $ScratchDirectory"
    }
    try { $null = New-Item -ItemType File -Path (Join-Path $ScratchDirectory '.write.test') -Force; Remove-Item (Join-Path $ScratchDirectory '.write.test') -Force }
    catch {
        Abort-Script "Aborting: ScratchDirectory is not writable." "Path: $ScratchDirectory"
    }
}


# Free Space Checks
Abort-IfFreeDiskLow $systemDrive $MinFreeSystemGB
if ($ScratchDirectory) { 
        Abort-IfFreeDiskLow $ScratchDirectory $MinFreeScratchGB 
}

# Pending reboot Checks
Abort-IfPathExists 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
Abort-IfPathExists 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
Abort-IfPathExists "$systemDrive\Windows\WinSxS\pending.xml"
if (Test-PendingFileRenameOperations) {
    Say Debug "    Note: Windows report having some pending rename/move/delete"
    Say Debug "    operations to perform, but that is usualy not a reason to reboot."
    Say Debug "    (But if you get any errors you may retry after a reboot)"
}
Say debug "OK: reboot is not required."

# Check: Host Identity and compatibility with provided sources 
# (only if -Source was provided)
if ($source) {
        Say debug "Checking Host Identity because -Source was provided (the source must be compatible with the host)"

        $hostId = Get-HostIdentity
        Say Debug "Host: $($hostId.Product) | Build $($hostId.Build) | Arch $($hostId.Arch)" $hostId.Languages
        Write-Log 'HostIdentity' ($hostId | Out-String)

        if($Source -and $Source.Count -gt 0){
            Say 'Info' "Preflight: Validate Source WIM/ESD"
            $evaluatedSources = @()
            foreach($spec in $Source){
                $info = Test-DismSource -Spec $spec
                $evaluatedSources += $info
                if($info.Valid){
                    Say Debug "Source OK: $($info.Spec)" "Name=$($info.Name) | Arch=$($info.Arch) | Version=$($info.Version)"
                } else {
                    Say Warn "Note: source failed validation: $($info.Spec)" "Reason: $($info.Reason)"
                }
            }
            $mismatch = $evaluatedSources | Where-Object { $_.Valid -and $_.Arch -and ($_.Arch -notmatch $hostId.Arch) }
            if($mismatch){
                Say Warn "Note: source architecture differs from host." "Host=$($hostId.Arch); Sources=[$(($mismatch | Select-Object -ExpandProperty Spec) -join ', ')]"
            }
        }

        if ($LimitAccess) {
                # Abort if -LimitAccess specified  and source architecture differs from host
                if ($mismatch) {Abort-Script "Aborting: source architecture differs from host and -LimitAccess forbids fallback." "Host=$($hostId.Arch)"}
                
                # Abort if -LimitAccess specified but no valid /Source provided.
                $validSources = @()
                if ($evaluatedSources) { $validSources = $evaluatedSources | Where-Object Valid }
                if ($validSources.Count -eq 0) {
                    Abort-Script "Aborting: -LimitAccess specified but no valid /Source provided."
                }
        }
    Say debug "OK: all is good."
}


# Important reminder for DISM/Repair-WindowsImage: 
#     -Online means to target the running O.S. (nothing to do with Internet access)
#     -LimitAccess means to be limited to the provided -Sources and do not consult Windows Update/WSUS sources 

#------------------------------------------------------------------------------------------------------------------------
# Starting: DISM /Online /Restorehealth (Component Store Health Check)"
#------------------------------------------------------------------------------------------------------------------------
$p = @{ Online=$true; RestoreHealth=$true; ErrorAction='Stop' }
$preview = 'Repair-WindowsImage -Online -RestoreHealth'
say info "$(Get-Date) Starting: $preview (Repair-WindowsImage is the PowerShell version of DISM)"
$repair_WinImg = Repair-WindowsImage @p

$repair_WinImg_ImageHealthState = $repair_WinImg.ImageHealthState
if ($repair_WinImg_ImageHealthState -eq 'Repairable') {
    Say Warn "Note: Found problem(s) in the component store but they are repairable."

    #-----------------------------------------------------------------------------------------------------
    say info "$(Get-Date) Starting: 'Repair-WindowsImage -RestoreHealth -Online -Sources $Source -LimitAccess:$LimitAccess -ScratchDirectory $ScratchDirectory'"
    #-------------------------------------------------------------------------------------------------------------
    $p = @{ Online=$true;  RestoreHealth=$true }
    if($Source -and $Source.Count -gt 0){ $p.Source = ($Source -join ';') }
    if($LimitAccess){ $p.LimitAccess = $true }
    if($ScratchDirectory){ $p.ScratchDirectory = $ScratchDirectory }
    try{
        # Example of what it returns: @{ImageHealthState="Healthy"; RestartNeeded=$false}
        $repair_result = Repair-WindowsImage @p -ErrorAction Stop
        if ($repair_result.RestartNeeded) {Abort-Script "Aborting: Please reboot, then run me again." "On completion Windows Image health was '$($repair_result.ImageHealthState)'"}
        Say Good "Repair-WindowsImage -RestoreHealth completed successfully." 

        #-----------------------------------------------------------------------------------------------------
        say info "$(Get-Date) Starting: 'Repair-WindowsImage -ScanHealth -Online' (deep check)"
        # We prefer ScanHealth for a thorough verification
        #-----------------------------------------------------------------------------------------------------
        try {
            $imageHealthState = (Repair-WindowsImage -ScanHealth -Online -ErrorAction Stop).ImageHealthState
        } catch {
            $imageHealthState = $null        
            Say Warn "Note: ScanHealth failed; will fall back to CheckHealth." $_.Exception.Message
        }
    
        if (-not $imageHealthState) {
            #-----------------------------------------------------------------------------------------------------
            say info "$(Get-Date) Starting: 'Repair-WindowsImage -Online -CheckHealth' as a fallback"
            #-----------------------------------------------------------------------------------------------------
            try {
                $imageHealthState = (Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop).ImageHealthState
            } catch {
                $imageHealthState = $null        
                $null = Get-InterestingDISMLogLines
                $null = Get-InterestingCBSLogLines
                Abort-Script "Aborting: 'Repair-WindowsImage -Online -CheckHealth' also failed" $_.Exception.Message
            }
        }
    
        if ($imageHealthState -eq 'Healthy') {
            Say Good "OK: component store now reports healthy." "Post-repair verification = $imageHealthState."
        } else {
            $null = Get-InterestingDISMLogLines
            $null = Get-InterestingCBSLogLines
            Abort-Script "Aborting: component store not healthy after repair." "imageHealthState = $imageHealthState."
        }        
    }catch{
        $err_msg = $_.Exception.Message
        Write-Log 'Error' $err_msg
        $null = Get-InterestingDISMLogLines
        $null = Get-InterestingCBSLogLines
        Say bad $err_msg
        if    ($err_msg -match '0x800f081f')     { Abort-Script "Aborting: repair needs Windows source media -- rerun with -source param." }
        elseif($err_msg -match '0x800f0906')     { Abort-Script "Aborting: provided -source lacks required source files."}
        elseif($err_msg -match 'repair.*pending'){ Abort-Script "Aborting: previous repair is pending a reboot." "Reboot, then rerun."}
        else                                     { Abort-Script "Aborting: RestoreHealth failed."}    
    }    
} elseif ($repair_WinImg_ImageHealthState -eq 'NonRepairable') {
    Say Warn "Error: component store corruption is non-repairable. Skipping automatic repair." 
    Say Info "We will collect diagnostics with 'Repair-WindowsImage -ScanHealth -Online'. Plan an in-place repair install with matching media."
    Repair-WindowsImage -ScanHealth -Online -ErrorAction Stop
    $null = Get-InterestingDISMLogLines
    $null = Get-InterestingCBSLogLines
    Abort-Script "Aborting after non-repairable component store corruption and collection of diagnostics." "Plan an in-place repair install with matching media."
} elseif ($repair_WinImg_ImageHealthState -eq 'Healthy') {
    Say Good "OK: DISM found Component Store to be healthy." 
} else {
    $null = Get-InterestingDISMLogLines
    $null = Get-InterestingCBSLogLines
    Abort-Script "Aborting: unable to determine component store health. Summary.CheckHealth is $repair_WinImg_ImageHealthState instead of 'Healthy','Repairable','NonRepairable'" 
}


say info "$(Get-Date) Starting SFC /scannow"
$sfc_scan_result = Invoke-Sfc '/scannow'
switch ($sfc_scan_result.Result) {
    'PendingReboot' { 
        Abort-Script "Aborting: a reboot is required to complete repairs." "Reboot, then rerun if necessary."
    }
    'NotRepaired'   { 
        $null = Get-InterestingCBSLogLines
        Abort-Script "Aborting: SFC could not repair some files." `
        "I suggest you run me again once. Also check $systemDrive\Windows\Logs\DISM\dism.log, $systemDrive\Windows\Logs\CBS\CBS.log; consider providing DISM source or in-place repair."
    }
    'Repaired'      { 
        $null = Get-InterestingCBSLogLines
        Say Good "Repair completed: SFC fixed corrupt files." 
        Say Warn "I suggest you reboot, sooner than latter."
    }
    'NoViolations'  { 
        Say Good "OK: SFC /scannow found no integrity violations." 
    }
    default         { 
        $null = Get-InterestingCBSLogLines
        Abort-Script "Aborting: SFC /scannow returned an unrecognized message." `
        "Check the log file for full output." 
    }
}

#  DISM /Online /Restorehealth  
#  SFC /scannow 
Say Debug "You will find a structured log in '$LogFile'"
Say Debug "You will find the transcript of this session in '$TranscriptFile'"
Say Debug "If you *desperately* need free space, you may run: DISM /Cleanup-image"
Say Info "$(Get-Date) All Done."
try { Stop-Transcript | Out-Null } catch {}
