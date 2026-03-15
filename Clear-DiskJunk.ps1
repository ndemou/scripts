function Clear-DiskJunk {
<#
.SYNOPSIS
Deletes selected junk files and directories from a copied disk tree, with conservative defaults and full WhatIf/Confirm support.

.DESCRIPTION
Clear-DiskJunk scans a target path and removes only the junk categories you explicitly allow.

By default it runs in conservative mode and targets:
- browser-caches
- safe-temp-files

Conservative mode avoids deleting generic directory names such as cache, temp, log, or logs unless you explicitly include
DANGEROUS-broad-temp-cache-logs.

The function is designed for very large trees. It streams matches as they are found instead of accumulating all results in memory.
Use -PassThru to emit one result object per matched item. Without -PassThru it emits only a final summary object.

safe-temp-files deletes:
- *.tmp files older than 30 days
- Office temp files (~$*.??? and ~$*.????)

DANGEROUS-broad-temp-cache-logs expands matching to broad generic temp/cache/log locations and broad *.log / *.tmp file cleanup.

.EXAMPLE
Clear-DiskJunk -Path D:\MountedDisk -WhatIf

Shows what would be deleted using the conservative default categories.

.EXAMPLE
Clear-DiskJunk -Path D:\MountedDisk -IncludeCategory browser-caches,DANGEROUS-broad-temp-cache-logs -Confirm

Prompts before deleting and includes the dangerous broad cleanup category.

.EXAMPLE
Clear-DiskJunk -Path D:\MountedDisk -ExcludePath 'D:\MountedDisk\Users\Nick\AppData\Local\Google\*' -PassThru |
    Export-Csv C:\temp\diskjunk-results.csv -NoTypeInformation

Streams one result object per matched item and saves them.

.PARAMETER Path
Root path to scan.

.PARAMETER IncludeCategory
Cleanup categories to include.

Allowed values:
- browser-caches
- safe-temp-files
- DANGEROUS-broad-temp-cache-logs

Default:
- browser-caches
- safe-temp-files

.PARAMETER ExcludePath
Paths or wildcard patterns to exclude. Matches are tested against both full Windows paths and root-relative forward-slash paths.

.PARAMETER TmpOlderThanDays
Age threshold for *.tmp deletion in the safe-temp-files category. Default is 30.

.PARAMETER PassThru
Emits one object per matched item as it is processed. Useful for logging and large-scale runs.

.OUTPUTS
Without -PassThru:
A summary object.

With -PassThru:
One result object per matched item, followed by a final summary object.

.NOTES
- Supports -WhatIf and -Confirm.
- Intended primarily for copies of Windows disks, not live system cleanup.
- Broad cleanup can remove data you may later want for troubleshooting or forensics.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    [ValidateSet(
        'browser-caches',
        'safe-temp-files',
        'DANGEROUS-broad-temp-cache-logs'
    )]
    [string[]]$IncludeCategory = @(
        'browser-caches',
        'safe-temp-files'
    ),

    [string[]]$ExcludePath = @(),

    [ValidateRange(1,3650)]
    [int]$TmpOlderThanDays = 30,

    [switch]$PassThru
)

Set-StrictMode -Version 2

$resolvedRoot = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
    throw "Path not found or not a directory: $resolvedRoot"
}

$normalizedRoot = [System.IO.Path]::GetFullPath($resolvedRoot).TrimEnd('\')
$normalizedRootLower = $normalizedRoot.ToLowerInvariant()
$hasDangerous = $IncludeCategory -contains 'DANGEROUS-broad-temp-cache-logs'
$tmpCutoff = (Get-Date).AddDays(-$TmpOlderThanDays)

$script:stats = [ordered]@{
    RootPath          = $normalizedRoot
    Categories        = @($IncludeCategory)
    ExcludePath       = @($ExcludePath)
    TmpOlderThanDays  = $TmpOlderThanDays
    MatchCount        = 0L
    DeletedCount      = 0L
    WouldDeleteCount  = 0L
    FailedCount       = 0L
    SkippedCount      = 0L
    DeletedBytes      = 0L
    WouldDeleteBytes  = 0L
    FailedBytes       = 0L
}

function Convert-ToRelativeUnixPath {
    param(
        [string]$FullName,
        [string]$Root,
        [string]$RootLower
    )

    $full = [System.IO.Path]::GetFullPath($FullName)
    $fullLower = $full.ToLowerInvariant()

    if ($fullLower -eq $RootLower) { return '/' }
    if (-not $fullLower.StartsWith($RootLower + '\')) {
        throw "Path '$full' is not under root '$Root'"
    }

    $relative = $full.Substring($Root.Length).TrimStart('\')
    '/' + ($relative -replace '\\', '/')
}

function Test-IsExcluded {
    param(
        [string]$FullName,
        [string]$Root,
        [string]$RootLower,
        [string[]]$Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }

    $full = [System.IO.Path]::GetFullPath($FullName)
    $unixRel = Convert-ToRelativeUnixPath -FullName $full -Root $Root -RootLower $RootLower

    foreach ($pattern in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }

        if ($pattern.Contains('*') -or $pattern.Contains('?') -or $pattern.Contains('[')) {
            if ($full -like $pattern -or $unixRel -like $pattern) { return $true }
        } else {
            $candidate = $pattern.TrimEnd('\','/')
            if ($full.ToLowerInvariant().StartsWith($candidate.ToLowerInvariant())) { return $true }
            if ($unixRel.ToLowerInvariant().StartsWith($candidate.ToLowerInvariant())) { return $true }
        }
    }

    $false
}

function Get-DirLengthSafe {
    param([string]$LiteralPath)

    $sum = 0L
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $LiteralPath -Recurse -Force -File -ErrorAction SilentlyContinue)) {
            $sum += $f.Length
        }
    } catch {
    }
    $sum
}

function New-ResultRecord {
    param(
        [string]$Kind,
        [string]$Category,
        [string]$ItemPath,
        [string]$Reason,
        [Int64]$Bytes,
        [string]$Status,
        [string]$Message
    )

    [pscustomobject]@{
        Kind     = $Kind
        Category = $Category
        Path     = $ItemPath
        Reason   = $Reason
        SizeMB   = [math]::Round(($Bytes / 1MB), 2)
        Status   = $Status
        Message  = $Message
    }
}

function Write-ResultRecord {
    param(
        [string]$Kind,
        [string]$Category,
        [string]$ItemPath,
        [string]$Reason,
        [Int64]$Bytes,
        [string]$Status,
        [string]$Message
    )

    $script:stats.MatchCount++

    switch ($Status) {
        'Deleted' {
            $script:stats.DeletedCount++
            $script:stats.DeletedBytes += $Bytes
        }
        'WouldDelete' {
            $script:stats.WouldDeleteCount++
            $script:stats.WouldDeleteBytes += $Bytes
        }
        'Failed' {
            $script:stats.FailedCount++
            $script:stats.FailedBytes += $Bytes
        }
        'Skipped' {
            $script:stats.SkippedCount++
        }
    }

    if ($PassThru) {
        New-ResultRecord -Kind $Kind -Category $Category -ItemPath $ItemPath -Reason $Reason -Bytes $Bytes -Status $Status -Message $Message
    }
}

function Test-BrowserCacheDir {
    param([string]$RelativeUnixPath)

    if ($RelativeUnixPath -imatch '/Mozilla/[^/]+/Cache$') { return 'browser-caches: Mozilla profile Cache' }
    if ($RelativeUnixPath -imatch '/MicrosoftEdge/Cache$') { return 'browser-caches: MicrosoftEdge Cache' }
    if ($RelativeUnixPath -imatch '/MicrosoftEdge/[^/]+/Cache$') { return 'browser-caches: MicrosoftEdge profile Cache' }
    if ($RelativeUnixPath -imatch '/Chrome/[^/]+/Cache$') { return 'browser-caches: Chrome profile Cache' }
    if ($RelativeUnixPath -imatch '/Default/Media Cache$') { return 'browser-caches: Chromium Media Cache' }
    if ($RelativeUnixPath -imatch '/GoogleEarth/unified_cache$') { return 'browser-caches: GoogleEarth unified_cache' }
    if ($RelativeUnixPath -imatch '/Skype/[^/]+/emo_cache$') { return 'browser-caches: Skype emo_cache' }
    if ($RelativeUnixPath -imatch '/Device Metadata/dmrccache$') { return 'browser-caches: Device Metadata dmrccache' }
    if ($RelativeUnixPath -imatch '/INetCache$') { return 'browser-caches: INetCache' }
    if ($RelativeUnixPath -imatch '/WebCache$') { return 'browser-caches: WebCache' }
    if ($RelativeUnixPath -imatch '/OfficeFileCache$') { return 'browser-caches: OfficeFileCache' }
    if ($RelativeUnixPath -imatch '/CryptnetUrlCache$') { return 'browser-caches: CryptnetUrlCache' }
    if ($RelativeUnixPath -imatch '/AppCache$') { return 'browser-caches: AppCache' }
    if ($RelativeUnixPath -imatch '/IECompatCache$') { return 'browser-caches: IECompatCache' }
    if ($RelativeUnixPath -imatch '/WebServiceCache$') { return 'browser-caches: WebServiceCache' }
    if ($RelativeUnixPath -imatch '/IECompatUaCache$') { return 'browser-caches: IECompatUaCache' }
    $null
}

function Test-DangerousDir {
    param([string]$RelativeUnixPath)

    if ($RelativeUnixPath -imatch '/cache$') { return 'DANGEROUS-broad-temp-cache-logs: generic cache dir' }
    if ($RelativeUnixPath -imatch '/LocalCache$') { return 'DANGEROUS-broad-temp-cache-logs: LocalCache dir' }
    if ($RelativeUnixPath -imatch '/Package Cache$') { return 'DANGEROUS-broad-temp-cache-logs: Package Cache dir' }
    if ($RelativeUnixPath -imatch '/logs$') { return 'DANGEROUS-broad-temp-cache-logs: generic logs dir' }
    if ($RelativeUnixPath -imatch '/log$') { return 'DANGEROUS-broad-temp-cache-logs: generic log dir' }
    if ($RelativeUnixPath -imatch '/temp$') { return 'DANGEROUS-broad-temp-cache-logs: generic temp dir' }
    if ($RelativeUnixPath -imatch '/temporary[^/]*$') { return 'DANGEROUS-broad-temp-cache-logs: generic temporary* dir' }
    if ($RelativeUnixPath -imatch '/AppData/Local/Microsoft/Windows$') { return 'DANGEROUS-broad-temp-cache-logs: broad Microsoft Windows AppData subtree' }
    if ($RelativeUnixPath -imatch '/AppData/Local/Microsoft/Device Stage$') { return 'DANGEROUS-broad-temp-cache-logs: broad Device Stage subtree' }
    $null
}

function Get-DirectoryAction {
    param([string]$FullName)

    if (Test-IsExcluded -FullName $FullName -Root $normalizedRoot -RootLower $normalizedRootLower -Patterns $ExcludePath) {
        return [pscustomobject]@{ Category = 'Excluded'; Reason = 'Matched -ExcludePath'; Excluded = $true }
    }

    $rel = Convert-ToRelativeUnixPath -FullName $FullName -Root $normalizedRoot -RootLower $normalizedRootLower

    if ($IncludeCategory -contains 'browser-caches') {
        $reason = Test-BrowserCacheDir -RelativeUnixPath $rel
        if ($reason) {
            return [pscustomobject]@{ Category = 'browser-caches'; Reason = $reason; Excluded = $false }
        }
    }

    if ($hasDangerous) {
        $reason = Test-DangerousDir -RelativeUnixPath $rel
        if ($reason) {
            return [pscustomobject]@{ Category = 'DANGEROUS-broad-temp-cache-logs'; Reason = $reason; Excluded = $false }
        }
    }

    $null
}

function Get-FileAction {
    param([System.IO.FileInfo]$File)

    if (Test-IsExcluded -FullName $File.FullName -Root $normalizedRoot -RootLower $normalizedRootLower -Patterns $ExcludePath) {
        return [pscustomobject]@{ Category = 'Excluded'; Reason = 'Matched -ExcludePath'; Excluded = $true }
    }

    if ($IncludeCategory -contains 'safe-temp-files') {
        if ($File.Name -like '*.tmp' -and $File.LastWriteTime -lt $tmpCutoff) {
            return [pscustomobject]@{
                Category = 'safe-temp-files'
                Reason   = "safe-temp-files: *.tmp older than $($TmpOlderThanDays) days"
                Excluded = $false
            }
        }
        if ($File.Name -like '~$*.???') {
            return [pscustomobject]@{
                Category = 'safe-temp-files'
                Reason   = 'safe-temp-files: Office temp file (~$*.???)'
                Excluded = $false
            }
        }
        if ($File.Name -like '~$*.????') {
            return [pscustomobject]@{
                Category = 'safe-temp-files'
                Reason   = 'safe-temp-files: Office temp file (~$*.????)'
                Excluded = $false
            }
        }
    }

    if ($hasDangerous) {
        if ($File.Name -like '*.log') {
            return [pscustomobject]@{
                Category = 'DANGEROUS-broad-temp-cache-logs'
                Reason   = 'DANGEROUS-broad-temp-cache-logs: *.log file'
                Excluded = $false
            }
        }
        if ($File.Name -like '*.tmp') {
            return [pscustomobject]@{
                Category = 'DANGEROUS-broad-temp-cache-logs'
                Reason   = 'DANGEROUS-broad-temp-cache-logs: *.tmp file'
                Excluded = $false
            }
        }
    }

    $null
}

function Process-Directory {
    param([System.IO.DirectoryInfo]$Dir)

    $action = Get-DirectoryAction -FullName $Dir.FullName
    if (-not $action) { return $false }

    if ($action.Excluded) {
        Write-ResultRecord -Kind 'Directory' -Category $action.Category -ItemPath $Dir.FullName -Reason $action.Reason -Bytes 0 -Status 'Skipped' -Message 'Excluded'
        return $false
    }

    $bytes = Get-DirLengthSafe -LiteralPath $Dir.FullName

    if ($PSCmdlet.ShouldProcess($Dir.FullName, 'Remove directory recursively')) {
        try {
            Remove-Item -LiteralPath $Dir.FullName -Recurse -Force -ErrorAction Stop
            Write-ResultRecord -Kind 'Directory' -Category $action.Category -ItemPath $Dir.FullName -Reason $action.Reason -Bytes $bytes -Status 'Deleted' -Message 'Removed'
            return $true
        } catch {
            $msg = $_.Exception.Message
            Write-Warning "$($Dir.FullName): $msg"
            Write-ResultRecord -Kind 'Directory' -Category $action.Category -ItemPath $Dir.FullName -Reason $action.Reason -Bytes $bytes -Status 'Failed' -Message $msg
            return $false
        }
    } else {
        Write-ResultRecord -Kind 'Directory' -Category $action.Category -ItemPath $Dir.FullName -Reason $action.Reason -Bytes $bytes -Status 'WouldDelete' -Message 'WhatIf/Confirm prevented deletion'
        return $true
    }
}

function Process-File {
    param([System.IO.FileInfo]$File)

    $action = Get-FileAction -File $File
    if (-not $action) { return }

    if ($action.Excluded) {
        Write-ResultRecord -Kind 'File' -Category $action.Category -ItemPath $File.FullName -Reason $action.Reason -Bytes 0 -Status 'Skipped' -Message 'Excluded'
        return
    }

    $bytes = $File.Length

    if ($PSCmdlet.ShouldProcess($File.FullName, 'Remove file')) {
        try {
            Remove-Item -LiteralPath $File.FullName -Force -ErrorAction Stop
            Write-ResultRecord -Kind 'File' -Category $action.Category -ItemPath $File.FullName -Reason $action.Reason -Bytes $bytes -Status 'Deleted' -Message 'Removed'
        } catch {
            $msg = $_.Exception.Message
            Write-Warning "$($File.FullName): $msg"
            Write-ResultRecord -Kind 'File' -Category $action.Category -ItemPath $File.FullName -Reason $action.Reason -Bytes $bytes -Status 'Failed' -Message $msg
        }
    } else {
        Write-ResultRecord -Kind 'File' -Category $action.Category -ItemPath $File.FullName -Reason $action.Reason -Bytes $bytes -Status 'WouldDelete' -Message 'WhatIf/Confirm prevented deletion'
    }
}

function Walk-Tree {
    param([string]$CurrentPath)

    $children = @(Get-ChildItem -LiteralPath $CurrentPath -Force -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        if ($child.PSIsContainer) {
            $prune = Process-Directory -Dir $child
            if (-not $prune) {
                Walk-Tree -CurrentPath $child.FullName
            }
        } else {
            Process-File -File $child
        }
    }
}

Walk-Tree -CurrentPath $normalizedRoot

[pscustomobject]@{
    RootPath          = $script:stats.RootPath
    Categories        = $script:stats.Categories
    ExcludePath       = $script:stats.ExcludePath
    TmpOlderThanDays  = $script:stats.TmpOlderThanDays
    MatchCount        = $script:stats.MatchCount
    DeletedCount      = $script:stats.DeletedCount
    WouldDeleteCount  = $script:stats.WouldDeleteCount
    FailedCount       = $script:stats.FailedCount
    SkippedCount      = $script:stats.SkippedCount
    DeletedSizeMB     = [math]::Round(($script:stats.DeletedBytes / 1MB), 2)
    WouldDeleteSizeMB = [math]::Round(($script:stats.WouldDeleteBytes / 1MB), 2)
    FailedSizeMB      = [math]::Round(($script:stats.FailedBytes / 1MB), 2)
}
}
