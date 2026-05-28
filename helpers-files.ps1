<#
A collection of helper functions for handling files
#>

function Get-HardLinks {
<# 
.SYNOPSIS
Lists files in the current directory that have >1 hardlink, and shows all link paths
.EXAMPLE
Get-HardLinks|Format-List
#>
    Get-ChildItem -File | ForEach-Object {
      $links = & fsutil hardlink list $_.FullName 2>$null
      if ($LASTEXITCODE -eq 0 -and $links.Count -gt 1) {
        [pscustomobject]@{
          File      = $_.Name
          LinkCount = $links.Count
          Links     = ($links -join "`n")
        }
      }
    } 
}

function New-ZipFromFolder {
<#
.SYNOPSIS
Creates a zip file from a folder, keeping the folder as the top-level entry and allowing for exclusions.

.DESCRIPTION
Packages the source folder into a zip file whose top-level folder name
matches the source folder name. Allows for recursive exclusions based 
on file name, folder name, or relative path.

Creates a sibling staging folder next to the source folder and removes
it before returning. On NTFS volumes, included files are staged as
hardlinks unless DontUseHardLinks is set. Hardlinking is super-fast.

.PARAMETER Exclude
Wildcard patterns used to skip files or folders anywhere under the
source folder. A pattern can match an item name or a relative path.

.PARAMETER NoCompression
When set, writes the archive without compression. 

.PARAMETER Fast
When set, writes the archive with the fastest compression level.

.PARAMETER DontUseHardLinks
When set, stages included files by copying them; otherwise the function
uses hardlinks when the source volume supports them.

.EXAMPLE
New-ZipFromFolder .\App .\App.zip `
  -Exclude '*.bak','*.tmp','.git'

Creates the zip while skipping matching files and folders under App.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceFolderPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationPath,

    [string[]]$Exclude = @(),

    [switch]$NoCompression,
    [switch]$Fast,
    [switch]$DontUseHardLinks
  )

  Set-StrictMode -Version 2
  $ErrorActionPreference = 'Stop'

  function Test-ExcludeMatch {
    param(
      [Parameter(Mandatory = $true)][string]$Name,
      [Parameter(Mandatory = $true)][string]$RelativePath,
      [string[]]$Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }

    $relativePathNormalized = $RelativePath -replace '/', '\'

    foreach ($pattern in $Patterns) {
      if ([string]::IsNullOrWhiteSpace($pattern)) { continue }

      $patternNormalized = $pattern -replace '/', '\'

      if ($Name -like $patternNormalized) { return $true }
      if ($relativePathNormalized -like $patternNormalized) { return $true }
      if ($relativePathNormalized -like "*\$($patternNormalized)") {
        return $true
      }
    }

    return $false
  }

  function Get-VolumeRoot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    return [System.IO.Path]::GetPathRoot($resolved)
  }

  function Test-PathIsNtfs {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root)) { return $false }

    $driveLetter = $root.TrimEnd('\').TrimEnd(':')
    if ([string]::IsNullOrWhiteSpace($driveLetter)) { return $false }

    $disk = Get-CimInstance -ClassName Win32_LogicalDisk `
      -Filter "DeviceID='$($driveLetter):'" -ErrorAction SilentlyContinue
    if (-not $disk) { return $false }

    return ($disk.FileSystem -eq 'NTFS')
  }

  function New-HardLinkFile {
    param(
      [Parameter(Mandatory = $true)][string]$Path,
      [Parameter(Mandatory = $true)][string]$Target
    )

    $null = New-Item -ItemType HardLink -Path $Path -Target $Target `
      -ErrorAction Stop
  }

  function Copy-TreeWithExclusions {
    param(
      [Parameter(Mandatory = $true)][string]$SourceRoot,
      [Parameter(Mandatory = $true)][string]$DestinationRoot,
      [string[]]$Patterns,
      [bool]$UseHardLinks
    )

    $sourceRootResolved = (
      Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop
    ).ProviderPath.TrimEnd('\')

    Get-ChildItem -LiteralPath $sourceRootResolved -Force | ForEach-Object {
      $stack = New-Object System.Collections.Stack
      $stack.Push($_)

      while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $relativePath = $item.FullName.Substring(
          $sourceRootResolved.Length
        ).TrimStart('\')

        if ([string]::IsNullOrWhiteSpace($relativePath)) { continue }

        if (Test-ExcludeMatch -Name $item.Name `
            -RelativePath $relativePath `
            -Patterns $Patterns) {
          continue
        }

        $targetPath = Join-Path -Path $DestinationRoot `
          -ChildPath $relativePath

        if ($item.PSIsContainer) {
          if (-not (Test-Path -LiteralPath $targetPath)) {
            New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
          }

          Get-ChildItem -LiteralPath $item.FullName -Force |
            Sort-Object Name -Descending |
            ForEach-Object { $stack.Push($_) }
        } else {
          $targetParent = Split-Path -Path $targetPath -Parent
          if (-not (Test-Path -LiteralPath $targetParent)) {
            New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
          }

          if ($UseHardLinks) {
            New-HardLinkFile -Path $targetPath -Target $item.FullName
          } else {
            Copy-Item -LiteralPath $item.FullName `
              -Destination $targetPath -Force
          }
        }
      }
    }
  }

  if ($NoCompression -and $Fast) {
    throw 'Use either -NoCompression or -Fast, not both.'
  }

  $compressionLevel = 'Optimal'
  if ($NoCompression) {
    $compressionLevel = 'NoCompression'
  } elseif ($Fast) {
    $compressionLevel = 'Fastest'
  }

  $sourceItem = Get-Item -LiteralPath $SourceFolderPath -ErrorAction Stop
  if (-not $sourceItem.PSIsContainer) {
    throw "SourceFolderPath must point to a folder: $($SourceFolderPath)"
  }

  $zipPathInput = $DestinationPath
  if ([System.IO.Path]::GetExtension($zipPathInput) -ne '.zip') {
    throw "DestinationPath must end with .zip: $($DestinationPath)"
  }

  $zipFileName = [System.IO.Path]::GetFileName($zipPathInput)
  $zipDirectoryInput = Split-Path -Path $zipPathInput -Parent
  if ([string]::IsNullOrWhiteSpace($zipDirectoryInput)) {
    $zipDirectoryInput = '.'
  }

  if (-not (Test-Path -LiteralPath $zipDirectoryInput)) {
    New-Item -ItemType Directory -Path $zipDirectoryInput -Force | Out-Null
  }

  $zipDirectory = (
    Resolve-Path -LiteralPath $zipDirectoryInput -ErrorAction Stop
  ).ProviderPath
  $zipPath = Join-Path -Path $zipDirectory -ChildPath $zipFileName

  $sourceParent = Split-Path -Path $sourceItem.FullName -Parent
  $rootFolderName = $sourceItem.Name
  $tempRoot = Join-Path -Path $sourceParent `
    -ChildPath ("~temp-" + [guid]::NewGuid().ToString())
  $stagingRoot = Join-Path -Path $tempRoot -ChildPath $rootFolderName

  $useHardLinks = $false
  if (-not $DontUseHardLinks) {
    $sourceVolumeRoot = Get-VolumeRoot -Path $sourceItem.FullName
    $stageVolumeRoot = [System.IO.Path]::GetPathRoot($tempRoot)

    if (($sourceVolumeRoot -eq $stageVolumeRoot) -and
        (Test-PathIsNtfs -Path $sourceItem.FullName)) {
      $useHardLinks = $true
    }
  }

  try {
    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

    Copy-TreeWithExclusions `
      -SourceRoot $sourceItem.FullName `
      -DestinationRoot $stagingRoot `
      -Patterns $Exclude `
      -UseHardLinks $useHardLinks

    if (Test-Path -LiteralPath $zipPath) {
      Remove-Item -LiteralPath $zipPath -Force
    }

    Compress-Archive -LiteralPath $stagingRoot `
      -DestinationPath $zipPath `
      -CompressionLevel $compressionLevel `
      -Force

    if (-not (Test-Path -LiteralPath $zipPath)) {
      throw "Zip file was not created: $($zipPath)"
    }

    Get-Item -LiteralPath $zipPath -ErrorAction Stop
  }
  finally {
    if (Test-Path -LiteralPath $tempRoot) {
      Remove-Item -LiteralPath $tempRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
    }
  }
}

function Delete-OldFiles {
<#
.SYNOPSIS
Deletes old files under a directory tree, with WhatIf support.

.DESCRIPTION
Attempts to remove files under Root whose LastWriteTime is older than Cutoff.
Use this when you need recursive age-based cleanup with WhatIf support and
optional cleanup of child folders left empty by the cleanup.

Skips reparse points (junctions/symlinks/mount points) so cleanup stays inside
the intended tree.

By default, non-root child folders will be removed when they have no
remaining files or child folders after file cleanup. Root is not
removed. When LeaveEmptyFolders is set, folders are not removed.

Deletion failures for individual files or folders are reported as warnings.
Other matching files and folders may still be processed. Permission limits,
locked files, and enumeration errors can leave matching files or folders in
place.

.OUTPUTS
None. Does not write objects to the pipeline.

Writes scan and deletion status to the host.
Writes warnings for failed file or folder removals.

.PARAMETER Root
Directory tree to clean. The path must identify an existing directory.

.PARAMETER Cutoff
Files with LastWriteTime earlier than this value are candidates for removal.

.PARAMETER LeaveEmptyFolders
When set, only matching files are removed; otherwise, non-root child folders
left empty by the cleanup scope may also be removed.

.EXAMPLE
Delete-OldFiles -Root C:\Temp -Cutoff (Get-Date).AddMonths(-6) -WhatIf

Shows the files and folders that would be removed under C:\Temp.

.EXAMPLE
Delete-OldFiles -Root C:\Temp -Cutoff (Get-Date).AddMonths(-6) `
    -LeaveEmptyFolders

Removes old files under C:\Temp but does not remove empty folders.
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [datetime]$Cutoff,

        [switch]$LeaveEmptyFolders
    )

    $RootItem = Get-Item -LiteralPath $Root -ErrorAction Stop
    $RootFullName = $RootItem.FullName.TrimEnd('\')
    $WouldDeleteDirs = @{}

    $Dirs = @(
        @($RootItem) + @(
            Get-ChildItem -LiteralPath $RootItem.FullName -Directory -Force -Recurse -ErrorAction SilentlyContinue
        ) |
            Sort-Object `
                @{ Expression = { ($_.FullName.TrimEnd('\') -split '\\').Count }; Descending = $true },
                @{ Expression = { $_.FullName }; Descending = $true }
    )

    $TotalDirs = $Dirs.Count
    $ScannedDirs = 0

    foreach ($DirItem in $Dirs) {
        $ScannedDirs++

        $Dir = $DirItem.FullName
        $DirFullName = $Dir.TrimEnd('\')

        $PercentComplete = 0
        if ($TotalDirs -gt 0) {
            $PercentComplete = [int](($ScannedDirs / $TotalDirs) * 100)
        }

        Write-Progress `
            -Activity "Deleting old files under $RootFullName" `
            -Status "Scanning folder $ScannedDirs of $TotalDirs" `
            -CurrentOperation $Dir `
            -PercentComplete $PercentComplete

        $TotalFiles = 0
        $OldCandidateFiles = 0
        $DeletedFiles = 0

        Get-ChildItem -LiteralPath $Dir -File -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                $TotalFiles++

                # Skip reparse points (junctions/symlinks/mount points) so cleanup stays inside the intended temp tree and does not follow links into unrelated locations.
                $reparsePoint = ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint
                if ($_.LastWriteTime -lt $Cutoff -and -not $reparsePoint) {
                    $OldCandidateFiles++
                    $File = $_

                    if ($PSCmdlet.ShouldProcess($File.FullName, "Delete old file")) {
                        try {
                            Remove-Item -LiteralPath $File.FullName -Force -ErrorAction Stop
                            $DeletedFiles++
                            Write-Output "Deleted: $($File.FullName)"
                        }
                        catch {
                            Write-Warning "Failed: $($File.FullName) - $($_.Exception.Message)"
                        }
                    }
                }
            }

        if ($WhatIfPreference) {
            $EffectiveDeletedFiles = $OldCandidateFiles
        }
        else {
            $EffectiveDeletedFiles = $DeletedFiles
        }

        $IsRoot = [string]::Equals(
            $DirFullName,
            $RootFullName,
            [System.StringComparison]::OrdinalIgnoreCase
        )

        if (-not $LeaveEmptyFolders -and $TotalFiles -eq $EffectiveDeletedFiles -and -not $IsRoot) {
            $FirstRemainingSubDir = Get-ChildItem -LiteralPath $Dir -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $SubDirFullName = $_.FullName.TrimEnd('\')
                    -not ($WhatIfPreference -and $WouldDeleteDirs.ContainsKey($SubDirFullName))
                } |
                Select-Object -First 1

            if (-not $FirstRemainingSubDir) {
                if ($PSCmdlet.ShouldProcess($Dir, "Delete empty folder")) {
                    try {
                        Remove-Item -LiteralPath $Dir -Force -ErrorAction Stop
                        $WouldDeleteDirs[$DirFullName] = $true
                        Write-Output "Deleted folder: $Dir"
                    }
                    catch {
                        Write-Warning "Failed deleting folder: $Dir - $($_.Exception.Message)"
                    }
                }
                elseif ($WhatIfPreference) {
                    $WouldDeleteDirs[$DirFullName] = $true
                }
            }
        }
    }

    Write-Progress `
        -Activity "Deleting old files under $RootFullName" `
        -Completed
}

function Get-DiskInfo {
    <#
    .SYNOPSIS Gets Win32_LogicalDisk information for one disk.
    .DESCRIPTION Popular properties: FreeSpace, Size, VolumeName, DriveType
    .PARAMETER Disk Disk device ID, for example C:.
    #>
    param([Parameter(Mandatory = $true)][string]$Disk)
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID = '$Disk'")
}

function Test-NonReparseDirectory {
    <#
    .SYNOPSIS Returns true only for real directories, not junctions/symlinks.
    .PARAMETER LiteralPath Directory path to test without wildcard expansion.
    #>
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $Item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction SilentlyContinue
    if (-not $Item) { return $false }
    if (-not $Item.PSIsContainer) { return $false }
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) { return $false }
    return $true
}

function Clear-OldTempFiles {
<#
.SYNOPSIS
Deletes old files from common Windows temporary file locations.

.DESCRIPTION
Attempts to remove old files from the current process TEMP and TMP
locations, the Windows temp location, and detected user temp folders under
C:\Users.

Skips reparse points (junctions/symlinks/mount points) so cleanup stays inside
the intended trees.

Use this as a safer temp cleanup entry point when you need age-based cleanup
across the usual system and user temp locations, WhatIf support, and optional
cleanup of child folders left empty by the cleanup.

The cutoff is calculated from the current time and MonthsOld. By default,
non-root child folders inside each temp root may also be removed when they
have no remaining detected files or child folders after file cleanup. Temp
root folders themselves are not removed.

Deletion failures for individual files or folders are reported as warnings.
Other matching files and folders may still be processed. Permission limits,
locked files, missing profiles, and enumeration errors can leave matching
files or folders in place. Run elevated to cover system and other-user temp
locations where required.

.OUTPUTS
None. Does not write objects to the pipeline.

Writes cutoff, scan, and deletion status to the host.
Writes warnings for failed file or folder removals.

.PARAMETER MonthsOld
Age threshold in months. Files older than the calculated cutoff are
candidates for removal.

.PARAMETER LeaveEmptyFolders
When set, only matching files are removed; otherwise, non-root child folders
left empty by the cleanup will also be removed.

.EXAMPLE
Clear-OldTempFiles -WhatIf

Shows the old temp files and folders that would be removed.

.EXAMPLE
Clear-OldTempFiles -MonthsOld 3 -LeaveEmptyFolders

Removes temp files older than the calculated cutoff and keeps folders.
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [int]$MonthsOld = 6,

        [switch]$LeaveEmptyFolders
    )

    $Cutoff = (Get-Date).AddMonths(-1 * $MonthsOld)

    $TempRoots = New-Object System.Collections.Generic.List[string]

    $CandidateRoots = @(
        $env:TEMP,
        $env:TMP,
        "$env:WINDIR\Temp"
    )

    foreach ($Path in $CandidateRoots) {
        if ($Path -and (Test-NonReparseDirectory -LiteralPath $Path)) {
            $TempRoots.Add((Get-Item -LiteralPath $Path -Force).FullName)
        }
    }

    $UserTempRoots = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne [System.IO.FileAttributes]::ReparsePoint
        } |
        ForEach-Object {
            Join-Path $_.FullName "AppData\Local\Temp"
        } |
        Where-Object {
            Test-NonReparseDirectory -LiteralPath $_
        }

    foreach ($Path in $UserTempRoots) {
        $TempRoots.Add((Get-Item -LiteralPath $Path -Force).FullName)
    }

    $TempRoots = $TempRoots | Sort-Object -Unique

    Write-Output "Will delete files older than $($Cutoff.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output ""

    $SystemDisk = $env:SystemDrive.TrimEnd('\')
    $FreeBeforeBytes = 0
    try {$FreeBeforeBytes = (Get-DiskInfo $env:SystemDrive.TrimEnd('\')).FreeSpace} catch {}

    foreach ($Root in $TempRoots) {
        Delete-OldFiles `
            -Root $Root `
            -Cutoff $Cutoff `
            -LeaveEmptyFolders:$LeaveEmptyFolders `
            -WhatIf:$WhatIfPreference
    }

    $FreeAfterBytes = 0
    try {$FreeAfterBytes = (Get-DiskInfo $env:SystemDrive.TrimEnd('\')).FreeSpace} catch {}
    $FreeGainedBytes = $FreeAfterBytes - $FreeBeforeBytes

    Write-Output ""
    Write-Output "System disk($SystemDisk) free-space report:"
    Write-Output ("  Free before      : {0:N1} MB" -f ($FreeBeforeBytes / 1MB))
    Write-Output ("  Free after       : {0:N1} MB" -f ($FreeAfterBytes / 1MB))
    Write-Output ("  Free space gained: {0:N1} MB" -f ($FreeGainedBytes / 1MB))
}

