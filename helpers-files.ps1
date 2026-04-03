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
Creates a zip file from a folder keeping that folder as the top-level entry in the zip.

.DESCRIPTION
Packages the source folder into a zip file whose top-level folder name
matches the source folder name. Use it when you need a predictable
archive layout and recursive exclusions based on file name, folder name,
or relative path; Compress-Archive does not offer that as a single call.

Creates the destination folder if needed. If a zip already exists at the
destination path, it is removed before the new zip is written. 

.PARAMETER Exclude
Wildcard patterns used to skip files or folders anywhere under the
source folder. A pattern can match an item name or a relative path.

.PARAMETER Fast
When set, writes the archive with the fastest compression level.

.EXAMPLE
New-ZipFromFolder .\App .\App.zip `
  -Exclude '*.bak','*.tmp','.git'
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
    [switch]$Fast
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
      if ($relativePathNormalized -like "*\$($patternNormalized)") { return $true }
    }

    return $false
  }

  function Copy-TreeWithExclusions {
    param(
      [Parameter(Mandatory = $true)][string]$SourceRoot,
      [Parameter(Mandatory = $true)][string]$DestinationRoot,
      [string[]]$Patterns
    )

    $sourceRootResolved = (Resolve-Path -LiteralPath $SourceRoot -ErrorAction Stop).ProviderPath.TrimEnd('\')

    Get-ChildItem -LiteralPath $sourceRootResolved -Force | ForEach-Object {
      $stack = New-Object System.Collections.Stack
      $stack.Push($_)

      while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $relativePath = $item.FullName.Substring($sourceRootResolved.Length).TrimStart('\')
        if ([string]::IsNullOrWhiteSpace($relativePath)) { continue }

        if (Test-ExcludeMatch -Name $item.Name -RelativePath $relativePath -Patterns $Patterns) {
          continue
        }

        $targetPath = Join-Path -Path $DestinationRoot -ChildPath $relativePath

        if ($item.PSIsContainer) {
          if (-not (Test-Path -LiteralPath $targetPath)) {
            New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
          }

          Get-ChildItem -LiteralPath $item.FullName -Force | Sort-Object Name -Descending | ForEach-Object {
            $stack.Push($_)
          }
        } else {
          $targetParent = Split-Path -Path $targetPath -Parent
          if (-not (Test-Path -LiteralPath $targetParent)) {
            New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
          }

          Copy-Item -LiteralPath $item.FullName -Destination $targetPath -Force
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

  $zipDirectory = (Resolve-Path -LiteralPath $zipDirectoryInput -ErrorAction Stop).ProviderPath
  $zipPath = Join-Path -Path $zipDirectory -ChildPath $zipFileName

  $rootFolderName = $sourceItem.Name
  $tempRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([guid]::NewGuid().ToString())
  $stageParent = Join-Path -Path $tempRoot -ChildPath 'stage'
  $stagingRoot = Join-Path -Path $stageParent -ChildPath $rootFolderName

  try {
    New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

    Copy-TreeWithExclusions -SourceRoot $sourceItem.FullName -DestinationRoot $stagingRoot -Patterns $Exclude

    if (Test-Path -LiteralPath $zipPath) {
      Remove-Item -LiteralPath $zipPath -Force
    }

    Compress-Archive -LiteralPath $stagingRoot -DestinationPath $zipPath -CompressionLevel $compressionLevel -Force

    if (-not (Test-Path -LiteralPath $zipPath)) {
      throw "Zip file was not created: $($zipPath)"
    }

    Get-Item -LiteralPath $zipPath -ErrorAction Stop
  }
  finally {
    if (Test-Path -LiteralPath $tempRoot) {
      Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

