<#
.SYNOPSIS
Ensures all ndemou.github.io/scripts are up-to-date.

.DESCRIPTION
Existing files that differ are replaced and a backup is created. 
Identical files are left unchanged. 
#>
####################################################################
#
#  START OF CONFIG
#
$DESTINATION_DIR    = 'C:\it\bin'
$BACKUPS_DIR = 'C:\it\temp'
$DOWNLOAD_URI   = 'https://ndemou.github.io/scripts'
#
#  END OF CONFIG
#
####################################################################

####################################################################
#
#  HELPER FUNCTIONS START
#
function New-EmptyTempDirectory {
<#
.SYNOPSIS
Creates a directory at "$env:TEMP\<Name>" and returns its full path.
.OUTPUTS
System.String, The full path of the created directory under $env:TEMP.
#>
    [CmdletBinding()]param([string]$Name)
    $tmpRoot = Join-Path $env:TEMP $Name
    # If $tmpRoot already exists
    if (Test-Path -Path $tmpRoot) {
        # If it's a folder: Clear it out
        if (Test-Path -Path $tmpRoot -PathType Container) {
            Get-ChildItem -Path $tmpRoot -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } 
        # If it's a file: Find a unique 6-digit alternative name
        else {
            while (Test-Path -Path $tmpRoot) {
                $suffix = Get-Random -Minimum 100000 -Maximum 1000000
                $tmpRoot = Join-Path $env:TEMP "$Name-$suffix"
            }
        }
    }
    # Create the directory
    $null = New-Item -ItemType Directory -Path $tmpRoot -Force
    return $tmpRoot
}

function Sync-FileFromWeb {
<#
.SYNOPSIS
Downloads a file and updates the local copy if they differ.

.DESCRIPTION
Downloads file to TempPath and compares it to the file in DestinationPath.

If the destination file does not exist, the downloaded file is placed into
DestinationPath.

If the destination file exists and content is identical, the temp file is
removed, and the destination file remains unchanged.

If the destination file exists and content differs, the destination file is
replaced with the downloaded file and the function returns $true. When
replacing an existing file, the function attempts to create a per-file
backup archive in BackupPath; backup failures do not prevent the update.

Warnings are emitted on download or update failures.

.OUTPUTS
System.Boolean
$true  - DestinationPath\FileName was created or replaced.
$false - No change occurred or the operation failed.
#>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$true)][string]$FileName,
    [Parameter(Mandatory=$true)][string]$BaseUri,
    [Parameter(Mandatory=$true)][string]$TempPath, # This is the Directory
    [Parameter(Mandatory=$true)][string]$DestinationPath,
    [Parameter(Mandatory=$true)][string]$BackupPath
  )

  $srcUrl = "$BaseUri/$FileName"
  $DownloadPath = Join-Path $TempPath $FileName 
  $finalPath    = Join-Path $DestinationPath $FileName
  $updated      = $false

  try {
    Invoke-WebRequest -Uri $srcUrl -OutFile $DownloadPath -UseBasicParsing -ErrorAction Stop

    $newHash = (Get-FileHash -Path $DownloadPath -Algorithm SHA256).Hash
    $existingHash = $null

    if (Test-Path $finalPath) {
      try { $existingHash = (Get-FileHash -Path $finalPath -Algorithm SHA256).Hash } catch { $existingHash = $null }
    }

    $isDifferent = $true
    if ($existingHash -ne $null -and $existingHash -eq $newHash) { $isDifferent = $false }

    if ($isDifferent) {
      if (Test-Path $finalPath) {
        $leaf    = Split-Path $finalPath -Leaf
        $dateStr = (Get-Date -Format 'yyyyMMdd.hhmmss')
        $first8  = if ($existingHash) { $existingHash.Substring(0,8) } else { 'NOHASH' }
        $perFileZip = Join-Path $BackupPath ("{0}.{1}_{2}.zip" -f $leaf, $dateStr, $first8)

        $stageDir = Join-Path $TempPath ("_bak_{0}_{1}" -f ($leaf -replace '[^\w\.-]','_'), $first8)
        
        if (-not (Test-Path $stageDir)) { $null = New-Item -ItemType Directory -Path $stageDir }
        $stageFile = Join-Path $stageDir $leaf

        try {
          Copy-Item -LiteralPath $finalPath -Destination $stageFile -Force
          Compress-Archive -Path $stageFile -DestinationPath $perFileZip -Force
          Write-Host -ForegroundColor DarkGray ("Per-file backup created: {0}" -f $perFileZip)
        } catch {
          Write-Warning ("Failed to create per-file backup for {0}: {1}" -f $leaf, $_.Exception.Message)
        }
      }

      try {
        Move-Item -LiteralPath $DownloadPath -Destination $finalPath -Force
        Write-Host -ForegroundColor White ("Updated {0}" -f $finalPath)
        $updated = $true
      } catch {
        Write-Warning ("Failed to update {0}: {1}" -f $finalPath, $_.Exception.Message)
        try { if (Test-Path $DownloadPath) { Remove-Item -LiteralPath $DownloadPath -Force } } catch {}
      }
    } else {
      Remove-Item -LiteralPath $DownloadPath -Force
      Write-Verbose ("No change for {0}" -f $FileName)
      $updated = $false
    }
    } catch {
      $statusCode = $null
      try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { $statusCode = $null }
    
      if ($statusCode -eq 404) {
        Write-Host -ForegroundColor DarkGray ("Script not on the Web, skipping: {0}" -f $FileName)
      } else {
        Write-Warning ("Failed to download {0}: {1}" -f $srcUrl, $_.Exception.Message)
      }
    
      try { if (Test-Path $DownloadPath) { Remove-Item -LiteralPath $DownloadPath -Force } } catch {}
      $updated = $false
    }

  return $updated
}
#
#  HELPER FUNCTIONS END
#
####################################################################

####################################################################
#
#  MAIN CODE
#


# Download/update scripts
# Write-Host -for DarkGray "Checking for code updates (I will backup & then overwrite local code if updates are found)"
$tmpRoot = New-EmptyTempDirectory -Name "update-all-scripts"
foreach ($file in (ls $DESTINATION_DIR\*.ps1).name) {
    # Write-Host -for DarkGray "Checking $file"
    $updated = Sync-FileFromWeb -FileName  $file `
                -BaseUri   $DOWNLOAD_URI `
                -TempPath   $tmpRoot `
                -DestinationPath   $DESTINATION_DIR `
                -BackupPath $BACKUPS_DIR
}
