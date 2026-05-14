<#
.SYNOPSIS
Ensures all health-check scripts and PS Modules are installed & up-to-date.

.DESCRIPTION
Missing files are created. Existing files that differ are replaced.
Identical files are left unchanged. If this script updates itself,
it re-invokes the updated copy. When replacing a file, backup copies
are created in the backups directory.
Will set PSGallery as Trusted.

.OUTPUTS
None.
#>
[CmdletBinding()]
param(
  [switch]$Reinstall,
  [string]$UpdateFromZip,
  [switch]$ForceRefreshReleaseMetadata,
  [Parameter(DontShow=$true)][int]$SelfRerunCount = 0,
  [Parameter(DontShow=$true)][string]$PersistReleaseMarker
)

####################################################################
#
#  START OF CONFIG
#
$SCRIPT_BIN_DIR = (Resolve-Path -LiteralPath $PSScriptRoot).Path
if ((Split-Path -Leaf $SCRIPT_BIN_DIR) -ine 'bin') {
  throw "Refusing to run. Update-GetHealthCode.ps1 must be located in and executed from a 'bin' folder. Current script location: '$SCRIPT_BIN_DIR'."
}
$ROOT_DIR = Split-Path -Parent $SCRIPT_BIN_DIR

$DEST_DIR = $SCRIPT_BIN_DIR
$BAK_DIR  = Join-Path $ROOT_DIR 'temp'
$CFG_DIR  = Join-Path $ROOT_DIR 'config'
$LOG_DIR  = Join-Path $ROOT_DIR 'log'
$script:UPDATE_LOG_PATH = Join-Path $LOG_DIR 'Update-GetHealthCode.log'
$REPO_URL = 'https://github.com/ndemou/GetComputerHealth'
$REPO_REF = 'main'
$LATEST_RELEASE_METADATA_CACHE_PATH = Join-Path $CFG_DIR 'Get-ComputerHealth-latest-release-meta.json'
$RELEASE_METADATA_CACHE_TTL_MINUTES = 60
$ZIP_CACHE_PATTERN = 'GetComputerHealth-release-*.zip'
$MANUAL_ZIP_CACHE_PATTERN = 'GetComputerHealth-MANUAL-UPDATE-*.zip'
$repoSlug = (($REPO_URL -replace '^https?://github\.com/','') -replace '\.git$','').Trim('/')
#
#  END OF CONFIG
#
####################################################################

####################################################################
#
#  HELPER FUNCTIONS START
#
function Write-UpdateEvent {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Message)

  if ([string]::IsNullOrWhiteSpace($Message)) { return }
  Write-Host $Message
  try {
    if (-not (Test-Path -LiteralPath $LOG_DIR -PathType Container)) {
      $null = New-Item -ItemType Directory -Path $LOG_DIR -Force
    }
    Add-Content -LiteralPath $script:UPDATE_LOG_PATH -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
  } catch {
    Write-Verbose ("Failed writing update event log to {0}: {1}" -f $script:UPDATE_LOG_PATH, $_.Exception.Message)
  }
}

function Ensure-PSModuleInstalled {
<#
.SYNOPSIS
Ensures a PowerShell module is installed locally; installs it if missing.
.DESCRIPTION
If installation fails due to PSGallery not being registered, registers
PSGallery, marks it Trusted, and retries the installation once.
.OUTPUTS
None.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [string]$Scope = 'AllUsers'
  )

  Write-Verbose "Checking whether PowerShell module '$Name' is already installed"
  if (Get-Module -ListAvailable -Name $Name) {
    Write-Verbose "Module '$Name' is already installed"
    return
  }

  try {
    Write-Verbose "Installing PowerShell module '$Name' with scope '$Scope'"
    Install-Module -Name $Name -Scope $Scope -Force -ErrorAction Stop
    Write-Verbose "Successfully installed PowerShell module '$Name'"
  } catch {
    if ($_.Exception.Message -like "*No repository with the Name 'PSGallery'*") {
      Write-Warning "Registering PSGallery"
      Write-Verbose "Registering default PSRepository because PSGallery was missing"
      Register-PSRepository -Default -ErrorAction Stop
      Write-Verbose "Marking PSGallery as Trusted"
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
      Write-Verbose "Retrying installation of PowerShell module '$Name'"
      Install-Module -Name $Name -Scope $Scope -Force -ErrorAction Stop
      Write-Verbose "Successfully installed PowerShell module '$Name' after registering PSGallery"
    } else {
      throw
    }
  }
}

function New-EmptyTempDirectory {
<#
.SYNOPSIS
Creates a directory at "$env:TEMP\<Name>" and returns its full path.
.OUTPUTS
System.String. The full path of the created directory under $env:TEMP.
#>
  [CmdletBinding()]
  param([string]$Name)

  $tmdDir = Join-Path $env:TEMP $Name
  Write-Verbose "Preparing temporary directory '$tmdDir'"

  if (Test-Path -Path $tmdDir) {
    if (Test-Path -Path $tmdDir -PathType Container) {
      Write-Verbose "Temporary directory already exists; clearing its contents: '$tmdDir'"
      Get-ChildItem -Path $tmdDir -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } else {
      Write-Verbose "A file already exists at '$tmdDir'; generating a unique directory name"
      while (Test-Path -Path $tmdDir) {
        $suffix = Get-Random -Minimum 100000 -Maximum 1000000
        $tmdDir = Join-Path $env:TEMP "$Name-$suffix"
      }
      Write-Verbose "Using alternate temporary directory '$tmdDir'"
    }
  }

  $null = New-Item -ItemType Directory -Path $tmdDir -Force
  Write-Verbose "Temporary directory ready: '$tmdDir'"
  return $tmdDir
}

function Convert-GitHubRepoUrlToSlug {
<#
.SYNOPSIS
Converts a GitHub repo URL into "owner/repo" format.
#>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RepoUrl)

  Write-Verbose "Converting repository URL to slug: '$RepoUrl'"
  $slug = ($RepoUrl -replace '^https?://github\.com/','') -replace '\.git$',''
  $slug = $slug.Trim('/')
  if ([string]::IsNullOrWhiteSpace($slug)) {
    throw "Invalid GitHub repository URL: $RepoUrl"
  }
  Write-Verbose "Repository slug resolved to '$slug'"
  return $slug
}

function Convert-GetComputerHealthReleaseToMarker {
<#
.SYNOPSIS
Converts release metadata to a stable marker string.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RepositoryUrl,
    [Parameter(Mandatory)]$Release
  )

  $slug = Convert-GitHubRepoUrlToSlug -RepoUrl $RepositoryUrl
  $tag = [string]$Release.tag_name
  if ([string]::IsNullOrWhiteSpace($tag)) { $tag = 'untagged' }
  $id = [string]$Release.id
  if ([string]::IsNullOrWhiteSpace($id)) { $id = 'noid' }
  return ("{0}|{1}|{2}" -f $slug, $tag, $id)
}

function Get-GetComputerHealthVersionFromMarker {
<#
.SYNOPSIS
Extracts a comparable release version token from an installed/latest marker.
.DESCRIPTION
Returns values like 'v3.9.0' when the marker embeds a semantic-version tag,
or $null when no version-like token can be identified.
#>
  [CmdletBinding()]
  param([AllowNull()][string]$Marker)

  if ([string]::IsNullOrWhiteSpace($Marker)) {
    return $null
  }

  if ($Marker -match '(?i)\bv\d+\.\d+\.\d+\b') {
    return $matches[0].ToLowerInvariant()
  }

  return $null
}

function Test-GetComputerHealthMarkerEquivalent {
<#
.SYNOPSIS
Determines whether two release markers should be treated as the same installed version.
.DESCRIPTION
Markers are considered equivalent if they match exactly, or if both embed the
same semantic-version token (for example GitHub marker vs manual-zip marker).
#>
  [CmdletBinding()]
  param(
    [AllowNull()][string]$LeftMarker,
    [AllowNull()][string]$RightMarker
  )

  if ([string]::IsNullOrWhiteSpace($LeftMarker) -or [string]::IsNullOrWhiteSpace($RightMarker)) {
    return $false
  }

  if ($LeftMarker -eq $RightMarker) {
    return $true
  }

  $leftVersion = Get-GetComputerHealthVersionFromMarker -Marker $LeftMarker
  $rightVersion = Get-GetComputerHealthVersionFromMarker -Marker $RightMarker

  if ($leftVersion -and $rightVersion -and ($leftVersion -ieq $rightVersion)) {
    return $true
  }

  return $false
}

function Get-GetComputerHealthLatestRelease {
<#.SYNOPSIS
Gets latest GitHub release metadata for the configured repository.
Uses a local metadata cache to avoid querying GitHub too frequently.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RepositoryUrl,
    [string]$CachePath,
    [int]$CacheTtlMinutes = 60,
    [switch]$ForceRefresh
  )

  if ((-not $ForceRefresh) -and $CachePath -and (Test-Path -LiteralPath $CachePath -PathType Leaf)) {
    try {
      Write-Verbose "Reading cached data from $CachePath"
      $cachedRaw = Get-Content -LiteralPath $CachePath -Raw -ErrorAction Stop
      if ([string]::IsNullOrWhiteSpace($cachedRaw)) {
        Write-Verbose "Cached release metadata file '$CachePath' is empty"
        return $null
      }

      $cached = $cachedRaw | ConvertFrom-Json -ErrorAction Stop
      $fetchedAtProp = $cached.PSObject.Properties['fetchedAt']
      $releaseProp = $cached.PSObject.Properties['release']
      if ($fetchedAtProp -and $releaseProp -and $fetchedAtProp.Value -and $releaseProp.Value) {
        $ageMinutes = ((Get-Date) - ([datetime]$fetchedAtProp.Value)).TotalMinutes
        if ($ageMinutes -lt $CacheTtlMinutes) {
          Write-Verbose ("Using cached release metadata from '{0}' (age {1:N1} minutes, TTL {2} minutes)" -f $CachePath, $ageMinutes, $CacheTtlMinutes)
          return $releaseProp.Value
        }
        Write-Verbose ("Cached release metadata is stale (age {0:N1} minutes >= TTL {1} minutes)" -f $ageMinutes, $CacheTtlMinutes)
      }
    } catch {
      Write-Warning ("Failed to read cached release metadata from {0}: {1}" -f $CachePath, $_.Exception.Message)
    }
  } elseif ($ForceRefresh) {
    Write-Verbose "Force refresh requested; bypassing cached release metadata"
  }

  Write-Verbose "Querying latest release metadata for '$RepositoryUrl' from GitHub"
  $slug = Convert-GitHubRepoUrlToSlug -RepoUrl $RepositoryUrl
  $api = "https://api.github.com/repos/$slug/releases/latest"
  $headers = @{
    'User-Agent' = 'PowerShell'
    'Accept'     = 'application/vnd.github+json'
  }
  $release = Invoke-RestMethod -Method Get -Uri $api -Headers $headers -ErrorAction Stop
  Write-Verbose ("Latest release metadata retrieved: tag='{0}', id='{1}'" -f $release.tag_name, $release.id)

  if ($CachePath) {
    try {
      $cacheDir = Split-Path -Parent $CachePath
      if ($cacheDir -and (-not (Test-Path -LiteralPath $cacheDir))) {
        $null = New-Item -ItemType Directory -Path $cacheDir -Force
      }

      $cachePayload = @{
        fetchedAt = (Get-Date).ToString('o')
        release   = $release
      }

      if (Test-Path -LiteralPath $CachePath -PathType Leaf) {
        try {
          Write-Verbose "Reading installedReleaseMarker from $CachePath"
          $existingRaw = Get-Content -LiteralPath $CachePath -Raw -ErrorAction Stop
          $existingCache = $existingRaw | ConvertFrom-Json -ErrorAction Stop
          $existingMarkerProp = $existingCache.PSObject.Properties['installedReleaseMarker']
          if ($existingMarkerProp -and $existingMarkerProp.Value) {
            $cachePayload['installedReleaseMarker'] = [string]$existingMarkerProp.Value
          }
        } catch {
          Write-Warning ("Failed to preserve installed release marker from {0}: {1}" -f $CachePath, $_.Exception.Message)
        }
      }

      $cachePayload | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $CachePath -Encoding UTF8 -Force

      Write-Verbose "Updated release metadata cache at '$CachePath'"
    } catch {
      Write-Warning ("Failed to write release metadata cache to {0}: {1}" -f $CachePath, $_.Exception.Message)
    }
  }

  return $release
}

function Get-GetComputerHealthInstalledReleaseMarker {
<#
.SYNOPSIS
Reads the installed-release marker from the shared metadata cache file.
#>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$CachePath)

  try {
    if (-not (Test-Path -LiteralPath $CachePath -PathType Leaf)) {
      return $null
    }

    Write-Verbose "Reading release marker from $CachePath"
    $cachedRaw = Get-Content -LiteralPath $CachePath -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($cachedRaw)) {
      return $null
    }

    $cached = $cachedRaw | ConvertFrom-Json -ErrorAction Stop
    $markerProp = $cached.PSObject.Properties['installedReleaseMarker']
    if (-not $markerProp) {
      return $null
    }

    $marker = [string]$markerProp.Value
    if ([string]::IsNullOrWhiteSpace($marker)) {
      return $null
    }

    return $marker.Trim()
  } catch {
    Write-Warning ("Failed to read installed release marker from {0}: {1}" -f $CachePath, $_.Exception.Message)
    return $null
  }
}

function Set-GetComputerHealthInstalledReleaseMarker {
<#
.SYNOPSIS
Writes the installed-release marker into the shared metadata cache file.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CachePath,
    [Parameter(Mandatory)][string]$Marker,
    [string]$FetchedAt
  )

  try {
    $cacheDir = Split-Path -Parent $CachePath
    if ($cacheDir -and (-not (Test-Path -LiteralPath $cacheDir))) {
      $null = New-Item -ItemType Directory -Path $cacheDir -Force
    }

    $cachePayload = @{}
    if (Test-Path -LiteralPath $CachePath -PathType Leaf) {
      try {
        $cachedRaw = Get-Content -LiteralPath $CachePath -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($cachedRaw)) {
          $cached = $cachedRaw | ConvertFrom-Json -ErrorAction Stop
          $fetchedAtProp = $cached.PSObject.Properties['fetchedAt']
          $releaseProp = $cached.PSObject.Properties['release']
          if ($fetchedAtProp -and $fetchedAtProp.Value) { $cachePayload['fetchedAt'] = $fetchedAtProp.Value }
          if ($releaseProp -and $releaseProp.Value) { $cachePayload['release'] = $releaseProp.Value }
        }
      } catch {
        Write-Warning ("Failed to parse existing metadata cache before writing marker to {0}: {1}" -f $CachePath, $_.Exception.Message)
      }
    }

    if (-not [string]::IsNullOrWhiteSpace($FetchedAt)) {
      $cachePayload['fetchedAt'] = $FetchedAt
    }
    $cachePayload['installedReleaseMarker'] = $Marker

    $cachePayload | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $CachePath -Encoding UTF8 -Force
    Write-Verbose "Updated installed release marker in metadata cache '$CachePath'"
  } catch {
    Write-Warning ("Failed writing installed release marker to {0}: {1}" -f $CachePath, $_.Exception.Message)
  }
}

function Prepare-ManualUpdateZip {
<#
.SYNOPSIS
Prepares metadata for a manually provided update zip and copies it to temp cache.
.OUTPUTS
Hashtable with keys: SourceFullPath, ZipLastWriteTimeIso, CachedZipPath, ZipSha256, ManualMarker.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$CacheDir
  )

  if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
    throw "Zip file not found: $ZipPath"
  }

  if (-not (Test-Path -LiteralPath $CacheDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $CacheDir -Force
  }

  $zipItem = Get-Item -LiteralPath $ZipPath -ErrorAction Stop
  $sourceFullPath = $zipItem.FullName
  $zipLastWrite = [datetime]$zipItem.LastWriteTime
  $zipLastWriteIso = $zipLastWrite.ToString('o')
  $zipHash = (Get-FileHash -LiteralPath $sourceFullPath -Algorithm SHA256 -ErrorAction Stop).Hash
  $zipLastWriteToken = $zipLastWrite.ToString('yyyyMMdd-HHmmss')
  $cachedZipPath = Join-Path $CacheDir ("GetComputerHealth-MANUAL-UPDATE-{0}.zip" -f $zipLastWriteToken)
  $zipTag = [System.IO.Path]::GetFileNameWithoutExtension($zipItem.Name)
  if ([string]::IsNullOrWhiteSpace($zipTag)) { $zipTag = 'manual' }
  $manualMarker = ("manual-zip|{0}|{1}" -f $zipTag, $zipHash)

  $samePath = $false
  if (Test-Path -LiteralPath $cachedZipPath -PathType Leaf) {
    try {
      $existingFullPath = (Get-Item -LiteralPath $cachedZipPath -ErrorAction Stop).FullName
      $samePath = ($existingFullPath.TrimEnd('\') -ieq $sourceFullPath.TrimEnd('\'))
    } catch {
      $samePath = ($cachedZipPath.TrimEnd('\') -ieq $sourceFullPath.TrimEnd('\'))
    }
  } else {
    $samePath = ($cachedZipPath.TrimEnd('\') -ieq $sourceFullPath.TrimEnd('\'))
  }

  if ($samePath) {
    Write-Verbose "Manual update zip already in cache path '$cachedZipPath'; skipping copy"
  } else {
    Write-Verbose "Copying manual update zip to cache '$cachedZipPath'"
    Copy-Item -LiteralPath $sourceFullPath -Destination $cachedZipPath -Force -ErrorAction Stop
  }

  return @{
    SourceFullPath      = $sourceFullPath
    ZipLastWriteTimeIso = $zipLastWriteIso
    CachedZipPath       = $cachedZipPath
    ZipSha256           = $zipHash
    ManualMarker        = $manualMarker
  }
}

function Expand-GetComputerHealthLatestRelease {
<#.SYNOPSIS
Downloads and extracts the latest release zip into a temporary folder.
If a cached zip is corrupt or incomplete, it is deleted and downloaded again once.
.OUTPUTS
System.Collections.Hashtable with keys RootPath and ZipPath.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RepositoryUrl,
    [Parameter(Mandatory)][string]$TempPath,
    [Parameter(Mandatory)][string]$ZipCacheDir,
    [Parameter(Mandatory)]$Release,
    [switch]$ForceDownload
  )

  Write-Verbose "Preparing latest release from GitHub"
  $release = $Release
  if (-not $release.zipball_url) {
    throw "Latest release does not include zipball_url."
  }

  $zipNameSafeTag = ([string]$release.tag_name -replace '[^a-zA-Z0-9._-]', '_').Trim('_')
  if ([string]::IsNullOrWhiteSpace($zipNameSafeTag)) { $zipNameSafeTag = 'untagged' }

  $zipPath = Join-Path $ZipCacheDir ("GetComputerHealth-release-{0}-{1}.zip" -f $zipNameSafeTag, $release.id)
  $extractPath = Join-Path $TempPath 'latest-release'

  Write-Verbose "Release zip will be cached at '$zipPath'"
  Write-Verbose "Release zip will be extracted to '$extractPath'"

  if (-not (Test-Path -LiteralPath $extractPath -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $extractPath -Force
  }

  $headers = @{
    'User-Agent' = 'PowerShell'
    'Accept'     = 'application/vnd.github+json'
  }

  function Invoke-DownloadReleaseZip {
    param(
      [Parameter(Mandatory)][string]$Uri,
      [Parameter(Mandatory)][string]$OutFile,
      [Parameter(Mandatory)][hashtable]$Headers
    )

    if (Test-Path -LiteralPath $OutFile -PathType Leaf) {
      Write-Verbose "Deleting existing zip before download: '$OutFile'"
      Remove-Item -LiteralPath $OutFile -Force -ErrorAction Stop
    }

    Write-Verbose "Downloading release zip from GitHub"
    Write-UpdateEvent "Downloading release zip from GitHub"
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $Headers -UseBasicParsing -ErrorAction Stop
  }

  function Invoke-ExpandReleaseZip {
    param(
      [Parameter(Mandatory)][string]$LiteralZipPath,
      [Parameter(Mandatory)][string]$DestinationPath
    )

    if (Test-Path -LiteralPath $DestinationPath -PathType Container) {
      Get-ChildItem -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } else {
      $null = New-Item -ItemType Directory -Path $DestinationPath -Force
    }

    Write-Verbose "Expanding release zip '$LiteralZipPath'"
    Write-UpdateEvent "Expanding release zip '$LiteralZipPath'"
    Expand-Archive -LiteralPath $LiteralZipPath -DestinationPath $DestinationPath -Force -ErrorAction Stop
  }

  if ($ForceDownload -or (-not (Test-Path -LiteralPath $zipPath -PathType Leaf))) {
    Invoke-DownloadReleaseZip -Uri $release.zipball_url -OutFile $zipPath -Headers $headers
  } else {
    Write-Verbose "Reusing cached release zip '$zipPath'"
  }

  $expanded = $false
  $firstExpandError = $null

  try {
    Invoke-ExpandReleaseZip -LiteralZipPath $zipPath -DestinationPath $extractPath
    $expanded = $true
  } catch {
    $firstExpandError = $_
    Write-Warning ("Cached or downloaded zip appears invalid: {0}" -f $_.Exception.Message)

    try {
      if (Test-Path -LiteralPath $zipPath -PathType Leaf) {
        Write-Warning "Deleting bad cached zip '$zipPath' and retrying download once"
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop
      }
    } catch {
      Write-Warning ("Failed to delete bad zip '{0}': {1}" -f $zipPath, $_.Exception.Message)
    }

    Invoke-DownloadReleaseZip -Uri $release.zipball_url -OutFile $zipPath -Headers $headers
    Invoke-ExpandReleaseZip -LiteralZipPath $zipPath -DestinationPath $extractPath
    $expanded = $true
  }

  if (-not $expanded) {
    throw $firstExpandError
  }

  $root = Get-ChildItem -LiteralPath $extractPath -Directory | Select-Object -First 1
  if (-not $root) {
    throw "Release zip extracted but no top-level folder was found."
  }

  Write-Verbose "Extracted release root is '$($root.FullName)'"
  return @{
    RootPath = $root.FullName
    ZipPath  = $zipPath
  }
}

function Expand-ReleaseFromZipFile {
<#.SYNOPSIS
Extracts a provided release zip into a temporary folder and returns extracted root path.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ZipPath,
    [Parameter(Mandatory)][string]$TempPath
  )

  Write-Verbose "Preparing release from provided zip '$ZipPath'"
  if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
    throw "Zip file not found: $ZipPath"
  }

  $extractPath = Join-Path $TempPath 'provided-release'
  Write-Verbose "Provided zip will be extracted to '$extractPath'"

  if (-not (Test-Path $extractPath)) {
    $null = New-Item -ItemType Directory -Path $extractPath
  }

  Write-Verbose "Expanding provided zip '$ZipPath'"
  Write-UpdateEvent "Expanding release zip '$ZipPath'"
  Expand-Archive -LiteralPath $ZipPath -DestinationPath $extractPath -Force

  $root = Get-ChildItem -LiteralPath $extractPath -Directory | Select-Object -First 1
  if (-not $root) {
    throw "Provided zip extracted but no top-level folder was found."
  }

  Write-Verbose "Extracted provided release root is '$($root.FullName)'"
  return @{
    RootPath = $root.FullName
    ZipPath  = $ZipPath
  }
}

function Keep-OnlyLatestReleaseZips {
<#.SYNOPSIS
Keeps only the latest N cached release zips.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CacheDir,
    [Parameter(Mandatory)][string]$Pattern,
    [int]$KeepCount = 2
  )

  try {
    Write-Verbose "Pruning cached release zips in '$CacheDir' using pattern '$Pattern'; keeping newest $KeepCount"
    $cachedZips = Get-ChildItem -LiteralPath $CacheDir -File -Filter $Pattern -ErrorAction Stop |
      Sort-Object -Property LastWriteTime -Descending

    if ($null -eq $cachedZips) {
      $cachedZips = @()
    }

    $cachedZipCount = @($cachedZips).Length
    Write-Verbose ("Found {0} cached release zip(s)" -f $cachedZipCount)

    if (@($cachedZips).Count -gt $KeepCount) {
      $toDelete = @($cachedZips | Select-Object -Skip $KeepCount)
      foreach ($item in $toDelete) {
        Write-Verbose "Deleting old cached release zip '$($item.FullName)'"
      }
      if (@($toDelete).Length -gt 0) {
        $toDelete | Remove-Item -Force -ErrorAction Stop
      }
    } else {
      Write-Verbose "No cached release zips need pruning"
    }
  } catch {
    Write-Warning ("Failed pruning cached release zips in {0}: {1}" -f $CacheDir, $_.Exception.Message)
  }
}

function Replace-FileFromSource {
<#
.SYNOPSIS
Copies a file from the extracted release tree and updates the local copy if they differ.

.DESCRIPTION
Compares SourcePath\<relative FileName> to DestinationPath\<relative FileName>.

If the destination file does not exist, the downloaded file is placed into
DestinationPath.

If the destination file exists and content is identical, the destination file
remains unchanged.

If the destination file exists and content differs, the destination file is
replaced with the source file and the function returns $true. When replacing
an existing file, the function attempts to copy the prior file to BackupPath
with a timestamped `.bak` filename; backup failures do not prevent the update.

Warnings are emitted on copy or update failures.

.OUTPUTS
System.Boolean
$true  - DestinationPath\FileName was created or replaced.
$false - No change occurred or the operation failed.
#>
  [CmdletBinding()]
  param (
    [Parameter(Mandatory=$true)][string]$FileName,
    [Parameter(Mandatory=$true)][string]$SourcePath,
    [Parameter(Mandatory=$true)][string]$DestinationPath,
    [Parameter(Mandatory=$true)][string]$BackupPath
  )

  $releaseFilePath = Join-Path $SourcePath $FileName
  $finalPath       = Join-Path $DestinationPath $FileName
  $finalDir        = Split-Path -Path $finalPath -Parent
  $updated         = $false

  try {
    if (-not (Test-Path -LiteralPath $releaseFilePath -PathType Leaf)) {
      throw "Expected file not found in release zip: $FileName"
    }

    $isDifferent = $true

    if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
      $sourceSize = (Get-Item -LiteralPath $releaseFilePath -ErrorAction Stop).Length
      $destSize = (Get-Item -LiteralPath $finalPath -ErrorAction Stop).Length

      if ($sourceSize -eq $destSize) {
        $newHash = (Get-FileHash -Path $releaseFilePath -Algorithm SHA256).Hash
        $existingHash = $null

        try {
          $existingHash = (Get-FileHash -Path $finalPath -Algorithm SHA256).Hash
        } catch {
          Write-Warning "Failed computing existing hash for '$finalPath'; proceeding as different"
          $existingHash = $null
        }

        if ($existingHash -ne $null -and $existingHash -eq $newHash) {
          $isDifferent = $false
        }
      }
    }

    if ($isDifferent) {
      if (Test-Path -LiteralPath $finalPath -PathType Leaf) {
        $leaf       = Split-Path $finalPath -Leaf
        $dateStr    = Get-Date -Format 'yyyyMMdd.hhmmss'
        $backupFile = Join-Path $BackupPath ("{0}.{1}.bak" -f $leaf, $dateStr)

        try {
          Copy-Item -LiteralPath $finalPath -Destination $backupFile -Force -ErrorAction Stop
          Write-Verbose "Per-file backup created: '$backupFile'"
        } catch {
          Write-Warning ("Failed to create per-file backup for {0}: {1}" -f $leaf, $_.Exception.Message)
        }
      }

      try {
        if (-not (Test-Path -LiteralPath $finalDir -PathType Container)) {
          $null = New-Item -ItemType Directory -Path $finalDir -Force
        }
        Copy-Item -LiteralPath $releaseFilePath -Destination $finalPath -Force -ErrorAction Stop
        Write-Verbose "Updated '$finalPath'"
        $updated = $true
      } catch {
        Write-Warning ("Failed to update {0}: {1}" -f $finalPath, $_.Exception.Message)
      }
    } else {
      Write-Verbose "No content change detected for '$FileName'"
      $updated = $false
    }
  } catch {
    Write-Warning ("Failed to stage {0} from extracted release: {1}" -f $FileName, $_.Exception.Message)
    $updated = $false
  }

  return $updated
}

function Install-ReleaseFilesFromSource {
<#
.SYNOPSIS
Installs all files from an extracted release tree into the destination tree.

.DESCRIPTION
Walks SourcePath recursively, computes each file path relative to SourcePath, and
uses Replace-FileFromSource so files are only copied when missing or changed.
Files listed in ExcludeRelativePaths are skipped.

.OUTPUTS
System.Boolean
$true  - At least one file was created or replaced.
$false - No files changed.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$SourcePath,
    [Parameter(Mandatory=$true)][string]$DestinationPath,
    [Parameter(Mandatory=$true)][string]$BackupPath,
    [string[]]$ExcludeRelativePaths = @()
  )

  $changed = $false
  $sourceRootFullPath = (Resolve-Path -LiteralPath $SourcePath).Path
  $sourceRootWithSeparator = $sourceRootFullPath.TrimEnd('\','/') + '\'
  $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($relativePath in $ExcludeRelativePaths) {
    if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
      $null = $excluded.Add($relativePath.Replace('/','\'))
    }
  }

  Get-ChildItem -LiteralPath $sourceRootFullPath -Recurse -File | ForEach-Object {
    $fileFullPath = $_.FullName.Replace('/','\')
    if ($fileFullPath.StartsWith($sourceRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
      $relativePath = $fileFullPath.Substring($sourceRootWithSeparator.Length)
    } else {
      throw "Release file '$fileFullPath' is not under source root '$sourceRootFullPath'"
    }
    if ($excluded.Contains($relativePath)) {
      Write-Verbose "Skipping excluded release file '$relativePath'"
      return
    }

    if (Replace-FileFromSource -FileName $relativePath -SourcePath $sourceRootFullPath -DestinationPath $DestinationPath -BackupPath $BackupPath) {
      $changed = $true
    }
  }

  return $changed
}
#
#  HELPER FUNCTIONS END
#
####################################################################

####################################################################
#
#  MAIN CODE
#
$passNumber = $SelfRerunCount + 1
$passLabel = "[pass $passNumber/2]"

Write-Verbose "$passLabel Starting Update-GetHealthCode"
Write-Verbose "$passLabel Parameters: Reinstall=$Reinstall UpdateFromZip='$UpdateFromZip' ForceRefreshReleaseMetadata=$ForceRefreshReleaseMetadata SelfRerunCount=$SelfRerunCount PersistReleaseMarker='$PersistReleaseMarker'"
Write-UpdateEvent "$passLabel Parameters: Reinstall=$Reinstall UpdateFromZip='$UpdateFromZip' ForceRefreshReleaseMetadata=$ForceRefreshReleaseMetadata SelfRerunCount=$SelfRerunCount PersistReleaseMarker='$PersistReleaseMarker'"
Write-Verbose "Configuration:"
Write-Verbose "  DEST_DIR                    : $DEST_DIR"
Write-Verbose "  BAK_DIR                     : $BAK_DIR"
Write-Verbose "  CFG_DIR                     : $CFG_DIR"
Write-Verbose "  REPO_URL                    : $REPO_URL"
Write-Verbose "  REPO_REF                    : $REPO_REF"
Write-Verbose "  LATEST_RELEASE_METADATA_CACHE_PATH : $LATEST_RELEASE_METADATA_CACHE_PATH"
Write-Verbose "  RELEASE_METADATA_CACHE_TTL_MINUTES : $RELEASE_METADATA_CACHE_TTL_MINUTES"
Write-Verbose "  ZIP_CACHE_PATTERN           : $ZIP_CACHE_PATTERN"
Write-Verbose "  MANUAL_ZIP_CACHE_PATTERN    : $MANUAL_ZIP_CACHE_PATTERN"
Write-Verbose "  repoSlug                    : $repoSlug"

if (-not (Test-Path $DEST_DIR)) {
  Write-Verbose "Creating destination directory '$DEST_DIR'"
  New-Item -ItemType Directory -Path $DEST_DIR | Out-Null
} else {
  Write-Verbose "Destination directory already exists: '$DEST_DIR'"
}

if (-not (Test-Path $BAK_DIR)) {
  Write-Verbose "Creating backup/cache directory '$BAK_DIR'"
  New-Item -ItemType Directory -Path $BAK_DIR | Out-Null
} else {
  Write-Verbose "Backup/cache directory already exists: '$BAK_DIR'"
}

if (-not (Test-Path $CFG_DIR)) {
  Write-Verbose "Creating configuration directory '$CFG_DIR'"
  New-Item -ItemType Directory -Path $CFG_DIR | Out-Null
} else {
  Write-Verbose "Configuration directory already exists: '$CFG_DIR'"
}

Ensure-PSModuleInstalled -Name ImportExcel

$p = Join-Path $CFG_DIR 'Get-ComputerHealth.sigs-to-suppress.txt'
if (-not (Test-Path $p)) {
  Write-Verbose "Creating default suppressions file '$p'"
  $null = mkdir $CFG_DIR -Force -ErrorAction Ignore
  "# $($env:COMPUTERNAME)" | Out-File $p -Encoding UTF8
} else {
  Write-Verbose "Suppressions file already exists: '$p'"
}

$latestRelease = $null
$latestReleaseMarker = $null
$manualUpdateMarker = $null
$manualUpdateFetchedAt = $null
if (-not $UpdateFromZip) {
  Write-Verbose "$passLabel Resolving latest release metadata (cache TTL $RELEASE_METADATA_CACHE_TTL_MINUTES minutes)"
  try {
    $latestRelease = Get-GetComputerHealthLatestRelease -RepositoryUrl $REPO_URL -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -CacheTtlMinutes $RELEASE_METADATA_CACHE_TTL_MINUTES -ForceRefresh:$ForceRefreshReleaseMetadata
    $latestReleaseMarker = Convert-GetComputerHealthReleaseToMarker -RepositoryUrl $REPO_URL -Release $latestRelease
    Write-Verbose "$passLabel Latest release marker is '$latestReleaseMarker'"
    Write-UpdateEvent "$passLabel Latest release marker is '$latestReleaseMarker'"
  } catch {
    Write-Warning ("Could not query latest release metadata from {0}: {1}" -f $REPO_URL, $_.Exception.Message)
  }
} else {
  Write-Verbose "-UpdateFromZip specified; skipping latest release marker query"
  $manualUpdateZip = Prepare-ManualUpdateZip -ZipPath $UpdateFromZip -CacheDir $BAK_DIR
  $manualUpdateMarker = [string]$manualUpdateZip.ManualMarker
  $manualUpdateFetchedAt = [string]$manualUpdateZip.ZipLastWriteTimeIso
  Write-Verbose "Manual update marker is '$manualUpdateMarker'"
  Write-Verbose "Manual update fetchedAt is '$manualUpdateFetchedAt'"
}

if ($latestReleaseMarker) {
  $storedReleaseMarker = Get-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH

  if ($storedReleaseMarker) {
    Write-Verbose "Stored installed release marker is '$storedReleaseMarker'"
    Write-UpdateEvent "Stored installed release marker is '$storedReleaseMarker'"
  } else {
    Write-Verbose "No stored installed release marker is available yet"
  }

  if ((-not $Reinstall) -and $storedReleaseMarker -and (Test-GetComputerHealthMarkerEquivalent -LeftMarker $storedReleaseMarker -RightMarker $latestReleaseMarker)) {
    $storedVersion = Get-GetComputerHealthVersionFromMarker -Marker $storedReleaseMarker
    $latestVersion = Get-GetComputerHealthVersionFromMarker -Marker $latestReleaseMarker
    if (($storedReleaseMarker -ne $latestReleaseMarker) -and $storedVersion -and $latestVersion -and ($storedVersion -ieq $latestVersion)) {
      Write-Verbose "Installed marker came from a different source but matches latest version '$latestVersion'; skipping update download"
      Write-UpdateEvent "Installed marker came from a different source but matches latest version '$latestVersion'; skipping update download"
    } else {
      Write-Verbose "Latest release already downloaded and -Reinstall was not specified; skipping update download"
      Write-UpdateEvent "Latest release already downloaded and -Reinstall was not specified; skipping update download"
    }
    return
  }

  if ($Reinstall -and $storedReleaseMarker -and (Test-GetComputerHealthMarkerEquivalent -LeftMarker $storedReleaseMarker -RightMarker $latestReleaseMarker)) {
    Write-Verbose "-Reinstall was specified; re-downloading current latest release"
  }
} elseif ($manualUpdateMarker) {
  $storedReleaseMarker = Get-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH

  if ($storedReleaseMarker) {
    Write-Verbose "Stored installed release marker is '$storedReleaseMarker'"
    Write-UpdateEvent "Stored installed release marker is '$storedReleaseMarker'"
  } else {
    Write-Verbose "No stored installed release marker is available yet"
  }

  if ((-not $Reinstall) -and $storedReleaseMarker -and (Test-GetComputerHealthMarkerEquivalent -LeftMarker $storedReleaseMarker -RightMarker $manualUpdateMarker)) {
    $storedVersion = Get-GetComputerHealthVersionFromMarker -Marker $storedReleaseMarker
    $manualVersion = Get-GetComputerHealthVersionFromMarker -Marker $manualUpdateMarker
    if (($storedReleaseMarker -ne $manualUpdateMarker) -and $storedVersion -and $manualVersion -and ($storedVersion -ieq $manualVersion)) {
      Write-Verbose "Provided zip matches already installed version '$manualVersion' even though the source marker differs; skipping update"
      Write-UpdateEvent "Provided zip matches already installed version '$manualVersion' even though the source marker differs; skipping update"
    } else {
      Write-Verbose "Provided zip marker already installed and -Reinstall was not specified; skipping update"
      Write-UpdateEvent "Provided zip marker already installed and -Reinstall was not specified; skipping update"
    }
    return
  }
} else {
  Write-Verbose "$passLabel No latest release marker is available"
}

Write-Verbose "$passLabel Checking for code updates; local files will be backed up before replacement if needed"
$tmdDir = New-EmptyTempDirectory -Name "Update-GetHealthCode"
$releaseRoot = $null
$preparedZipPath = $null

try {
  if ($UpdateFromZip) {
    Write-Verbose "$passLabel Updating from provided zip '$UpdateFromZip'"
    Write-UpdateEvent "$passLabel Updating from provided zip '$UpdateFromZip'"
    $preparedRelease = Expand-ReleaseFromZipFile -ZipPath $UpdateFromZip -TempPath $tmdDir
    Keep-OnlyLatestReleaseZips -CacheDir $BAK_DIR -Pattern $MANUAL_ZIP_CACHE_PATTERN -KeepCount 4
  } else {
    Write-Verbose "$passLabel Updating from latest GitHub release"
    Write-UpdateEvent "$passLabel Updating from latest GitHub release"
    if (-not $latestRelease) {
      $latestRelease = Get-GetComputerHealthLatestRelease -RepositoryUrl $REPO_URL -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -CacheTtlMinutes $RELEASE_METADATA_CACHE_TTL_MINUTES -ForceRefresh:$ForceRefreshReleaseMetadata
    }
    $preparedRelease = Expand-GetComputerHealthLatestRelease -RepositoryUrl $REPO_URL -TempPath $tmdDir -ZipCacheDir $BAK_DIR -Release $latestRelease -ForceDownload:$Reinstall
    Keep-OnlyLatestReleaseZips -CacheDir $BAK_DIR -Pattern $ZIP_CACHE_PATTERN -KeepCount 4
  }
  $releaseRoot = $preparedRelease.RootPath
  $preparedZipPath = $preparedRelease.ZipPath
  Write-Verbose "$passLabel Release root resolved to '$releaseRoot'"
  Write-Verbose "$passLabel Prepared zip path is '$preparedZipPath'"
} catch {
  throw "Unable to prepare release zip: $($_.Exception.Message)"
}

$appliedUpdate = $false
$updated = Replace-FileFromSource -FileName 'Update-GetHealthCode.ps1' -SourcePath $releaseRoot -DestinationPath $DEST_DIR -BackupPath $BAK_DIR
if ($updated) { $appliedUpdate = $true }

if ($updated) {
  Write-Verbose "$passLabel This script updated itself"
  $zipName = if ($preparedZipPath) { Split-Path -Path $preparedZipPath -Leaf } else { '<unknown zip>' }
  Write-UpdateEvent "Applied GetComputerHealth update from zip '$zipName'"

  if ($latestReleaseMarker) {
    Write-Verbose "$passLabel Persisting installed release marker before self-rerun"
    Set-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -Marker $latestReleaseMarker
  } elseif ($manualUpdateMarker) {
    Write-Verbose "$passLabel Persisting manual update marker before self-rerun"
    Set-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -Marker $manualUpdateMarker -FetchedAt $manualUpdateFetchedAt
  }

  if ($SelfRerunCount -ge 1) {
    Write-Verbose "$passLabel Self-rerun already performed once; skipping additional rerun"
    return
  }

  $rerunPath = Join-Path $DEST_DIR 'Update-GetHealthCode.ps1'
  $rerunParameters = @{} + $PSBoundParameters
  $rerunParameters['SelfRerunCount'] = $SelfRerunCount + 1
  if ($preparedZipPath) {
    $rerunParameters['UpdateFromZip'] = $preparedZipPath
  }
  if ($latestReleaseMarker) {
    $rerunParameters['PersistReleaseMarker'] = $latestReleaseMarker
  }

  Write-Verbose "$passLabel Rerunning updated copy '$rerunPath' with one-time self-rerun guard"
  & $rerunPath @rerunParameters
  return
}

if (Install-ReleaseFilesFromSource -SourcePath $releaseRoot -DestinationPath $DEST_DIR -BackupPath $BAK_DIR -ExcludeRelativePaths @('Update-GetHealthCode.ps1')) { $appliedUpdate = $true }

if ($appliedUpdate) {
  $zipName = if ($preparedZipPath) { Split-Path -Path $preparedZipPath -Leaf } else { '<unknown zip>' }
  Write-UpdateEvent "Applied GetComputerHealth update from zip '$zipName'"
}

if ($PersistReleaseMarker) {
  Set-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -Marker $PersistReleaseMarker
} elseif ($latestReleaseMarker) {
  Set-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -Marker $latestReleaseMarker
} elseif ($manualUpdateMarker) {
  Set-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -Marker $manualUpdateMarker -FetchedAt $manualUpdateFetchedAt
}

if ((Get-Date) -le [datetime]'2026-04-30') {
  Write-Verbose "Executing cleanups of obsolete files"

  $obsoleteFiles = @(
    (Join-Path $CFG_DIR  'Get-ComputerHealth-latest-release.dat')
    (Join-Path $DEST_DIR 'lib-helpers-for-health-tests.ps1')
    (Join-Path $DEST_DIR 'lib-health-tests.ps1')
    (Join-Path $DEST_DIR 'ht-DC-PDC.ps1')
    (Join-Path $DEST_DIR 'ht-DNS.ps1')
    (Join-Path $DEST_DIR 'ht-DHCP.ps1')
    (Join-Path $DEST_DIR 'ht-syscfg-featdisc.ps1')
    (Join-Path $DEST_DIR 'ht-srvc-exe-resolve.ps1')
    (Join-Path $DEST_DIR 'ht-file-dir-anlz.ps1')
    (Join-Path $DEST_DIR 'ht-schtasks-master.ps1')
    (Join-Path $DEST_DIR 'ht-net-conn.ps1')
    (Join-Path $DEST_DIR 'ht-os-perf-hw.ps1')
    (Join-Path $DEST_DIR 'ht-win-os-hyg.ps1')
    (Join-Path $DEST_DIR 'ht-hypervisor.ps1')
    (Join-Path $DEST_DIR 'ht-DomJoined.ps1')
    (Join-Path $DEST_DIR 'ht-member.ps1')
    (Join-Path $DEST_DIR 'ht-mobile.ps1')
    (Join-Path $DEST_DIR 'ht-servers.ps1')
    (Join-Path $DEST_DIR 'ht-AD-GPO-mgmt.ps1')
    (Join-Path $DEST_DIR 'ht-DNS-DHCP-srvc.ps1')
    (Join-Path $DEST_DIR 'ht-hyperv-mgmt.ps1')
    (Join-Path $DEST_DIR 'ht-special.ps1')
  )

  foreach ($fpath in $obsoleteFiles) {
    if (Test-Path -LiteralPath $fpath) {
      Write-Verbose "Removing obsolete file '$fpath'"
      Remove-Item -LiteralPath $fpath
    }
  }
}

try {
  $backupRetentionCutoff = (Get-Date).AddMonths(-1)
  Write-Verbose "Pruning backup .bak files older than '$backupRetentionCutoff' from '$BAK_DIR'"

  $oldBackups = Get-ChildItem -LiteralPath $BAK_DIR -File -Filter '*.bak' -ErrorAction Stop |
    Where-Object { $_.LastWriteTime -lt $backupRetentionCutoff }

  foreach ($item in $oldBackups) {
    Write-Verbose "Deleting old backup file '$($item.FullName)'"
  }

  $oldBackups | Remove-Item -Force -ErrorAction Stop
} catch {
  Write-Warning ("Failed pruning old backups in {0}: {1}" -f $BAK_DIR, $_.Exception.Message)
}

Write-Verbose "Update-GetHealthCode completed"
