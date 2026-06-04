<#
.SYNOPSIS
Ensures all health-check scripts and PS Modules are installed & up-to-date.

.DESCRIPTION
Missing files are created. Existing files that differ are replaced.
Identical files are left unchanged. If this script updates itself,
it re-invokes the updated copy. When replacing a file, backup copies
are created in the backups directory.
Will set PSGallery as Trusted.

The updater also tracks a small "release marker" for the currently
installed code and for the target update source. A release marker is a
stable identifier for a specific release source, typically derived from
GitHub release metadata or from a manually supplied zip file name plus
its content hash. These markers are cached locally and let the updater
decide whether the requested update is already installed, whether it can
skip re-downloading or reapplying files, and when `-Reinstall` should
force the update to run again.

.PARAMETER Reinstall
Forces reinstall even when installed release matches target release.

.PARAMETER UpdateFromZip
Overides the default which is to fetch the latest GitHub release.

.PARAMETER Version
Explicit semantic version to associate with `-UpdateFromZip` when the zip
file name does not already embed a version token such as `v4.4.3`.
Use `X.Y.Z` or `vX.Y.Z`. 

.PARAMETER ForceRefreshReleaseMetadata
Overides the default which is to cache latest-release metadata locally
for a few minutes (to avoid querying GitHub on every run).

.PARAMETER Config
Hashtable or PowerShell data file path for customized installs. `Options.InstallDir`
sets the install root; `ConfigFiles` writes named .psd1 files under the config folder.

.PARAMETER SelfRerunCount
Internal use only. Tracks the one-time self-rerun pass count.

.PARAMETER PersistReleaseMarker
Internal use only. Carries the resolved release marker across self-rerun.

.PARAMETER Config
Optional installer customization. Pass either a hashtable or the path to a PowerShell data file.
The top-level Options branch changes installer behavior. The top-level ConfigFiles branch
creates PowerShell data files under the installation config directory.

.PARAMETER GenerateConfigPsd1
Creates a template PowerShell data file named GetComputerHealth.install.psd1 in the current
working directory, then exits. Customize that file and pass its path to -Config.

.EXAMPLE
.\Update-GetHealthCode.ps1

Checks the locally cached latest-release metadata, refreshes it from
GitHub when needed, and installs the latest published release when it is
newer than the currently installed release marker.

.EXAMPLE
.\Update-GetHealthCode.ps1 -UpdateFromZip C:\Downloads\GetComputerHealth-v4.4.3.zip

#>
[CmdletBinding()]
param(
  [switch]$Reinstall,
  [string]$UpdateFromZip,
  [string]$Version,
  [switch]$ForceRefreshReleaseMetadata,
  [object]$Config,
  [switch]$GenerateConfigPsd1,
  [Parameter(DontShow=$true)][int]$SelfRerunCount = 0,
  [Parameter(DontShow=$true)][string]$PersistReleaseMarker
)


function Get-EarlyGchInstallConfigSection {
  param(
    [AllowNull()]$ConfigObject,
    [Parameter(Mandatory)][string]$Key
  )

  if ($null -eq $ConfigObject) { return $null }
  if ($ConfigObject -is [hashtable]) {
    if ($ConfigObject.ContainsKey($Key)) { return $ConfigObject[$Key] }
    return $null
  }
  if ($ConfigObject.PSObject.Properties[$Key]) { return $ConfigObject.$Key }
  return $null
}

function Resolve-EarlyGchInstallConfig {
  param([AllowNull()]$InputObject)

  if ($null -eq $InputObject) { return $null }
  if ($InputObject -is [string]) {
    $configPath = [string]$InputObject
    if ([string]::IsNullOrWhiteSpace($configPath)) { return $null }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
      throw "Install configuration file not found: '$configPath'"
    }
    return (Import-PowerShellDataFile -LiteralPath $configPath -ErrorAction Stop)
  }
  return $InputObject
}

function Get-EarlyGchInstallConfigValue {
  param(
    [Parameter(Mandatory)]$ConfigObject,
    [Parameter(Mandatory)][string]$Key
  )

  if ($ConfigObject -is [hashtable]) { return $ConfigObject[$Key] }
  return $ConfigObject.$Key
}

function ConvertTo-EarlyGchPsd1KeyLiteral {
  param([Parameter(Mandatory)][string]$Key)

  if ($Key -match '^[A-Za-z_][A-Za-z0-9_]*$') { return $Key }
  return ("'{0}'" -f ($Key -replace "'", "''"))
}

function ConvertTo-EarlyGchPsd1Literal {
  param(
    [AllowNull()]$Value,
    [int]$Indent = 0
  )

  $spaces = ''.PadLeft($Indent)
  $childIndent = $Indent + 4
  $childSpaces = ''.PadLeft($childIndent)

  if ($null -eq $Value) { return '$null' }
  if ($Value -is [bool]) {
    if ($Value) { return '$true' }
    return '$false'
  }
  if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return ([string]$Value) }
  if ($Value -is [System.Collections.IDictionary]) {
    $lines = @('@{')
    foreach ($key in @($Value.Keys | Sort-Object)) {
      $keyText = ConvertTo-EarlyGchPsd1KeyLiteral -Key ([string]$key)
      $valueText = ConvertTo-EarlyGchPsd1Literal -Value $Value[$key] -Indent $childIndent
      $lines += ('{0}{1} = {2}' -f $childSpaces, $keyText, $valueText)
    }
    $lines += ($spaces + '}')
    return ($lines -join [Environment]::NewLine)
  }
  if (($Value -is [System.Collections.IEnumerable]) -and (-not ($Value -is [string]))) {
    $items = @($Value)
    if ($items.Count -eq 0) { return '@()' }
    $itemTexts = @()
    foreach ($item in $items) { $itemTexts += (ConvertTo-EarlyGchPsd1Literal -Value $item -Indent $childIndent) }
    return ('@({0}{1}{0})' -f [Environment]::NewLine, (($itemTexts | ForEach-Object { $childSpaces + $_ }) -join (',' + [Environment]::NewLine)))
  }
  return ("'{0}'" -f (([string]$Value) -replace "'", "''"))
}

function ConvertTo-EarlyGchPsd1Text {
  param([Parameter(Mandatory)]$Value)
  (ConvertTo-EarlyGchPsd1Literal -Value $Value -Indent 0) + [Environment]::NewLine
}

function Write-EarlyGchTextFileUtf8NoBom {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Text
  )

  $dir = Split-Path -Parent $Path
  if ($dir -and (-not (Test-Path -LiteralPath $dir -PathType Container))) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-EarlyGchCustomConfigFiles {
  param(
    [AllowNull()]$InstallConfig,
    [Parameter(Mandatory)][string]$ConfigDir
  )

  $configFiles = Get-EarlyGchInstallConfigSection -ConfigObject $InstallConfig -Key 'ConfigFiles'
  if ($null -eq $configFiles) { return }
  if (-not ($configFiles -is [System.Collections.IDictionary])) {
    throw 'ConfigFiles must be a hashtable whose keys are config file names.'
  }
  if (-not (Test-Path -LiteralPath $ConfigDir -PathType Container)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
  }
  foreach ($name in @($configFiles.Keys | Sort-Object)) {
    $fileName = [string]$name
    if ([string]::IsNullOrWhiteSpace($fileName)) { throw 'ConfigFiles contains an empty config file name.' }
    if ($fileName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 -or $fileName -match '[\\/]') {
      throw "ConfigFiles file name '$fileName' must be a simple file name."
    }
    $path = Join-Path $ConfigDir $fileName
    Write-EarlyGchTextFileUtf8NoBom -Path $path -Text (ConvertTo-EarlyGchPsd1Text -Value $configFiles[$name])
  }
}


####################################################################
#
#  START OF CONFIG
#
$script:InstallConfig = Resolve-EarlyGchInstallConfig -InputObject $Config
$SCRIPT_BIN_DIR = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$installOptions = Get-EarlyGchInstallConfigSection -ConfigObject $script:InstallConfig -Key 'Options'
if ($installOptions -and ((($installOptions -is [hashtable]) -and $installOptions.ContainsKey('InstallDir')) -or ($installOptions.PSObject.Properties['InstallDir']))) {
  $installDir = [string](Get-EarlyGchInstallConfigValue -ConfigObject $installOptions -Key 'InstallDir')
  if ([string]::IsNullOrWhiteSpace($installDir)) {
    throw 'Config.Options.InstallDir cannot be empty.'
  }
  $ROOT_DIR = [System.IO.Path]::GetFullPath($installDir)
  $SCRIPT_BIN_DIR = Join-Path $ROOT_DIR 'bin'
}
elseif ((Split-Path -Leaf $SCRIPT_BIN_DIR) -ine 'bin') {
  throw "Refusing to run. Update-GetHealthCode.ps1 must be located in and executed from a 'bin' folder unless -Config @{ Options = @{ InstallDir = ... } } is provided. Current script location: '$SCRIPT_BIN_DIR'."
}
else {
  $ROOT_DIR = Split-Path -Parent $SCRIPT_BIN_DIR
}

$DEST_DIR = $SCRIPT_BIN_DIR
$BAK_DIR  = Join-Path $ROOT_DIR 'temp'
$CFG_DIR  = Join-Path $ROOT_DIR 'config'
$LOG_DIR  = Join-Path $ROOT_DIR 'log'
$script:UpdateTranscriptStarted = $false
$script:UpdateTranscriptTempPath = $null
$script:UpdateTranscriptFinalPath = $null
$script:UpdateTranscriptTimestamp = (Get-Date)
$REPO_URL = 'https://github.com/ndemou/GetComputerHealth'
$SHOW_AS_POSTPONED_WINDOW_DAYS = 150
$REPO_REF = 'main'
$GCH_CONFIG_PATH = $null
$LATEST_RELEASE_METADATA_CACHE_PATH = $null
$RELEASE_METADATA_CACHE_TTL_MINUTES = 60
$ZIP_CACHE_PATTERN = 'GetComputerHealth-release-*.zip'
$MANUAL_ZIP_CACHE_PATTERN = 'GetComputerHealth-MANUAL-UPDATE-*.zip'
$repoSlug = $null
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
}


function ConvertTo-GchHashtable {
  [CmdletBinding()]
  param([AllowNull()]$Value)

  if ($null -eq $Value) {
    return @{}
  }

  if ($Value -is [hashtable]) {
    return $Value
  }

  if ($Value -is [string]) {
    $path = [System.IO.Path]::GetFullPath($Value)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      throw "Configuration file '$path' does not exist."
    }

    try {
      $loadedConfig = Import-PowerShellDataFile -LiteralPath $path -ErrorAction Stop
    } catch {
      throw "Failed reading configuration file '$path': $($_.Exception.Message)"
    }

    if ($null -eq $loadedConfig) {
      return @{}
    }

    if ($loadedConfig -isnot [hashtable]) {
      throw "Configuration file '$path' must contain a top-level hashtable."
    }

    return $loadedConfig
  }

  throw "-Config must be a hashtable or the path to a PowerShell data file."
}

function Get-GchInstallConfigTemplateText {
  [CmdletBinding()]
  param()

  @'
@{
    Options = @{
        # Installation root. Scripts are installed under the bin subfolder.
        InstallDir = 'C:\IT\GetComputerHealth'
    }
    ConfigFiles = @{
        'Send-Message.psd1' = @{
            Server = 'smtp.contoso.com'
            From   = 'SERVER01+alerts@contoso.com'
            To     = 'ops@contoso.com;admin@contoso.com'
        }
        'gch.psd1' = @{
            AutomaticUpdates = $false
            SendReports = 'Auto' # 'Never', 'Always', 'Auto'
            ShowAsPostponedWindowDays = 15
            IpsOfAllDCs = @('10.1.2.3', '10.1.2.4')
        }
    }
}
'@
}

function Write-GchInstallConfigTemplate {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $parentDir = Split-Path -Parent $fullPath
  if (-not [string]::IsNullOrWhiteSpace($parentDir) -and (-not (Test-Path -LiteralPath $parentDir -PathType Container))) {
    $null = New-Item -ItemType Directory -Path $parentDir -Force
  }

  Set-Content -LiteralPath $fullPath -Value (Get-GchInstallConfigTemplateText) -Encoding UTF8
  return $fullPath
}

function Get-GchInstallOption {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$InstallConfig,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not (Test-GchConfigKey -Config $InstallConfig -Key 'Options')) {
    return $null
  }

  $options = Get-GchConfigValue -Config $InstallConfig -Key 'Options'
  if ($null -eq $options) {
    return $null
  }

  if (-not (Test-GchConfigKey -Config $options -Key $Name)) {
    return $null
  }

  return (Get-GchConfigValue -Config $options -Key $Name)
}

function ConvertTo-GchPsd1Literal {
  [CmdletBinding()]
  param(
    [AllowNull()]$Value,
    [int]$Indent = 0
  )

  if ($null -eq $Value) {
    return '$null'
  }

  if ($Value -is [bool]) {
    if ($Value) { return '$true' }
    return '$false'
  }

  if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
    return ([string]$Value)
  }

  if ($Value -is [string]) {
    return ("'{0}'" -f ($Value -replace "'", "''"))
  }

  if ($Value -is [hashtable]) {
    $lines = @('@{')
    foreach ($key in $Value.Keys) {
      $keyText = [string]$key
      $safeKey = if ($keyText -match '^[A-Za-z_][A-Za-z0-9_]*$') { $keyText } else { "'{0}'" -f ($keyText -replace "'", "''") }
      $child = ConvertTo-GchPsd1Literal -Value $Value[$key] -Indent ($Indent + 4)
      $lines += (' ' * ($Indent + 4)) + $safeKey + ' = ' + $child
    }
    $lines += (' ' * $Indent) + '}'
    return ($lines -join "`r`n")
  }

  if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
    $items = @()
    foreach ($item in $Value) {
      $items += (ConvertTo-GchPsd1Literal -Value $item -Indent $Indent)
    }
    return ('@(' + ($items -join ', ') + ')')
  }

  return ("'{0}'" -f (([string]$Value) -replace "'", "''"))
}

function ConvertTo-GchPsd1Text {
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable]$Data)

  return (ConvertTo-GchPsd1Literal -Value $Data -Indent 0) + "`r`n"
}

function Write-GchConfigFilesFromInstallConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$InstallConfig,
    [Parameter(Mandatory)][string]$ConfigDirectory
  )

  if (-not (Test-GchConfigKey -Config $InstallConfig -Key 'ConfigFiles')) {
    return
  }

  $configFiles = Get-GchConfigValue -Config $InstallConfig -Key 'ConfigFiles'
  if ($null -eq $configFiles) {
    return
  }

  if ($configFiles -isnot [hashtable]) {
    throw "The ConfigFiles branch in -Config must be a hashtable."
  }

  if (-not (Test-Path -LiteralPath $ConfigDirectory -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $ConfigDirectory -Force
  }

  foreach ($fileNameObject in $configFiles.Keys) {
    $fileName = [string]$fileNameObject
    if ([string]::IsNullOrWhiteSpace($fileName)) {
      throw "ConfigFiles contains an empty file name."
    }
    if ([System.IO.Path]::IsPathRooted($fileName) -or $fileName.Contains('..') -or $fileName.Contains('\') -or $fileName.Contains('/')) {
      throw "ConfigFiles entry '$fileName' is invalid. Use only a file name such as 'gch.psd1'."
    }
    if (-not $fileName.EndsWith('.psd1', [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "ConfigFiles entry '$fileName' is invalid. Configuration file names must end with .psd1."
    }
    if ($configFiles[$fileNameObject] -isnot [hashtable]) {
      throw "ConfigFiles entry '$fileName' must contain a hashtable."
    }

    $targetPath = Join-Path $ConfigDirectory $fileName
    $text = ConvertTo-GchPsd1Text -Data $configFiles[$fileNameObject]
    Set-Content -LiteralPath $targetPath -Value $text -Encoding UTF8
    Write-UpdateEvent "Wrote configuration file '$targetPath'"
  }
}

function Get-GchDefaultConfigText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RepoUrl,
    [Parameter(Mandatory)][int]$ShowAsPostponedWindowDays
  )

  @"
@{
    AutomaticUpdates = `$true
    RepoUrl = '$RepoUrl'
    ShowAsPostponedWindowDays = $ShowAsPostponedWindowDays
}
"@
}

function Ensure-GchConfigFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$RepoUrl,
    [Parameter(Mandatory)][int]$ShowAsPostponedWindowDays
  )

  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    return
  }

  $parentDir = Split-Path -Parent $Path
  if (-not [string]::IsNullOrWhiteSpace($parentDir) -and (-not (Test-Path -LiteralPath $parentDir -PathType Container))) {
    $null = New-Item -ItemType Directory -Path $parentDir -Force
  }

  $text = Get-GchDefaultConfigText -RepoUrl $RepoUrl -ShowAsPostponedWindowDays $ShowAsPostponedWindowDays
  Set-Content -LiteralPath $Path -Value $text -Encoding UTF8
}

function Read-GchConfigFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return @{}
  }

  try {
    $config = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
  } catch {
    throw "Failed reading configuration file '$Path': $($_.Exception.Message)"
  }

  if ($null -eq $config) {
    return @{}
  }

  return $config
}

function Test-GchConfigKey {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Config,
    [Parameter(Mandatory)][string]$Key
  )

  if ($Config -is [hashtable]) {
    return $Config.ContainsKey($Key)
  }

  return ($Config.PSObject.Properties[$Key] -ne $null)
}

function Get-GchConfigValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Config,
    [Parameter(Mandatory)][string]$Key
  )

  if ($Config -is [hashtable]) {
    return $Config[$Key]
  }

  return $Config.$Key
}

function Test-GchFalsyValue {
  [CmdletBinding()]
  param([AllowNull()]$Value)

  if ($null -eq $Value) { return $true }
  if ($Value -is [bool]) { return (-not $Value) }
  if ($Value -is [int]) { return ($Value -eq 0) }
  if ($Value -is [string]) {
    $text = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }
    return ($text -in @('0', 'false', 'no', 'off'))
  }

  return (-not [bool]$Value)
}

function Resolve-GchConfiguredRepoUrl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RepoUrl)

  $value = $RepoUrl.Trim()
  $uri = $null
  if (([string]::IsNullOrWhiteSpace($value)) -or (-not [System.Uri]::TryCreate($value, [System.UriKind]::Absolute, [ref]$uri))) {
    throw "Invalid RepoUrl value in gch.psd1: '$RepoUrl'. Use a GitHub repository URL such as https://github.com/owner/repo."
  }

  if (($uri.Scheme -notin @('http', 'https')) -or ($uri.Host -ine 'github.com')) {
    throw "Invalid RepoUrl value in gch.psd1: '$RepoUrl'. Use a GitHub repository URL such as https://github.com/owner/repo."
  }

  $parts = @($uri.AbsolutePath.Trim('/') -split '/')
  if (($parts.Count -lt 2) -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
    throw "Invalid RepoUrl value in gch.psd1: '$RepoUrl'. Use a GitHub repository URL such as https://github.com/owner/repo."
  }

  $normalizedPath = ('{0}/{1}' -f $parts[0], (($parts[1] -replace '\.git$', '')))
  return ('{0}://github.com/{1}' -f $uri.Scheme.ToLowerInvariant(), $normalizedPath)
}

function Resolve-GchConfiguredNonNegativeInteger {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Value,
    [Parameter(Mandatory)][string]$Key
  )

  $text = ([string]$Value).Trim()
  $number = 0
  if (([string]::IsNullOrWhiteSpace($text)) -or (-not [int]::TryParse($text, [ref]$number)) -or ($number -lt 0)) {
    throw "Invalid $Key value in gch.psd1: '$Value'. Use an integer greater than or equal to 0."
  }

  return $number
}

function Get-DiskFormatStateText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$CurrentDiskFormat,
    [Parameter(Mandatory)][int]$LatestCompatibleCodeVersion
  )

  @"
@{
  # This is the major version of the last code release that changed the On-Disk Format
  CurrentDiskFormat = $CurrentDiskFormat
  # This is the major version of the latest code that works fine with the above On-Disk Format
  LatestCompatibleCodeVersion = $LatestCompatibleCodeVersion
}
"@
}

function Read-DiskFormatState {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return @{
      CurrentDiskFormat = 4
      LatestCompatibleCodeVersion = 4
    }
  }

  try {
    $state = Import-PowerShellDataFile -LiteralPath $Path -ErrorAction Stop
  } catch {
    throw "Failed reading disk format state file '$Path': $($_.Exception.Message)"
  }

  if ($null -eq $state) {
    throw "Disk format state file '$Path' did not contain a PowerShell data hash."
  }

  $current = Resolve-GchConfiguredNonNegativeInteger -Value $state.CurrentDiskFormat -Key 'CurrentDiskFormat'
  $latestCompatible = Resolve-GchConfiguredNonNegativeInteger -Value $state.LatestCompatibleCodeVersion -Key 'LatestCompatibleCodeVersion'

  return @{
    CurrentDiskFormat = $current
    LatestCompatibleCodeVersion = $latestCompatible
  }
}

function Write-DiskFormatState {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][int]$CurrentDiskFormat,
    [Parameter(Mandatory)][int]$LatestCompatibleCodeVersion
  )

  $parentDir = Split-Path -Parent $Path
  if (-not [string]::IsNullOrWhiteSpace($parentDir) -and (-not (Test-Path -LiteralPath $parentDir -PathType Container))) {
    $null = New-Item -ItemType Directory -Path $parentDir -Force
  }

  $text = Get-DiskFormatStateText -CurrentDiskFormat $CurrentDiskFormat -LatestCompatibleCodeVersion $LatestCompatibleCodeVersion
  Set-Content -LiteralPath $Path -Value $text -Encoding UTF8
}

function Get-GetComputerHealthMajorVersion {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Version)

  $match = [regex]::Match($Version.Trim(), '^(?:v)?(?<Major>\d+)\.\d+\.\d+$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $match.Success) {
    throw "Invalid GetComputerHealth version '$Version'. Use semantic version format X.Y.Z."
  }

  return [int]$match.Groups['Major'].Value
}

function ConvertTo-DiskFormatManifestList {
  [CmdletBinding()]
  param([AllowNull()][string]$Value)

  $items = @()
  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $items
  }

  foreach ($item in ($Value -split ',')) {
    $trimmed = $item.Trim()
    if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
      $items += $trimmed
    }
  }

  return $items
}

function Read-DiskFormatMigrationManifest {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ScriptPath)

  $text = Get-Content -LiteralPath $ScriptPath -Raw -ErrorAction Stop
  $manifestMatch = [regex]::Match($text, '(?is)\.MANIFEST\s*(?<Body>.*?)(?:\r?\n\s*\.[A-Z][A-Z0-9_-]*|\r?\n\s*#>)')
  if (-not $manifestMatch.Success) {
    throw "Migration script '$ScriptPath' is missing a .MANIFEST block."
  }

  $modifiedTopFolders = @()
  $newTopFolders = @()
  $lines = $manifestMatch.Groups['Body'].Value -split "`r?`n"
  foreach ($line in $lines) {
    $cleanLine = ([string]$line).Trim()
    if ([string]::IsNullOrWhiteSpace($cleanLine) -or $cleanLine.StartsWith('#')) {
      continue
    }

    $keyValueMatch = [regex]::Match($cleanLine, '^(?<Key>[A-Za-z][A-Za-z0-9_]*)\s*=\s*(?<Value>.*)$')
    if (-not $keyValueMatch.Success) {
      continue
    }

    $key = $keyValueMatch.Groups['Key'].Value
    $value = $keyValueMatch.Groups['Value'].Value
    if ($key -ieq 'ModifiedTopFolders') {
      $modifiedTopFolders = ConvertTo-DiskFormatManifestList -Value $value
    } elseif ($key -ieq 'NewTopFolders') {
      $newTopFolders = ConvertTo-DiskFormatManifestList -Value $value
    }
  }

  return @{
    ModifiedTopFolders = @($modifiedTopFolders)
    NewTopFolders = @($newTopFolders)
  }
}

function Get-DiskFormatMigrationScripts {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$MigrationDir,
    [Parameter(Mandatory)][int]$SourceDiskFormat,
    [Parameter(Mandatory)][int]$TargetCodeVersion
  )

  if (-not (Test-Path -LiteralPath $MigrationDir -PathType Container)) {
    return @()
  }

  $results = @()
  $files = @(Get-ChildItem -LiteralPath $MigrationDir -File -Filter 'migrate-to-version-*.ps1' -ErrorAction Stop)
  foreach ($file in $files) {
    $match = [regex]::Match($file.Name, '^migrate-to-version-(?<Version>\d+)\.ps1$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
      continue
    }

    $migrationVersion = [int]$match.Groups['Version'].Value
    if (($migrationVersion -gt $SourceDiskFormat) -and ($migrationVersion -le $TargetCodeVersion)) {
      $results += [pscustomobject]@{
        Version = $migrationVersion
        Path = $file.FullName
      }
    }
  }

  return @($results | Sort-Object -Property Version)
}

function Remove-OldDiskFormatMigrationBackups {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootDir,
    [int]$RetentionDays = 7
  )

  try {
    $cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
    $oldBackups = @()
    $backupCandidates = @(Get-ChildItem -LiteralPath $RootDir -Directory -Recurse -ErrorAction Stop)
    foreach ($candidate in $backupCandidates) {
      if (($candidate.Name -match '^\d+-to-\d+\.bak$') -and ($candidate.LastWriteTime -lt $cutoff)) {
        $oldBackups += $candidate
      }
    }

    foreach ($backup in $oldBackups) {
      Write-Verbose "Deleting old disk format migration backup '$($backup.FullName)'"
      Remove-Item -LiteralPath $backup.FullName -Recurse -Force -ErrorAction Stop
    }
  } catch {
    Write-Warning ("Failed pruning old disk format migration backups in {0}: {1}" -f $RootDir, $_.Exception.Message)
  }
}

function Backup-DiskFormatMigrationFolders {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootDir,
    [Parameter(Mandatory)][string[]]$TopFolders,
    [Parameter(Mandatory)][int]$FromVersion,
    [Parameter(Mandatory)][int]$ToVersion
  )

  $backups = @()
  foreach ($topFolder in $TopFolders) {
    if ([string]::IsNullOrWhiteSpace($topFolder)) {
      continue
    }

    if ($topFolder.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
      throw "Invalid top folder name in migration manifest: '$topFolder'"
    }

    $sourcePath = Join-Path $RootDir $topFolder
    $backupPath = Join-Path $sourcePath ('{0}-to-{1}.bak' -f $FromVersion, $ToVersion)
    $backupLeafName = Split-Path -Leaf $backupPath

    if (Test-Path -LiteralPath $backupPath) {
      Write-Verbose "Deleting existing disk format migration backup '$backupPath'"
      Remove-Item -LiteralPath $backupPath -Recurse -Force -ErrorAction Stop
    }

    if (Test-Path -LiteralPath $sourcePath -PathType Container) {
      Write-Verbose "Creating disk format migration backup '$backupPath' from '$sourcePath'"
      New-Item -ItemType Directory -Path $backupPath -Force -ErrorAction Stop | Out-Null
      $sourceChildren = @(Get-ChildItem -LiteralPath $sourcePath -Force -ErrorAction Stop)
      foreach ($child in $sourceChildren) {
        if ($child.Name -ieq $backupLeafName) {
          continue
        }

        Copy-Item -LiteralPath $child.FullName -Destination $backupPath -Recurse -Force -ErrorAction Stop
      }

      Write-UpdateEvent "Created disk format migration backup '$backupPath'"
      $backups += [pscustomobject]@{
        TopFolder = $topFolder
        SourcePath = $sourcePath
        BackupPath = $backupPath
        HadSource = $true
      }
    } else {
      Write-Verbose "Top folder '$sourcePath' does not exist; no migration backup needed"
      $backups += [pscustomobject]@{
        TopFolder = $topFolder
        SourcePath = $sourcePath
        BackupPath = $backupPath
        HadSource = $false
      }
    }
  }

  return @($backups)
}

function Restore-DiskFormatMigrationFolders {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Backups)

  foreach ($backup in @($Backups)) {
    if ($backup.HadSource) {
      if (-not (Test-Path -LiteralPath $backup.BackupPath -PathType Container)) {
        throw "Cannot restore disk format migration backup because '$($backup.BackupPath)' no longer exists."
      }

      if (-not (Test-Path -LiteralPath $backup.SourcePath -PathType Container)) {
        New-Item -ItemType Directory -Path $backup.SourcePath -Force -ErrorAction Stop | Out-Null
      }

      $backupLeafName = Split-Path -Leaf $backup.BackupPath
      $sourceChildren = @(Get-ChildItem -LiteralPath $backup.SourcePath -Force -ErrorAction Stop)
      foreach ($child in $sourceChildren) {
        if ($child.Name -ieq $backupLeafName) {
          continue
        }

        Write-Verbose "Removing modified path '$($child.FullName)' before restore"
        Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction Stop
      }

      Write-Verbose "Restoring disk format migration backup '$($backup.BackupPath)' to '$($backup.SourcePath)'"
      $backupChildren = @(Get-ChildItem -LiteralPath $backup.BackupPath -Force -ErrorAction Stop)
      foreach ($child in $backupChildren) {
        Copy-Item -LiteralPath $child.FullName -Destination $backup.SourcePath -Recurse -Force -ErrorAction Stop
      }
    } elseif (Test-Path -LiteralPath $backup.SourcePath) {
      Write-Verbose "Deleting folder '$($backup.SourcePath)' because it did not exist before the failed migration"
      Remove-Item -LiteralPath $backup.SourcePath -Recurse -Force -ErrorAction Stop
    }
  }
}

function Remove-DiskFormatMigrationNewFolders {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootDir,
    [Parameter(Mandatory)][string[]]$TopFolders,
    [string[]]$ExistingTopFolders = @()
  )

  $existing = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($topFolder in $ExistingTopFolders) {
    if (-not [string]::IsNullOrWhiteSpace($topFolder)) {
      $null = $existing.Add($topFolder)
    }
  }

  foreach ($topFolder in $TopFolders) {
    if ([string]::IsNullOrWhiteSpace($topFolder)) {
      continue
    }

    if ($existing.Contains($topFolder)) {
      Write-Verbose "Leaving existing folder '$topFolder' in place after failed migration"
      continue
    }

    $path = Join-Path $RootDir $topFolder
    if (Test-Path -LiteralPath $path) {
      Write-Verbose "Deleting new folder introduced by failed migration: '$path'"
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    }
  }
}

function Invoke-DiskFormatMigrationScript {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [Parameter(Mandatory)][string]$WorkingDirectory
  )

  $powerShellExe = Join-Path $PSHOME 'powershell.exe'
  if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) {
    $powerShellExe = 'powershell.exe'
  }

  $startInfo = New-Object System.Diagnostics.ProcessStartInfo
  $startInfo.FileName = $powerShellExe
  $startInfo.Arguments = ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f ($ScriptPath -replace '"', '\"'))
  $startInfo.UseShellExecute = $false
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.CreateNoWindow = $true
  $startInfo.WorkingDirectory = $WorkingDirectory

  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $startInfo
  $null = $process.Start()
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()

  if (-not [string]::IsNullOrWhiteSpace($stdout)) {
    Write-Host $stdout.TrimEnd()
  }
  if (-not [string]::IsNullOrWhiteSpace($stderr)) {
    Write-Warning $stderr.TrimEnd()
  }

  $stdoutLines = @()
  if (-not [string]::IsNullOrWhiteSpace($stdout)) {
    $stdoutLines = @($stdout -split "`r?`n")
  }

  $lastStdoutLine = ''
  for ($i = $stdoutLines.Count - 1; $i -ge 0; $i--) {
    $candidate = ([string]$stdoutLines[$i]).Trim()
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
      $lastStdoutLine = $candidate
      break
    }
  }

  $updaterPath = $null
  if ($lastStdoutLine -match '^PATH_TO_UPDATER=(?<Path>.+)$') {
    $updaterPath = $matches['Path']
  }

  return [pscustomobject]@{
    ExitCode = [int]$process.ExitCode
    LastStdoutLine = $lastStdoutLine
    UpdaterPath = $updaterPath
  }
}

function Invoke-DiskFormatMigrations {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootDir,
    [Parameter(Mandatory)][string]$ReleaseRoot,
    [Parameter(Mandatory)][string]$TargetCodeVersion
  )

  $targetCodeMajor = Get-GetComputerHealthMajorVersion -Version $TargetCodeVersion
  $dataDir = Join-Path $RootDir 'data'
  $statePath = Join-Path $dataDir 'disk-format.psd1'
  $state = Read-DiskFormatState -Path $statePath
  $sourceDiskFormat = [int]$state.CurrentDiskFormat

  Write-UpdateEvent "Detected source disk format: $sourceDiskFormat"
  Write-UpdateEvent "Target code major version: $targetCodeMajor"
  Write-Verbose "Detected source disk format: $sourceDiskFormat"
  Write-Verbose "Target code major version: $targetCodeMajor"

  if ($targetCodeMajor -lt $sourceDiskFormat) {
    throw "Format downgrade is not supported. Source disk format is $sourceDiskFormat but target code major version is $targetCodeMajor."
  }

  $mutex = New-Object System.Threading.Mutex($false, 'Global\GetComputerHealth-DiskFormatMigration')
  $hasMutex = $false
  try {
    try {
      $hasMutex = $mutex.WaitOne([TimeSpan]::FromSeconds(60))
    } catch [System.Threading.AbandonedMutexException] {
      $hasMutex = $true
      Write-Warning 'Recovered an abandoned disk format migration mutex.'
    }

    if (-not $hasMutex) {
      throw 'Another GetComputerHealth disk format migration is already running.'
    }

    Remove-OldDiskFormatMigrationBackups -RootDir $RootDir -RetentionDays 7

    $migrationDir = Join-Path $ReleaseRoot 'disk-format-migrations'
    $migrations = @(Get-DiskFormatMigrationScripts -MigrationDir $migrationDir -SourceDiskFormat $sourceDiskFormat -TargetCodeVersion $targetCodeMajor)
    $currentDiskFormat = $sourceDiskFormat
    $lastUpdaterPath = $null

    if ($migrations.Count -eq 0) {
      Write-Verbose "No disk format migration scripts found for versions greater than $sourceDiskFormat and less than or equal to $targetCodeMajor"
      Write-UpdateEvent "No disk format migration is needed."
      if ([int]$state.LatestCompatibleCodeVersion -ne $targetCodeMajor) {
        Write-DiskFormatState -Path $statePath -CurrentDiskFormat $currentDiskFormat -LatestCompatibleCodeVersion $targetCodeMajor
        Write-UpdateEvent "Persisted disk format: CurrentDiskFormat=$currentDiskFormat LatestCompatibleCodeVersion=$targetCodeMajor"
      }
      return [pscustomobject]@{
        CurrentDiskFormat = $currentDiskFormat
        LatestCompatibleCodeVersion = $targetCodeMajor
        UpdaterPath = $null
        RanMigrations = $false
      }
    }

    foreach ($migration in $migrations) {
      $manifest = Read-DiskFormatMigrationManifest -ScriptPath $migration.Path
      $modifiedTopFolders = @($manifest.ModifiedTopFolders)
      $newTopFolders = @($manifest.NewTopFolders)

      Write-UpdateEvent ("Running disk format migration {0} from '{1}'" -f $migration.Version, $migration.Path)
      $backups = @()
      $existingNewTopFolders = @()
      foreach ($topFolder in $newTopFolders) {
        if ([string]::IsNullOrWhiteSpace($topFolder)) {
          continue
        }

        if (Test-Path -LiteralPath (Join-Path $RootDir $topFolder)) {
          $existingNewTopFolders += $topFolder
        }
      }

      try {
        $backups = @(Backup-DiskFormatMigrationFolders -RootDir $RootDir -TopFolders $modifiedTopFolders -FromVersion $currentDiskFormat -ToVersion $migration.Version)
        $result = Invoke-DiskFormatMigrationScript -ScriptPath $migration.Path -WorkingDirectory $RootDir

        if ($result.ExitCode -eq 0) {
          if ([string]::IsNullOrWhiteSpace($result.UpdaterPath)) {
            throw "Migration '$($migration.Path)' succeeded but did not emit PATH_TO_UPDATER as the last stdout line."
          }
          $lastUpdaterPath = $result.UpdaterPath
          $currentDiskFormat = [int]$migration.Version
        } elseif (($result.ExitCode -eq 1) -and ($result.LastStdoutLine -eq 'No migration is needed')) {
          Write-Verbose "Migration '$($migration.Path)' reported that no action was needed"
          $currentDiskFormat = [int]$migration.Version
        } else {
          throw "Migration '$($migration.Path)' failed with exit code $($result.ExitCode)."
        }
      } catch {
        Write-Warning ("Disk format migration {0} failed; attempting restore: {1}" -f $migration.Version, $_.Exception.Message)
        Restore-DiskFormatMigrationFolders -Backups $backups
        Remove-DiskFormatMigrationNewFolders -RootDir $RootDir -TopFolders $newTopFolders -ExistingTopFolders $existingNewTopFolders
        throw
      }
    }

    Write-DiskFormatState -Path $statePath -CurrentDiskFormat $currentDiskFormat -LatestCompatibleCodeVersion $targetCodeMajor
    Write-UpdateEvent "Persisted disk format: CurrentDiskFormat=$currentDiskFormat LatestCompatibleCodeVersion=$targetCodeMajor"

    return [pscustomobject]@{
      CurrentDiskFormat = $currentDiskFormat
      LatestCompatibleCodeVersion = $targetCodeMajor
      UpdaterPath = $lastUpdaterPath
      RanMigrations = $true
    }
  } finally {
    if ($hasMutex) {
      $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
  }
}

function Start-UpdateTranscript {
<#
.SYNOPSIS
Starts transcript logging for the updater when possible.
#>
  [CmdletBinding()]
  param()

  try {
    $tempRoot = $env:TEMP
    if ([string]::IsNullOrWhiteSpace($tempRoot)) {
      $tempRoot = [System.IO.Path]::GetTempPath()
    }
    $script:UpdateTranscriptTempPath = Join-Path $tempRoot ("Update-GetHealthCode-{0}.transcript.log" -f [guid]::NewGuid().ToString())

    Start-Transcript -Path $script:UpdateTranscriptTempPath -Force -ErrorAction Stop | Out-Null
    $script:UpdateTranscriptStarted = $true
  } catch {
    $script:UpdateTranscriptStarted = $false
    $script:UpdateTranscriptTempPath = $null
    Write-Warning ("Failed to start transcript log in temp storage: {0}" -f $_.Exception.Message)
  }
}

function Stop-UpdateTranscript {
<#
.SYNOPSIS
Stops transcript logging for the updater when it was started.
#>
  [CmdletBinding()]
  param()

  if (-not $script:UpdateTranscriptStarted) {
    return
  }

  try {
    Stop-Transcript | Out-Null
  } catch {
    Write-Warning ("Failed to stop transcript log at {0}: {1}" -f $script:UPDATE_LOG_PATH, $_.Exception.Message)
  } finally {
    $script:UpdateTranscriptStarted = $false
  }
}

function Finalize-UpdateTranscript {
<#
.SYNOPSIS
Moves a completed updater transcript from temp storage into the log folder.
#>
  [CmdletBinding()]
  param()

  if ([string]::IsNullOrWhiteSpace($script:UpdateTranscriptTempPath)) {
    return
  }

  try {
    if (-not (Test-Path -LiteralPath $script:UpdateTranscriptTempPath -PathType Leaf)) {
      return
    }

    if (-not (Test-Path -LiteralPath $LOG_DIR -PathType Container)) {
      $null = New-Item -ItemType Directory -Path $LOG_DIR -Force
    }

    $timestampText = $script:UpdateTranscriptTimestamp.ToString('yyyy-MM-dd_HH.mm.ss')
    $script:UpdateTranscriptFinalPath = Join-Path $LOG_DIR ("Update-GetHealthCode-{0}.log" -f $timestampText)
    Move-Item -LiteralPath $script:UpdateTranscriptTempPath -Destination $script:UpdateTranscriptFinalPath -Force -ErrorAction Stop
  } catch {
    Write-Warning ("Failed to finalize transcript log from {0}: {1}" -f $script:UpdateTranscriptTempPath, $_.Exception.Message)
  } finally {
    $script:UpdateTranscriptTempPath = $null
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

  Write-Verbose "Ensuring NuGet package provider is available for PowerShellGet"
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $Scope -ErrorAction Stop | Out-Null
  Import-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null

  try {
    Write-Verbose "Installing PowerShell module '$Name' with scope '$Scope'"
    Install-Module -Name $Name -Scope $Scope -Force -Confirm:$false -ErrorAction Stop
    Write-Verbose "Successfully installed PowerShell module '$Name'"
  } catch {
    if ($_.Exception.Message -like "*No repository with the Name 'PSGallery'*") {
      Write-Warning "Registering PSGallery"
      Write-Verbose "Registering default PSRepository because PSGallery was missing"
      Register-PSRepository -Default -ErrorAction Stop
      Write-Verbose "Marking PSGallery as Trusted"
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
      Write-Verbose "Retrying installation of PowerShell module '$Name'"
      Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope $Scope -ErrorAction Stop | Out-Null
      Import-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop | Out-Null
      Install-Module -Name $Name -Scope $Scope -Force -Confirm:$false -ErrorAction Stop
      Write-Verbose "Successfully installed PowerShell module '$Name' after registering PSGallery"
    } else {
      throw
    }
  }
}

function New-RandomTempDirectoryPath {
<#
.SYNOPSIS
Returns an unused "$TempRoot\<Name>.<N>" path where N is between 0 and 9999.
.OUTPUTS
System.String. A currently unused temporary directory path.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$TempRoot,
    [Parameter(Mandatory)][string]$Name
  )

  for ($attempt = 0; $attempt -lt 100; $attempt++) {
    $suffix = Get-Random -Minimum 0 -Maximum 10000
    $candidate = Join-Path $TempRoot ("{0}.{1}" -f $Name, $suffix)
    if (-not (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue)) {
      return $candidate
    }
  }

  throw "Could not find an available temporary directory matching '$Name.<N>' under '$TempRoot' after 100 attempts."
}

function New-EmptyTempDirectory {
<#
.SYNOPSIS
Creates a reusable temporary directory and returns its full path.
.OUTPUTS
System.String. The full path of the created directory under $env:TEMP.
#>
  [CmdletBinding()]
  param([string]$Name)

  $tempRoot = $env:TEMP
  if ([string]::IsNullOrWhiteSpace($tempRoot)) {
    $tempRoot = [System.IO.Path]::GetTempPath()
  }

  $tmdDir = Join-Path $tempRoot $Name
  Write-Verbose "Preparing temporary directory '$tmdDir'"

  if (Test-Path -LiteralPath $tmdDir) {
    if (Test-Path -LiteralPath $tmdDir -PathType Container) {
      Write-Verbose "Temporary directory already exists; clearing its contents: '$tmdDir'"
      try {
        Get-ChildItem -LiteralPath $tmdDir -Recurse -Force -ErrorAction Stop |
          Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
      } catch {
        Write-Warning ("Could not clear temporary directory '{0}': {1}" -f $tmdDir, $_.Exception.Message)
        $tmdDir = New-RandomTempDirectoryPath -TempRoot $tempRoot -Name $Name
        Write-Verbose "Using alternate temporary directory '$tmdDir'"
      }
    } else {
      Write-Verbose "A file already exists at '$tmdDir'; generating a unique directory name"
      $tmdDir = New-RandomTempDirectoryPath -TempRoot $tempRoot -Name $Name
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

function ConvertTo-GetComputerHealthVersionToken {
<#
.SYNOPSIS
Normalizes a user-provided version string into the internal vX.Y.Z form.
.DESCRIPTION
Accepts versions like 1.2.3 or v1.2.3 and returns v1.2.3.
Returns null when no value was provided.
#>
  [CmdletBinding()]
  param([AllowNull()][string]$Version)

  if ([string]::IsNullOrWhiteSpace($Version)) {
    return $null
  }

  $trimmedVersion = $Version.Trim()
  $match = [regex]::Match($trimmedVersion, '^(?:v)?(?<Version>\d+\.\d+\.\d+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if (-not $match.Success) {
    throw "Invalid -Version value '$Version'. Use semantic version format X.Y.Z."
  }

  return ('v{0}' -f $match.Groups['Version'].Value)
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
    [Parameter(Mandatory)][string]$CacheDir,
    [string]$Version
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
  $zipTag = [System.IO.Path]::GetFileNameWithoutExtension($zipItem.Name)
  if ([string]::IsNullOrWhiteSpace($zipTag)) { $zipTag = 'manual' }
  $manualMarker = ("manual-zip|{0}|{1}" -f $zipTag, $zipHash)
  $markerVersionToken = Get-GetComputerHealthVersionFromMarker -Marker $manualMarker
  $requestedVersionToken = ConvertTo-GetComputerHealthVersionToken -Version $Version

  if (-not $markerVersionToken) {
    if (-not $requestedVersionToken) {
      throw "Manual update zip file name must embed a semver tag like 'v1.2.3' unless -Version '1.2.3' is supplied. Zip: $sourceFullPath"
    }
    $manualMarker = ("manual-zip|{0}|{1}" -f $requestedVersionToken, $zipHash)
  } elseif ($requestedVersionToken -and ($requestedVersionToken -ine $markerVersionToken)) {
    throw "Provided -Version '$Version' does not match the semver '$markerVersionToken' embedded in zip file name '$($zipItem.Name)'."
  }

  $cacheVersionToken = if ($markerVersionToken) { $markerVersionToken } else { $requestedVersionToken }
  $cachedZipPath = Join-Path $CacheDir ("GetComputerHealth-MANUAL-UPDATE-{0}-{1}.zip" -f $cacheVersionToken, $zipLastWriteToken)

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

function Get-NormalizedFileSystemPath {
<#
.SYNOPSIS
Returns a full filesystem path string suitable for path comparison.
.DESCRIPTION
Accepts existing and missing paths and removes trailing slashes.
Use it when Resolve-Path alone would reject paths that do not exist yet.
.OUTPUTS
System.String. A full path string without trailing slashes.
#>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  try {
    if (Test-Path -LiteralPath $Path) {
      return ((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path).TrimEnd('\','/')
    }
  } catch {
  }

  return ([System.IO.Path]::GetFullPath($Path)).TrimEnd('\','/')
}

function Get-GetComputerHealthScriptVersion {
<#
.SYNOPSIS
Returns the embedded semantic version from a script file when present.
.DESCRIPTION
Returns null when the file is missing or when no supported version
assignment is found. Writes a warning if the file exists but cannot be
read.
.OUTPUTS
System.String. A version like 4.1.3, or null when no version is
available.
#>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ScriptPath)

  if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    return $null
  }

  try {
    $content = Get-Content -LiteralPath $ScriptPath -Raw -ErrorAction Stop
    $match = [regex]::Match($content, '(?im)^\s*\$VERSION\s*=\s*["''](?<version>\d+\.\d+\.\d+)["'']')
    if ($match.Success) {
      return $match.Groups['version'].Value
    }
  } catch {
    Write-Warning ("Failed reading version from {0}: {1}" -f $ScriptPath, $_.Exception.Message)
  }

  return $null
}
#
#  HELPER FUNCTIONS END
#
####################################################################

####################################################################
#
#  MAIN CODE
#
$installConfig = ConvertTo-GchHashtable -Value $Config
if ($GenerateConfigPsd1) {
  $templatePath = Join-Path (Get-Location).Path 'GetComputerHealth.install.psd1'
  $writtenTemplatePath = Write-GchInstallConfigTemplate -Path $templatePath
  Write-UpdateEvent "Wrote installer configuration template '$writtenTemplatePath'"
  return
}

$configuredInstallDir = Get-GchInstallOption -InstallConfig $installConfig -Name 'InstallDir'
if (-not [string]::IsNullOrWhiteSpace([string]$configuredInstallDir)) {
  $ROOT_DIR = [System.IO.Path]::GetFullPath([string]$configuredInstallDir).TrimEnd('\','/')
  $DEST_DIR = Join-Path $ROOT_DIR 'bin'
  $SCRIPT_BIN_DIR = $DEST_DIR
} elseif ((Split-Path -Leaf $SCRIPT_BIN_DIR) -ieq 'bin') {
  $ROOT_DIR = Split-Path -Parent $SCRIPT_BIN_DIR
  $DEST_DIR = $SCRIPT_BIN_DIR
} else {
  throw "Refusing to run. Update-GetHealthCode.ps1 must be located in and executed from a 'bin' folder unless -Config Options.InstallDir is supplied. Current script location: '$SCRIPT_BIN_DIR'."
}

$BAK_DIR  = Join-Path $ROOT_DIR 'temp'
$CFG_DIR  = Join-Path $ROOT_DIR 'config'
$LOG_DIR  = Join-Path $ROOT_DIR 'log'
$GCH_CONFIG_PATH = Join-Path $CFG_DIR 'gch.psd1'
$LATEST_RELEASE_METADATA_CACHE_PATH = Join-Path $CFG_DIR 'Get-ComputerHealth-latest-release-meta.json'

Start-UpdateTranscript
try {
  $passNumber = $SelfRerunCount + 1
  $passLabel = "[pass $passNumber/2]"

  Write-Verbose "$passLabel Starting Update-GetHealthCode"
  Write-Verbose "$passLabel Parameters: Reinstall=$Reinstall UpdateFromZip='$UpdateFromZip' Version='$Version' ForceRefreshReleaseMetadata=$ForceRefreshReleaseMetadata ConfigSupplied=$($null -ne $Config) SelfRerunCount=$SelfRerunCount PersistReleaseMarker='$PersistReleaseMarker'"
  Write-UpdateEvent "$passLabel Parameters: Reinstall=$Reinstall UpdateFromZip='$UpdateFromZip' Version='$Version' ForceRefreshReleaseMetadata=$ForceRefreshReleaseMetadata ConfigSupplied=$($null -ne $Config) SelfRerunCount=$SelfRerunCount PersistReleaseMarker='$PersistReleaseMarker'"
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

  Write-GchConfigFilesFromInstallConfig -InstallConfig $installConfig -ConfigDirectory $CFG_DIR
  Ensure-GchConfigFile -Path $GCH_CONFIG_PATH -RepoUrl $REPO_URL -ShowAsPostponedWindowDays $SHOW_AS_POSTPONED_WINDOW_DAYS
  $gchConfig = Read-GchConfigFile -Path $GCH_CONFIG_PATH
  if (($null -eq $Config) -and (Test-GchConfigKey -Config $gchConfig -Key 'AutomaticUpdates') -and (Test-GchFalsyValue -Value (Get-GchConfigValue -Config $gchConfig -Key 'AutomaticUpdates'))) {
    Write-Warning "Automatic updates are disabled by '$GCH_CONFIG_PATH'. Update-GetHealthCode.ps1 will not make changes."
    return
  }
  if (Test-GchConfigKey -Config $gchConfig -Key 'RepoUrl') {
    $REPO_URL = Resolve-GchConfiguredRepoUrl -RepoUrl ([string](Get-GchConfigValue -Config $gchConfig -Key 'RepoUrl'))
  }
  if (Test-GchConfigKey -Config $gchConfig -Key 'ShowAsPostponedWindowDays') {
    $SHOW_AS_POSTPONED_WINDOW_DAYS = Resolve-GchConfiguredNonNegativeInteger -Value (Get-GchConfigValue -Config $gchConfig -Key 'ShowAsPostponedWindowDays') -Key 'ShowAsPostponedWindowDays'
  }
  $repoSlug = (($REPO_URL -replace '^https?://github\.com/','') -replace '\.git$','').Trim('/')
  Write-Verbose "Loaded Get-ComputerHealth configuration from '$GCH_CONFIG_PATH'"
  Write-Verbose "Configuration:"
  Write-Verbose "  DEST_DIR                    : $DEST_DIR"
  Write-Verbose "  BAK_DIR                     : $BAK_DIR"
  Write-Verbose "  CFG_DIR                     : $CFG_DIR"
  Write-Verbose "  GCH_CONFIG_PATH             : $GCH_CONFIG_PATH"
  Write-Verbose "  REPO_URL                    : $REPO_URL"
  Write-Verbose "  REPO_REF                    : $REPO_REF"
  Write-Verbose "  SHOW_AS_POSTPONED_WINDOW_DAYS : $SHOW_AS_POSTPONED_WINDOW_DAYS"
  Write-Verbose "  LATEST_RELEASE_METADATA_CACHE_PATH : $LATEST_RELEASE_METADATA_CACHE_PATH"
  Write-Verbose "  RELEASE_METADATA_CACHE_TTL_MINUTES : $RELEASE_METADATA_CACHE_TTL_MINUTES"
  Write-Verbose "  ZIP_CACHE_PATTERN           : $ZIP_CACHE_PATTERN"
  Write-Verbose "  MANUAL_ZIP_CACHE_PATTERN    : $MANUAL_ZIP_CACHE_PATTERN"
  Write-Verbose "  repoSlug                    : $repoSlug"

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
  $versionToInstall = $null
  if (-not $UpdateFromZip) {
    Write-Verbose "$passLabel Resolving latest release metadata (cache TTL $RELEASE_METADATA_CACHE_TTL_MINUTES minutes)"
    try {
      $latestRelease = Get-GetComputerHealthLatestRelease -RepositoryUrl $REPO_URL -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH -CacheTtlMinutes $RELEASE_METADATA_CACHE_TTL_MINUTES -ForceRefresh:$ForceRefreshReleaseMetadata
      $latestReleaseMarker = Convert-GetComputerHealthReleaseToMarker -RepositoryUrl $REPO_URL -Release $latestRelease
      $versionToInstall = Get-GetComputerHealthVersionFromMarker -Marker $latestReleaseMarker
      Write-Verbose "$passLabel Latest release marker is '$latestReleaseMarker'"
      Write-UpdateEvent "$passLabel Latest release marker is '$latestReleaseMarker'"
    } catch {
      Write-Warning ("Could not query latest release metadata from {0}: {1}" -f $REPO_URL, $_.Exception.Message)
    }
  } else {
    Write-Verbose "-UpdateFromZip specified; skipping latest release marker query"
    $manualUpdateZip = Prepare-ManualUpdateZip -ZipPath $UpdateFromZip -CacheDir $BAK_DIR -Version $Version
    $manualUpdateMarker = [string]$manualUpdateZip.ManualMarker
    $manualUpdateFetchedAt = [string]$manualUpdateZip.ZipLastWriteTimeIso
    $versionToInstall = Get-GetComputerHealthVersionFromMarker -Marker $manualUpdateMarker
    Write-Verbose "Manual update marker is '$manualUpdateMarker'"
    Write-Verbose "Manual update fetchedAt is '$manualUpdateFetchedAt'"
  }

  if ($latestReleaseMarker) {
    if (-not $versionToInstall) {
      throw "Could not determine a valid semver-like versionToInstall from latest release marker '$latestReleaseMarker'. Aborting update."
    }

    $storedReleaseMarker = Get-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH

    if ($storedReleaseMarker) {
      Write-Verbose "Stored installed release marker is '$storedReleaseMarker'"
      Write-UpdateEvent "Stored installed release marker is '$storedReleaseMarker'"
    } else {
      Write-Verbose "No stored installed release marker is available yet"
    }

    if (($SelfRerunCount -eq 0) -and (-not $Reinstall) -and $storedReleaseMarker -and (Test-GetComputerHealthMarkerEquivalent -LeftMarker $storedReleaseMarker -RightMarker $latestReleaseMarker)) {
      $storedVersion = Get-GetComputerHealthVersionFromMarker -Marker $storedReleaseMarker
      if (($storedReleaseMarker -ne $latestReleaseMarker) -and $storedVersion -and $versionToInstall -and ($storedVersion -ieq $versionToInstall)) {
        Write-Verbose "Installed marker came from a different source but matches latest version '$versionToInstall'; skipping update download"
        Write-UpdateEvent "Installed marker came from a different source but matches latest version '$versionToInstall'; skipping update download"
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
    if (-not $versionToInstall) {
      throw "Could not determine a valid semver-like versionToInstall from manual update marker '$manualUpdateMarker'. Aborting update."
    }

    $storedReleaseMarker = Get-GetComputerHealthInstalledReleaseMarker -CachePath $LATEST_RELEASE_METADATA_CACHE_PATH

    if ($storedReleaseMarker) {
      Write-Verbose "Stored installed release marker is '$storedReleaseMarker'"
      Write-UpdateEvent "Stored installed release marker is '$storedReleaseMarker'"
    } else {
      Write-Verbose "No stored installed release marker is available yet"
    }

    if (($SelfRerunCount -eq 0) -and (-not $Reinstall) -and $storedReleaseMarker -and (Test-GetComputerHealthMarkerEquivalent -LeftMarker $storedReleaseMarker -RightMarker $manualUpdateMarker)) {
      $storedVersion = Get-GetComputerHealthVersionFromMarker -Marker $storedReleaseMarker
      if (($storedReleaseMarker -ne $manualUpdateMarker) -and $storedVersion -and $versionToInstall -and ($storedVersion -ieq $versionToInstall)) {
        Write-Verbose "Provided zip matches already installed version '$versionToInstall' even though the source marker differs; skipping update"
        Write-UpdateEvent "Provided zip matches already installed version '$versionToInstall' even though the source marker differs; skipping update"
      } else {
        Write-Verbose "Provided zip marker already installed and -Reinstall was not specified; skipping update"
        Write-UpdateEvent "Provided zip marker already installed and -Reinstall was not specified; skipping update"
      }
      return
    }
  } else {
    throw "$passLabel Could not determine a valid semver-like versionToInstall because no release marker is available. Aborting update."
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
  $diskFormatMigration = Invoke-DiskFormatMigrations -RootDir $ROOT_DIR -ReleaseRoot $releaseRoot -TargetCodeVersion $versionToInstall
  if ($diskFormatMigration.RanMigrations -and (-not [string]::IsNullOrWhiteSpace($diskFormatMigration.UpdaterPath))) {
    $currentUpdaterPath = Get-NormalizedFileSystemPath -Path $PSCommandPath
    $migrationUpdaterPath = Get-NormalizedFileSystemPath -Path ([string]$diskFormatMigration.UpdaterPath)
    if ($migrationUpdaterPath -ine $currentUpdaterPath) {
      $expectedDestinationUpdaterPath = Get-NormalizedFileSystemPath -Path (Join-Path $DEST_DIR 'Update-GetHealthCode.ps1')
      if (-not (Test-Path -LiteralPath $migrationUpdaterPath -PathType Leaf)) {
        if ($migrationUpdaterPath -ieq $expectedDestinationUpdaterPath) {
          Write-Verbose "$passLabel Disk format migration returned destination updater path '$migrationUpdaterPath' before that file was staged; continuing with normal update flow."
        } else {
          throw "Disk format migration returned updater path '$migrationUpdaterPath', but that file does not exist."
        }
      } else {
        Write-Verbose "$passLabel Running updater returned by disk format migration: '$migrationUpdaterPath'"
        Stop-UpdateTranscript
        & $migrationUpdaterPath @PSBoundParameters
        return
      }
    }
  }

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
    if ($preparedZipPath -and $UpdateFromZip) {
      $rerunParameters['UpdateFromZip'] = $preparedZipPath
    }
    if ($latestReleaseMarker) {
      $rerunParameters['PersistReleaseMarker'] = $latestReleaseMarker
    }

    Write-Verbose "$passLabel Rerunning updated copy '$rerunPath' with one-time self-rerun guard"
    Stop-UpdateTranscript
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
} finally {
  Stop-UpdateTranscript
  Finalize-UpdateTranscript
}
