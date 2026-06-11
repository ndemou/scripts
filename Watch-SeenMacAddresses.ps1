<#
.SYNOPSIS
Records MAC,IP addresses observed in the local IPv4 neighbor cache.

.DESCRIPTION
The script keeps a running inventory of observed MAC addresses, with first
seen time, last seen time, and the IPv4 addresses seen for each MAC.

It is intended for passive local-link observation. It does not scan the
network and should not be used as proof that all devices in a VLAN were
found.

The output file is created or replaced as a PowerShell data file. The
parent directory is created when needed. If the script stops normally or is
interrupted, it attempts one final write. A terminating error can leave the
latest observations not written, and may leave a temporary file beside the
target file.

.OUTPUTS
Produces no pipeline output.

Creates or updates a PSD1 file containing:
  GeneratedAt : Timestamp of the file generation.
  SeenMACs    : List of records, one per MAC,IP address pair.
    MAC                : MAC address.
    IP                 : IPv4 address.
    FirstSeenTimestamp : First time this MAC,IP was observed.
    LastSeenTimestamp  : Most recent time this MAC,IP was observed.

.PARAMETER OutputPath
Path of the PSD1 inventory file to create or update.

.PARAMETER PollSeconds
Number of seconds between neighbor-cache observations.

.PARAMETER IdleWriteSeconds
Maximum seconds between writes when no new MAC or IP has been observed.

.PARAMETER ActiveWriteSeconds
Maximum seconds between writes while new MAC or IP observations exist.

.EXAMPLE
.\Watch-SeenMacAddresses.ps1

Starts passive observation and writes to the default PSD1 path.

.EXAMPLE
.\Watch-SeenMacAddresses.ps1 -PollSeconds 15 -ActiveWriteSeconds 30

Polls every 15 seconds and writes changed data at most every 30 seconds.
#>

#requires -Version 5.1

param(
    [string]$OutputPath = 'C:\it\log\seen_MAC_addresses.psd1',
    [int]$PollSeconds = 15,
    [int]$IdleWriteSeconds = 420,
    [int]$ActiveWriteSeconds = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


<#
.SYNOPSIS
Normalizes a MAC address for inventory use.

.OUTPUTS
Produces a string when the value is a usable unicast-like MAC address:
  The MAC address in uppercase hyphen-separated form.

Produces null when the value is blank, malformed, all zeros, broadcast, or
an IPv4 multicast MAC pattern.

.PARAMETER MacAddress
MAC address text to validate and normalize.
#>
function Normalize-MacAddress {
    param([string]$MacAddress)

    if ([string]::IsNullOrWhiteSpace($MacAddress)) {
        return $null
    }

    $normalized = $MacAddress.Trim().ToUpperInvariant() -replace ':', '-'

    if ($normalized -notmatch '^[0-9A-F]{2}(-[0-9A-F]{2}){5}$') {
        return $null
    }

    if ($normalized -eq '00-00-00-00-00-00') {
        return $null
    }

    if ($normalized -eq 'FF-FF-FF-FF-FF-FF') {
        return $null
    }

    if ($normalized -like '01-00-5E-*') {
        return $null
    }

    return $normalized
}


<#
.SYNOPSIS
Tests whether a value is a usable unicast IPv4 address for inventory use.

.OUTPUTS
Produces a Boolean:
  True  : The value is IPv4 and not in excluded first-octet ranges.
  False : The value is not IPv4 or is in an excluded range.

.PARAMETER IPAddress
Address text to evaluate.
#>
function Test-UnicastIPv4Address {
    param([string]$IPAddress)

    $parsedAddress = $null

    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsedAddress)) {
        return $false
    }

    if ($parsedAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $bytes = $parsedAddress.GetAddressBytes()
    $firstOctet = [int]$bytes[0]

    if ($firstOctet -eq 0) {
        return $false
    }

    if ($firstOctet -ge 224) {
        return $false
    }

    return $true
}


<#
.SYNOPSIS
Creates a new in-memory record for one observed MAC address.

.OUTPUTS
Produces an ordered hashtable:
  MAC                : The MAC address for the record.
  FirstSeenTimestamp : Timestamp assigned as the first observation time.
  LastSeenTimestamp  : Timestamp assigned as the latest observation time.
  IPs                : Empty hashtable used to hold observed IPv4 addresses.

.PARAMETER MacAddress
MAC address represented by the record.

.PARAMETER Timestamp
Timestamp to assign to both first seen and last seen.
#>
function New-SeenMacRecord {
    param(
        [string]$MacAddress,
        [datetime]$Timestamp
    )

    return [ordered]@{
        MAC = $MacAddress
        FirstSeenTimestamp = $Timestamp
        LastSeenTimestamp = $Timestamp
        IPs = @{}
    }
}


<#
.SYNOPSIS
Returns current usable IPv4 neighbor-cache observations.

.DESCRIPTION
Use this when the caller needs inventory-oriented observations rather than
raw neighbor-cache entries. Entries that are not useful for MAC/IP inventory
are not returned.

.OUTPUTS
Produces a psCustomObject for each usable current observation:
  MAC            : Normalized MAC address.
  IP             : IPv4 address observed for the MAC.
  State          : Neighbor-cache state as text.
  InterfaceAlias : Interface where the observation exists.
#>
function Get-CurrentArpEntries {
    $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue)

    foreach ($neighbor in $neighbors) {
        if ($neighbor.State -eq 'Incomplete') {
            continue
        }

        if ($neighbor.State -eq 'Unreachable') {
            continue
        }

        $macAddress = Normalize-MacAddress -MacAddress $neighbor.LinkLayerAddress

        if (-not $macAddress) {
            continue
        }

        $ipAddress = [string]$neighbor.IPAddress

        if (-not (Test-UnicastIPv4Address -IPAddress $ipAddress)) {
            continue
        }

        [pscustomobject]@{
            MAC = $macAddress
            IP = $ipAddress
            State = [string]$neighbor.State
            InterfaceAlias = [string]$neighbor.InterfaceAlias
        }
    }
}


# Formats a string value as a PSD1 single-quoted string expression.
function ConvertTo-Psd1String {
    param([string]$Value)

    return "'" + ($Value -replace "'", "''") + "'"
}


# Formats string values as a PSD1 array expression.
function ConvertTo-Psd1StringArray {
    param([string[]]$Values)

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    if ($items.Count -eq 0) {
        return '@()'
    }

    $quotedItems = @($items | ForEach-Object { ConvertTo-Psd1String -Value $_ })
    return '@(' + ($quotedItems -join ', ') + ')'
}


# Converts a value to DateTime, or returns a supplied default.
function ConvertTo-DateTimeOrDefault {
    param(
        [object]$Value,
        [datetime]$DefaultValue
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    try {
        return [datetime]::Parse(
            [string]$Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
    } catch {
        return $DefaultValue
    }
}


<#
.SYNOPSIS
Loads an existing seen-MAC PSD1 inventory file.

.DESCRIPTION
Returns an in-memory inventory suitable for continued observation. Missing
files, files without a SeenMACs key, and invalid records result in no record
for the invalid or missing data.

Invalid MAC addresses are ignored. Invalid timestamps are replaced with the
current time. Invalid IP addresses are ignored.

.OUTPUTS
Produces a hashtable keyed by MAC address. Each value is an ordered
hashtable:
  MAC                : Normalized MAC address.
  FirstSeenTimestamp : Loaded or defaulted first observation time.
  LastSeenTimestamp  : Loaded or defaulted latest observation time.
  IPs                : Hashtable of observed IPv4 addresses.

.PARAMETER Path
Path of the PSD1 inventory file to load.
#>
function Import-SeenMacFile {
    param([string]$Path)

    $seenMacs = @{}

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $seenMacs
    }

    $now = Get-Date
    $data = Import-PowerShellDataFile -LiteralPath $Path

    if (-not $data.ContainsKey('SeenMACs')) {
        return $seenMacs
    }

    foreach ($item in @($data['SeenMACs'])) {
        if ($null -eq $item) {
            continue
        }

        $macAddress = Normalize-MacAddress -MacAddress ([string]$item['MAC'])

        if (-not $macAddress) {
            continue
        }

        $record = New-SeenMacRecord -MacAddress $macAddress -Timestamp $now
        $record['FirstSeenTimestamp'] = ConvertTo-DateTimeOrDefault -Value $item['FirstSeenTimestamp'] -DefaultValue $now
        $record['LastSeenTimestamp'] = ConvertTo-DateTimeOrDefault -Value $item['LastSeenTimestamp'] -DefaultValue $now

        foreach ($ipAddress in @($item['IPs'])) {
            if (Test-UnicastIPv4Address -IPAddress ([string]$ipAddress)) {
                $record['IPs'][[string]$ipAddress] = $true
            }
        }

        $seenMacs[$macAddress] = $record
    }

    return $seenMacs
}


<#
.SYNOPSIS
Writes the seen-MAC inventory to a PSD1 file.

.DESCRIPTION
Writes the supplied inventory as a PowerShell data file. The parent
directory is created when needed. The target file is created or replaced.

A terminating error can leave the target file not updated and may leave a
temporary file beside the target path.

.OUTPUTS
Produces no pipeline output.

Writes status text to the host.

.PARAMETER SeenMacs
Inventory hashtable keyed by MAC address.

.PARAMETER Path
Path of the PSD1 file to create or replace.
#>
function Write-SeenMacFile {
    param(
        [hashtable]$SeenMacs,
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)

    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $generatedAt = (Get-Date).ToString('o')

    $lines.Add('@{')
    $lines.Add("    GeneratedAt = $(ConvertTo-Psd1String -Value $generatedAt)")
    $lines.Add('    SeenMACs = @(')

    $records = @(
        $SeenMacs.GetEnumerator() |
            Sort-Object Name |
            ForEach-Object { $_.Value }
    )

    foreach ($record in $records) {
        $macAddress = [string]$record['MAC']
        $firstSeen = ([datetime]$record['FirstSeenTimestamp']).ToString('o')
        $lastSeen = ([datetime]$record['LastSeenTimestamp']).ToString('o')
        $ipList = ConvertTo-Psd1StringArray -Values @($record['IPs'].Keys)

        $lines.Add('        @{')
        $lines.Add("            MAC = $(ConvertTo-Psd1String -Value $macAddress)")
        $lines.Add("            FirstSeenTimestamp = $(ConvertTo-Psd1String -Value $firstSeen)")
        $lines.Add("            LastSeenTimestamp = $(ConvertTo-Psd1String -Value $lastSeen)")
        $lines.Add("            IPs = $ipList")
        $lines.Add('        }')
    }

    $lines.Add('    )')
    $lines.Add('}')

    $temporaryPath = $fullPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $backupPath = $fullPath + '.' + [guid]::NewGuid().ToString('N') + '.bak'

    Set-Content -LiteralPath $temporaryPath -Value $lines -Encoding UTF8

    try {
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            [System.IO.File]::Replace($temporaryPath, $fullPath, $backupPath)

            if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
                Remove-Item -LiteralPath $backupPath -Force
            }
        } else {
            [System.IO.File]::Move($temporaryPath, $fullPath)
        }
    } catch {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }

        throw
    }

    Write-Host ("{0} Wrote {1} MAC entries to {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $SeenMacs.Count, $fullPath)
}


if ($PollSeconds -lt 1) {
    throw "PollSeconds must be at least 1."
}

if ($IdleWriteSeconds -lt 1) {
    throw "IdleWriteSeconds must be at least 1."
}

if ($ActiveWriteSeconds -lt 1) {
    throw "ActiveWriteSeconds must be at least 1."
}

$seenMacs = Import-SeenMacFile -Path $OutputPath
$lastWriteTimestamp = (Get-Date).AddSeconds(-$ActiveWriteSeconds)
$newDataSinceLastWrite = $false

Write-Host ("Loaded {0} existing MAC entries." -f $seenMacs.Count)
Write-Host ("Polling every {0}s. Writing to {1}" -f $PollSeconds, $OutputPath)

try {
    while ($true) {
        $now = Get-Date
        $entries = @(Get-CurrentArpEntries)

        foreach ($entry in $entries) {
            $macAddress = [string]$entry.MAC
            $ipAddress = [string]$entry.IP

            if (-not $seenMacs.ContainsKey($macAddress)) {
                $seenMacs[$macAddress] = New-SeenMacRecord -MacAddress $macAddress -Timestamp $now
                $newDataSinceLastWrite = $true
            }

            $record = $seenMacs[$macAddress]
            $record['LastSeenTimestamp'] = $now

            if (-not $record['IPs'].ContainsKey($ipAddress)) {
                $record['IPs'][$ipAddress] = $true
                $newDataSinceLastWrite = $true
            }
        }

        $secondsSinceLastWrite = ($now - $lastWriteTimestamp).TotalSeconds

        if ($newDataSinceLastWrite -and $secondsSinceLastWrite -ge $ActiveWriteSeconds) {
            Write-SeenMacFile -SeenMacs $seenMacs -Path $OutputPath
            $lastWriteTimestamp = Get-Date
            $newDataSinceLastWrite = $false
        } elseif ((-not $newDataSinceLastWrite) -and $secondsSinceLastWrite -ge $IdleWriteSeconds) {
            Write-SeenMacFile -SeenMacs $seenMacs -Path $OutputPath
            $lastWriteTimestamp = Get-Date
        }

        Start-Sleep -Seconds $PollSeconds
    }
} finally {
    Write-SeenMacFile -SeenMacs $seenMacs -Path $OutputPath
}