<#
.SYNOPSIS
Records MAC,IP address pairs observed in the local IPv4 neighbor cache.

.DESCRIPTION
The script keeps a running inventory of observed MAC,IP address pairs, with
first seen time and last seen time for each pair.

It is intended for passive local-link observation. It does not scan the
network and should not be used as proof that all devices in a VLAN were
found.

The output file is created or replaced as a PowerShell CLIXML file. The
parent directory is created when needed. If the script stops normally or is
interrupted, it attempts one final write. A terminating error can leave the
latest observations not written, and may leave a temporary file beside the
target file.

.OUTPUTS
Produces no pipeline output.

Creates or updates a CLIXML file containing:
  GeneratedAt : Timestamp of the file generation.
  SeenMACs    : List of records, one per MAC,IP address pair.
    MAC                : MAC address.
    IP                 : IPv4 address.
    FirstSeenTimestamp : First time this MAC,IP pair was observed.
    LastSeenTimestamp  : Most recent time this MAC,IP pair was observed.

.PARAMETER OutputPath
Path of the CLIXML inventory file to create or update.

.PARAMETER PollSeconds
Number of seconds between neighbor-cache observations.

.PARAMETER IdleWriteSeconds
Maximum seconds between writes when no new MAC,IP pair has been observed.

.PARAMETER ActiveWriteSeconds
Maximum seconds between writes while new MAC,IP pair observations exist.

.EXAMPLE
.\Watch-SeenMacAddresses.ps1

Starts passive observation and writes to the default CLIXML path.

.EXAMPLE
.\Watch-SeenMacAddresses.ps1 -PollSeconds 15 -ActiveWriteSeconds 30

Polls every 15 seconds and writes changed data at most every 30 seconds.
#>

#requires -Version 5.1

param(
    [string]$OutputPath = 'C:\it\log\seen_MAC_addresses.clixml',
    [int]$PollSeconds = 15,
    [int]$IdleWriteSeconds = 420,
    [int]$ActiveWriteSeconds = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


<#
.SYNOPSIS
Normalizes a MAC address for inventory use.

.DESCRIPTION
Returns a consistent uppercase hyphen-separated MAC address when the input
is usable for this inventory. Values that are blank, malformed, all zeros,
broadcast, or IPv4 multicast MAC patterns are rejected.

.OUTPUTS
Produces a string when the value is valid.

Produces null when the value is not usable.

.PARAMETER MacAddress
MAC address text to validate and normalize.

.EXAMPLE
Normalize-MacAddress -MacAddress '00:15:5d:00:19:09'

Returns:

00-15-5D-00-19-09
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

.DESCRIPTION
Returns true only for IPv4 addresses that are useful for this inventory.
Non-IPv4 values, 0.x.x.x values, and multicast/reserved 224.x.x.x or higher
values are rejected.

.OUTPUTS
Produces a Boolean:
  True  : The value is IPv4 and not in excluded first-octet ranges.
  False : The value is not IPv4 or is in an excluded range.

.PARAMETER IPAddress
Address text to evaluate.

.EXAMPLE
Test-UnicastIPv4Address -IPAddress '10.30.0.5'

Returns true.
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
Creates a stable key for one MAC,IP pair.

.DESCRIPTION
The returned key is used only internally by the script to deduplicate
observations. The file output still stores MAC and IP as separate fields.

.OUTPUTS
Produces a string key.

.PARAMETER MacAddress
Normalized MAC address.

.PARAMETER IPAddress
IPv4 address.

.EXAMPLE
New-SeenMacPairKey -MacAddress '00-15-5D-00-19-09' -IPAddress '10.30.0.5'

Returns:

00-15-5D-00-19-09|10.30.0.5
#>
function New-SeenMacPairKey {
    param(
        [string]$MacAddress,
        [string]$IPAddress
    )

    return ('{0}|{1}' -f $MacAddress, $IPAddress)
}


<#
.SYNOPSIS
Creates a new in-memory record for one observed MAC,IP pair.

.DESCRIPTION
Creates the canonical in-memory representation used by the script.

.OUTPUTS
Produces an ordered hashtable:
  MAC                : MAC address.
  IP                 : IPv4 address.
  FirstSeenTimestamp : Timestamp assigned as the first observation time.
  LastSeenTimestamp  : Timestamp assigned as the latest observation time.

.PARAMETER MacAddress
MAC address represented by the record.

.PARAMETER IPAddress
IPv4 address represented by the record.

.PARAMETER Timestamp
Timestamp to assign to both first seen and last seen.

.EXAMPLE
New-SeenMacRecord -MacAddress '00-15-5D-00-19-09' -IPAddress '10.30.0.5' -Timestamp (Get-Date)

Creates a new record for that MAC,IP pair.
#>
function New-SeenMacRecord {
    param(
        [string]$MacAddress,
        [string]$IPAddress,
        [datetime]$Timestamp
    )

    return [ordered]@{
        MAC = $MacAddress
        IP = $IPAddress
        FirstSeenTimestamp = $Timestamp
        LastSeenTimestamp = $Timestamp
    }
}


<#
.SYNOPSIS
Returns current usable IPv4 neighbor-cache observations.

.DESCRIPTION
Use this when the caller needs inventory-oriented observations rather than
raw neighbor-cache entries. Entries that are not useful for MAC/IP inventory
are not returned.

Neighbor-cache entries in Incomplete or Unreachable state are ignored.
Malformed MAC addresses, broadcast MAC addresses, all-zero MAC addresses,
IPv4 multicast MAC patterns, and unusable IPv4 addresses are ignored.

.OUTPUTS
Produces a psCustomObject for each usable current observation:
  MAC            : Normalized MAC address.
  IP             : IPv4 address observed for the MAC.
  State          : Neighbor-cache state as text.
  InterfaceAlias : Interface where the observation exists.

.EXAMPLE
Get-CurrentArpEntries

Returns the current usable MAC,IP observations from the local IPv4 neighbor
cache.
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


<#
.SYNOPSIS
Reads a named value from an imported object.

.DESCRIPTION
Supports both hashtable-like objects and normal/deserialized PowerShell
objects. This is useful because CLIXML import returns deserialized objects,
while older or manually constructed data may contain dictionaries.

.OUTPUTS
Produces the value when found.

Produces null when the value is not found.

.PARAMETER Item
Object to inspect.

.PARAMETER Name
Property or dictionary key to read.

.EXAMPLE
Get-InventoryValue -Item $record -Name 'MAC'

Returns the MAC value if it exists.
#>
function Get-InventoryValue {
    param(
        [object]$Item,
        [string]$Name
    )

    if ($null -eq $Item) {
        return $null
    }

    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Name)) {
            return $Item[$Name]
        }

        if ($Item.ContainsKey($Name)) {
            return $Item[$Name]
        }

        return $null
    }

    $property = $Item.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}


<#
.SYNOPSIS
Converts a value to DateTime, or returns a supplied default.

.DESCRIPTION
Accepts DateTime values and timestamp strings. String values are parsed
using invariant culture and round-trip date/time style.

.OUTPUTS
Produces a DateTime value.

.PARAMETER Value
Value to convert.

.PARAMETER DefaultValue
DateTime value to return when conversion fails.

.EXAMPLE
ConvertTo-DateTimeOrDefault -Value '2026-06-10T19:42:59.6605579+03:00' -DefaultValue (Get-Date)

Returns the parsed DateTime value when parsing succeeds.
#>
function ConvertTo-DateTimeOrDefault {
    param(
        [object]$Value,
        [datetime]$DefaultValue
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    if ($Value -is [datetime]) {
        return [datetime]$Value
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
Adds or merges one MAC,IP record into the in-memory inventory.

.DESCRIPTION
Adds a record when the MAC,IP pair is new. If the same MAC,IP pair already
exists, the earliest FirstSeenTimestamp and latest LastSeenTimestamp are
kept.

Invalid MAC or IP values are ignored.

.OUTPUTS
Produces no pipeline output.

.PARAMETER SeenMacs
Inventory hashtable keyed by internal MAC,IP pair key.

.PARAMETER MacAddress
MAC address for the record.

.PARAMETER IPAddress
IPv4 address for the record.

.PARAMETER FirstSeenTimestamp
First observed timestamp.

.PARAMETER LastSeenTimestamp
Last observed timestamp.

.EXAMPLE
Add-SeenMacRecord -SeenMacs $seenMacs -MacAddress '00-15-5D-00-19-09' -IPAddress '10.30.0.5' -FirstSeenTimestamp (Get-Date) -LastSeenTimestamp (Get-Date)

Adds or updates that pair in the inventory.
#>
function Add-SeenMacRecord {
    param(
        [hashtable]$SeenMacs,
        [string]$MacAddress,
        [string]$IPAddress,
        [datetime]$FirstSeenTimestamp,
        [datetime]$LastSeenTimestamp
    )

    $normalizedMacAddress = Normalize-MacAddress -MacAddress $MacAddress

    if (-not $normalizedMacAddress) {
        return
    }

    if (-not (Test-UnicastIPv4Address -IPAddress $IPAddress)) {
        return
    }

    $normalizedIpAddress = [string]$IPAddress
    $key = New-SeenMacPairKey -MacAddress $normalizedMacAddress -IPAddress $normalizedIpAddress

    if (-not $SeenMacs.ContainsKey($key)) {
        $SeenMacs[$key] = New-SeenMacRecord -MacAddress $normalizedMacAddress -IPAddress $normalizedIpAddress -Timestamp $FirstSeenTimestamp
        $SeenMacs[$key]['LastSeenTimestamp'] = $LastSeenTimestamp
        return
    }

    $record = $SeenMacs[$key]

    if ($FirstSeenTimestamp -lt [datetime]$record['FirstSeenTimestamp']) {
        $record['FirstSeenTimestamp'] = $FirstSeenTimestamp
    }

    if ($LastSeenTimestamp -gt [datetime]$record['LastSeenTimestamp']) {
        $record['LastSeenTimestamp'] = $LastSeenTimestamp
    }
}


<#
.SYNOPSIS
Loads an existing seen-MAC CLIXML inventory file.

.DESCRIPTION
Returns an in-memory inventory suitable for continued observation. Missing
files, files without a SeenMACs property, and invalid records result in no
record for the invalid or missing data.

Invalid MAC addresses are ignored. Invalid IP addresses are ignored. Invalid
timestamps are replaced with the current time.

The importer expects the current CLIXML shape:

  GeneratedAt
  SeenMACs
    MAC
    IP
    FirstSeenTimestamp
    LastSeenTimestamp

.OUTPUTS
Produces a hashtable keyed by internal MAC,IP pair key. Each value is an
ordered hashtable:
  MAC                : Normalized MAC address.
  IP                 : IPv4 address.
  FirstSeenTimestamp : Loaded or defaulted first observation time.
  LastSeenTimestamp  : Loaded or defaulted latest observation time.

.PARAMETER Path
Path of the CLIXML inventory file to load.

.EXAMPLE
Import-SeenMacFile -Path 'C:\it\log\seen_MAC_addresses.clixml'

Loads the inventory if the file exists.
#>
function Import-SeenMacFile {
    param([string]$Path)

    $seenMacs = @{}

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $seenMacs
    }

    $now = Get-Date

    try {
        $data = Import-Clixml -LiteralPath $Path
    } catch {
        throw "Could not read existing CLIXML inventory file '$Path'. Use another OutputPath or fix/remove the existing file. Original error: $($_.Exception.Message)"
    }

    $items = Get-InventoryValue -Item $data -Name 'SeenMACs'

    if ($null -eq $items) {
        return $seenMacs
    }

    foreach ($item in @($items)) {
        if ($null -eq $item) {
            continue
        }

        $macAddress = Normalize-MacAddress -MacAddress ([string](Get-InventoryValue -Item $item -Name 'MAC'))

        if (-not $macAddress) {
            continue
        }

        $ipAddress = [string](Get-InventoryValue -Item $item -Name 'IP')

        if (-not (Test-UnicastIPv4Address -IPAddress $ipAddress)) {
            continue
        }

        $firstSeenTimestamp = ConvertTo-DateTimeOrDefault -Value (Get-InventoryValue -Item $item -Name 'FirstSeenTimestamp') -DefaultValue $now
        $lastSeenTimestamp = ConvertTo-DateTimeOrDefault -Value (Get-InventoryValue -Item $item -Name 'LastSeenTimestamp') -DefaultValue $now

        Add-SeenMacRecord -SeenMacs $seenMacs -MacAddress $macAddress -IPAddress $ipAddress -FirstSeenTimestamp $firstSeenTimestamp -LastSeenTimestamp $lastSeenTimestamp
    }

    return $seenMacs
}


<#
.SYNOPSIS
Writes the seen-MAC inventory to a CLIXML file.

.DESCRIPTION
Writes the supplied inventory as a PowerShell CLIXML file. The parent
directory is created when needed. The target file is created or replaced.

The write is staged through a temporary file beside the target path. If the
target already exists, it is replaced through System.IO.File.Replace. If the
target does not exist, the temporary file is moved into place.

A terminating error can leave the target file not updated and may leave a
temporary file beside the target path.

.OUTPUTS
Produces no pipeline output.

Writes status text to the host.

.PARAMETER SeenMacs
Inventory hashtable keyed by internal MAC,IP pair key.

.PARAMETER Path
Path of the CLIXML file to create or replace.

.EXAMPLE
Write-SeenMacFile -SeenMacs $seenMacs -Path 'C:\it\log\seen_MAC_addresses.clixml'

Writes the current inventory to CLIXML.
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

    $records = @(
        $SeenMacs.GetEnumerator() |
            Sort-Object Name |
            ForEach-Object {
                $record = $_.Value

                [pscustomobject][ordered]@{
                    MAC = [string]$record['MAC']
                    IP = [string]$record['IP']
                    FirstSeenTimestamp = ([datetime]$record['FirstSeenTimestamp']).ToString('o')
                    LastSeenTimestamp = ([datetime]$record['LastSeenTimestamp']).ToString('o')
                }
            }
    )

    $data = [pscustomobject][ordered]@{
        GeneratedAt = (Get-Date).ToString('o')
        SeenMACs = $records
    }

    $temporaryPath = $fullPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $backupPath = $fullPath + '.' + [guid]::NewGuid().ToString('N') + '.bak'

    $data | Export-Clixml -LiteralPath $temporaryPath -Depth 5 -Encoding UTF8

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

    Write-Host ("{0} Wrote {1} MAC,IP entries to {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $SeenMacs.Count, $fullPath)
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

Write-Host ("Loaded {0} existing MAC,IP entries." -f $seenMacs.Count)
Write-Host ("Polling every {0}s. Writing to {1}" -f $PollSeconds, $OutputPath)

try {
    while ($true) {
        $now = Get-Date
        $entries = @(Get-CurrentArpEntries)

        foreach ($entry in $entries) {
            $macAddress = [string]$entry.MAC
            $ipAddress = [string]$entry.IP
            $key = New-SeenMacPairKey -MacAddress $macAddress -IPAddress $ipAddress

            if (-not $seenMacs.ContainsKey($key)) {
                $seenMacs[$key] = New-SeenMacRecord -MacAddress $macAddress -IPAddress $ipAddress -Timestamp $now
                $newDataSinceLastWrite = $true
                continue
            }

            $record = $seenMacs[$key]
            $record['LastSeenTimestamp'] = $now
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