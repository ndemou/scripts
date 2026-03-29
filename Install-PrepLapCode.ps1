<#
Only relevant to mazars (Install/Update mazars-prepare-laptop-code)
#>

#==========================================================================
#
# CONFIGURATION
#
    $SOURCE_DIR = "\\mazars-gr.local\NETLOGON\IT-scripts\prepare-laptop"
    $DEST_DIR = "C:\IT\bin"
    $MAIN_PREPLAPTOP_SCRIPT = "$DEST_DIR\mazars-prepare-laptop-code.ps1"
    $MAZARS_LAN = '10.30.0.0/16'
#
#==========================================================================


function Test-ShareLikelyUp {
<#
.SYNOPSIS
Quickly tests whether a UNC share host is LIKELY reachable over SMB.

.DESCRIPTION
Parses the host from a UNC share path, optionally verifies that at least one configured DNS server falls within an expected CIDR range, resolves the host to IPv4 and/or IPv6 addresses, and tests whether any resolved address accepts a TCP connection on port 445 within a short timeout.

This is a FAST reachability test, not a definitive share-access test. A positive result means the host likely has SMB available. It does not prove that the share exists or that the current user has access to it.

Supports hostnames, IPv4 UNC hosts, and Windows IPv6-literal UNC hosts.

.PARAMETER SharePath
UNC share path whose host will be tested.

.PARAMETER DnsCidrs
Optional CIDR ranges. When specified, at least one configured DNS server must fall within one of these ranges or the test returns a negative result.

.PARAMETER TcpTimeoutMs
For the connection test to TCP port 445 (SMB).

.OUTPUTS
A PSCustomObject with the test outcome and discovered details.

.EXAMPLE
Test-ShareLikelyUp -SharePath '\\server01\share'

.EXAMPLE
Test-ShareLikelyUp -SharePath '\\192.168.1.2\foo'

.EXAMPLE
Test-ShareLikelyUp -SharePath '\\server01.contoso.local\share' -DnsCidrs '10.30.0.0/16'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SharePath,
        [string[]]$DnsCidrs,
        [int]$TcpTimeoutMs = 400
    )

    function Convert-IpAddressToBigInteger {
        param([Parameter(Mandatory)][System.Net.IPAddress]$IpAddress)
        $bytes = $IpAddress.GetAddressBytes()
        [Array]::Reverse($bytes)
        $unsignedBytes = New-Object byte[] ($bytes.Length + 1)
        [Array]::Copy($bytes, 0, $unsignedBytes, 0, $bytes.Length)
        [System.Numerics.BigInteger]::new($unsignedBytes)
    }

    function Test-IpInCidr {
        param(
            [Parameter(Mandatory)][string]$IpAddress,
            [Parameter(Mandatory)][string]$Cidr
        )
        $parts = $Cidr -split '/'
        if ($parts.Count -ne 2) {
            throw "Invalid CIDR: $Cidr"
        }

        $networkIp = [System.Net.IPAddress]::Parse($parts[0])
        $candidateIp = [System.Net.IPAddress]::Parse($IpAddress)
        $prefixLength = [int]$parts[1]

        if ($networkIp.AddressFamily -ne $candidateIp.AddressFamily) {
            return $false
        }

        if ($candidateIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
                throw "Invalid IPv4 CIDR prefix length in $Cidr"
            }
        } elseif ($candidateIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            if ($prefixLength -lt 0 -or $prefixLength -gt 128) {
                throw "Invalid IPv6 CIDR prefix length in $Cidr"
            }
        } else {
            throw "Unsupported address family in $Cidr"
        }

        $candidateValue = Convert-IpAddressToBigInteger -IpAddress $candidateIp
        $networkValue = Convert-IpAddressToBigInteger -IpAddress $networkIp

        $bitCount = if ($candidateIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }

        if ($prefixLength -eq 0) {
            return $true
        }

        $hostBits = $bitCount - $prefixLength
        $candidatePrefix = $candidateValue -shr $hostBits
        $networkPrefix = $networkValue -shr $hostBits

        ($candidatePrefix -eq $networkPrefix)
    }

    function Test-Tcp445Open {
        param(
            [Parameter(Mandatory)][string]$ComputerName,
            [Parameter(Mandatory)][int]$TimeoutMs
        )
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($ComputerName, 445, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                return $false
            }

            $null = $client.EndConnect($async)
            return $true
        } catch {
            return $false
        } finally {
            $client.Close()
        }
    }

    function ConvertFrom-Ipv6LiteralHost {
        param([Parameter(Mandatory)][string]$HostName)

        if ($HostName -notmatch '\.ipv6-literal\.net$') {
            return $null
        }

        $base = $HostName -replace '\.ipv6-literal\.net$', ''
        $ipv6 = $base.Replace('-', ':')

        try {
            $parsed = [System.Net.IPAddress]::Parse($ipv6)
            if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                return $parsed.IPAddressToString
            }
            return $null
        } catch {
            return $null
        }
    }

    function Test-IsIpAddress {
        param([Parameter(Mandatory)][string]$Text)
        try {
            $null = [System.Net.IPAddress]::Parse($Text)
            return $true
        } catch {
            return $false
        }
    }

    $result = [pscustomobject]@{
        MatchingDnsServers = @()
        ResolvedAddresses  = @()
        ReachableAddress   = $null
        LikelyUp           = $false
        FailureReason      = $null
    }

    if ($SharePath -notmatch '^[\\]{2}([^\\]+)\\') {
        $result.FailureReason = "SharePath is not a valid UNC path."
        return $result
    }

    $targetHost = $Matches[1]

    if ($DnsCidrs -and $DnsCidrs.Count -gt 0) {
        $dnsServers = @()
        try {
            $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop |
                ForEach-Object { $_.ServerAddresses } |
                Where-Object { $_ } |
                Select-Object -Unique)
        } catch {
            $result.FailureReason = "Failed to read client DNS server configuration."
            return $result
        }

        foreach ($dnsServer in $dnsServers) {
            foreach ($cidr in $DnsCidrs) {
                try {
                    if (Test-IpInCidr -IpAddress $dnsServer -Cidr $cidr) {
                        $result.MatchingDnsServers += $dnsServer
                        break
                    }
                } catch {
                }
            }
        }

        $result.MatchingDnsServers = @($result.MatchingDnsServers | Select-Object -Unique)

        if ($result.MatchingDnsServers.Count -eq 0) {
            $result.FailureReason = "No configured DNS server matched the expected network list."
            return $result
        }
    }

    $ipv6LiteralAddress = ConvertFrom-Ipv6LiteralHost -HostName $targetHost
    if ($ipv6LiteralAddress) {
        $result.ResolvedAddresses = @($ipv6LiteralAddress)
    } elseif (Test-IsIpAddress -Text $targetHost) {
        $result.ResolvedAddresses = @(([System.Net.IPAddress]::Parse($targetHost)).IPAddressToString)
    } else {
        try {
            $result.ResolvedAddresses = @([System.Net.Dns]::GetHostAddresses($targetHost) |
                Where-Object {
                    $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -or
                    $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
                } |
                Select-Object -ExpandProperty IPAddressToString -Unique)
        } catch {
            $result.FailureReason = "DNS resolution failed."
            return $result
        }

        if ($result.ResolvedAddresses.Count -eq 0) {
            $result.FailureReason = "DNS resolution returned no IP addresses."
            return $result
        }
    }

    foreach ($address in $result.ResolvedAddresses) {
        if (Test-Tcp445Open -ComputerName $address -TimeoutMs $TcpTimeoutMs) {
            $result.ReachableAddress = $address
            $result.LikelyUp = $true
            return $result
        }
    }

    $result.FailureReason = "No reachable TCP 445 endpoint was found."
    return $result
}

function Write-HowToCopyCode {
    Write-Host ""
    Write-Host -for Cyan     " %USERPROFILE%\enLogic\IT Support - Documents\scripts_and_SW_we_build\mazars\NETLOGON-IT-scripts-prepare-laptop\"
    Write-Host -for DarkCyan "       (YOUR PC)"
    Write-Host -for DarkCyan "          |"
    Write-Host -for DarkCyan "         _|_"
    Write-Host -for DarkCyan "         \ /"
    Write-Host -for DarkCyan "          V"
    Write-Host -for DarkCyan "  (Forvis Mazars LAPTOP)"
    Write-Host -for Cyan     "       $DEST_DIR"
}

mkdir -force $DEST_DIR > $null

$copiedFilesFromDomain = $false
$r = Test-ShareLikelyUp -SharePath $SOURCE_DIR -DnsCidrs $MAZARS_LAN
if ($r.LikelyUp) {
    if (Test-Path $SOURCE_DIR) {
        Write-Host "Copying files from NETLOGON share of the domain:"
        Write-Host "    $SOURCE_DIR"
        copy "$SOURCE_DIR\*.*" $DEST_DIR\
        $copiedFilesFromDomain = $true
    }
}

if (-not $copiedFilesFromDomain) {
    if (Test-Path $MAIN_PREPLAPTOP_SCRIPT) {
        Write-Host ""
        $lastWriteTime = (Get-Item $MAIN_PREPLAPTOP_SCRIPT).LastWriteTime
        $lastWriteTimeStr = Get-Date $lastWriteTime -format 'yyyy-MMM-dd'
        if ($lastWriteTime -ge (Get-Date).AddDays(-15)) {
            Write-Host -for DarkGray  "Can't update existing code because we can't access " -NoNewLine
            Write-Host -for DarkGray  "\\mazars-gr.local\NETLOGON\IT-scripts\prepare-laptop"
            Write-Host -for White     "But don't bother" -NoNewLine
            Write-Host -for DarkGray  " -- your code is fresh ($lastWriteTimeStr)."
        } else {
            Write-Host -for White     "Can't update existing code because we can't access " -NoNewLine
            Write-Host -for Cyan      "\\mazars-gr.local\NETLOGON\IT-scripts\prepare-laptop"
            Write-Host ""
            Write-Host -for White     "Your code was last udpated at $lastWriteTimeStr " -NoNewLine
            Write-Host -for Yellow    "If you want to update, " -NoNewLine
            Write-Host -for White     "manually copy these files:"
            Write-HowToCopyCode 
        }
    } else {
        Write-Host ""
        Write-Host -for Red  " _________________________________________________________________"
        Write-Host -for Red  "                        ERROR                                     "
        Write-Host -for Red  ""
        Write-Host -for Red  " Can't access \\mazars-gr.local\NETLOGON\IT-scripts\prepare-laptop"
        Write-Host -for Red  " _________________________________________________________________"
        Write-Host ""
        Write-Host -for Yellow  "Please manually copy these files:"
        explorer.exe "$DEST_DIR"
        Write-HowToCopyCode
    }
}
Write-Host ""
