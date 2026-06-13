##############################################################
#
# A collection of helper functions for Networking
#
##############################################################


<#
.SYNOPSIS
Lists remote IPs observed on local listening TCP ports.

.OUTPUTS
Produces one psCustomObject per remote IP:
  RemoteAddress   : The remote IP address.
  LocalPorts      : The local listening port or ports observed.
  States          : The TCP state or states observed.
  ConnectionCount : The number of matching TCP connection rows.

.DESCRIPTION
Reports remote IPs that currently have, or still have visible closed TCP
rows for, non-loopback local listening TCP ports below the configured
port limit.

Use this when you need a compact connection inventory by remote IP,
rather than raw connection rows. The result is a point-in-time view of
the TCP table. Connections removed by Windows before the function runs
are not reported.

By default, loopback, wildcard, and the server's own IP addresses are
excluded from remote addresses. This avoids reporting connections from
the server to itself.

.PARAMETER MaxListeningPortExclusive
Upper exclusive local listening port limit. Only listening TCP ports
below this value are considered.

.PARAMETER States
TCP states to include. Use names accepted by the State property, such
as Established, TimeWait, CloseWait, LastAck, FinWait1, and FinWait2.

.PARAMETER IncludeLocalMachineConnections
When set, connections whose remote address is one of the server's own
IP addresses may be included. Otherwise, they are excluded.

.EXAMPLE
Get-RemoteIpOnLowListeningTcpPort

Returns one row per remote IP, with the observed local ports, observed
TCP states, and matching connection-row count.

.EXAMPLE
Get-RemoteIpOnLowListeningTcpPort -Verbose

Returns the same objects and writes the matched connection details to
the verbose stream.
#>
function Get-RemoteIpOnLowListeningTcpPort {
    [CmdletBinding()]
    param(
        [int]$MaxListeningPortExclusive = 49152,

        [string[]]$States = @(
            'Established',
            'CloseWait',
            'LastAck',
            'FinWait1',
            'FinWait2',
            'TimeWait'
        ),

        [switch]$IncludeLocalMachineConnections
    )

    $stateSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($state in $States) {
        [void]$stateSet.Add($state)
    }

    $excludedRemoteAddresses = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($address in @('127.0.0.1', '::1', '0.0.0.0', '::')) {
        [void]$excludedRemoteAddresses.Add($address)
    }

    if (-not $IncludeLocalMachineConnections) {
        foreach ($networkInterface in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($unicastAddress in $networkInterface.GetIPProperties().UnicastAddresses) {
                $address = $unicastAddress.Address.ToString()

                if ($address -and
                    $address -notlike '169.254.*' -and
                    $address -ne '::') {
                    [void]$excludedRemoteAddresses.Add($address)
                }
            }
        }
    }

    $ipProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()

    $listeningPorts = [System.Collections.Generic.HashSet[int]]::new()

    foreach ($endpoint in $ipProperties.GetActiveTcpListeners()) {
        if ($endpoint.Port -lt $MaxListeningPortExclusive -and
            -not [System.Net.IPAddress]::IsLoopback($endpoint.Address)) {
            [void]$listeningPorts.Add($endpoint.Port)
        }
    }

    if ($listeningPorts.Count -eq 0) {
        Write-Verbose 'No matching listening ports found.'
        return
    }

    $groups = @{}

    foreach ($connection in $ipProperties.GetActiveTcpConnections()) {
        $state = $connection.State.ToString()
        $remoteAddress = $connection.RemoteEndPoint.Address.ToString()
        $localPort = $connection.LocalEndPoint.Port

        if (-not $stateSet.Contains($state) -or
            -not $listeningPorts.Contains($localPort) -or
            $excludedRemoteAddresses.Contains($remoteAddress)) {
            continue
        }

        if (-not $groups.ContainsKey($remoteAddress)) {
            $groups[$remoteAddress] = [pscustomobject]@{
                LocalPorts = [System.Collections.Generic.HashSet[int]]::new()
                States     = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )
                Count      = 0
            }
        }

        $group = $groups[$remoteAddress]
        [void]$group.LocalPorts.Add($localPort)
        [void]$group.States.Add($state)
        $group.Count++
    }

    foreach ($remoteAddress in @($groups.Keys | Sort-Object)) {
        $group = $groups[$remoteAddress]

        [pscustomobject]@{
            RemoteAddress   = $remoteAddress
            LocalPorts      = @($group.LocalPorts | Sort-Object)
            States          = @($group.States | Sort-Object)
            ConnectionCount = $group.Count
        }
    }
}


<#
.SYNOPSIS
Watches and optionally reports remote IPs observed on local listening TCP ports.

.DESCRIPTION
Maintains a cumulative record of remote IPs observed on non-loopback local
listening TCP ports below the configured port limit.

The watch continues until interrupted, for example with Ctrl+C. By default,
it runs silently and does not produce success-stream output.

For each remote IP, the function records the first and last observation time.
Local ports and TCP states are accumulated for the lifetime of the stored
state.

When ShowReport is specified, the cumulative report is displayed periodically.
Report generation is controlled separately from connection sampling to avoid
repeatedly constructing a potentially large formatted report.

When StateFile is provided, the cumulative state is saved in CLIXML format.
If the file already exists, its observations are loaded and collection
continues from that state. This allows the watch to be stopped and resumed.

The parent directory of StateFile is created when necessary. State is first
written to a temporary file and then moved over the configured state file to
reduce the risk of leaving a partially written file.

.OUTPUTS
None by default.

When ShowReport is specified, the function writes a formatted report directly
to the host. The report contains:

  RemoteAddress : The remote IP address.
  LocalPorts    : Local listening port or ports observed.
  States        : TCP state or states observed.
  FirstSeen     : First time the remote IP was observed.
  LastSeen      : Most recent time the remote IP was observed.

The formatted report is host output and is not written to the success-output
pipeline.

.PARAMETER Seconds
Number of seconds between TCP connection sampling cycles.

The default is 10 seconds.

.PARAMETER MaxListeningPortExclusive
Upper exclusive local listening port limit. Only listening TCP ports below
this value are considered.

The default is 49152.

.PARAMETER States
TCP states to include, such as Established, TimeWait, CloseWait, LastAck,
FinWait1, and FinWait2.

.PARAMETER IncludeLocalMachineConnections
Includes connections whose remote address is one of the server's own IP
addresses.

By default, loopback, unspecified, and local-machine remote addresses are
excluded.

.PARAMETER StateFile
Path to the CLIXML file used to load and save the cumulative observations.

The file contains structured state, not the formatted on-screen report.

.PARAMETER SaveIntervalSeconds
Minimum number of seconds between writes to StateFile.

The default is 60 seconds. This parameter has no effect when StateFile is not
specified.

.PARAMETER ShowReport
Displays the cumulative report periodically.

By default, reporting is disabled. Collection and StateFile updates continue
normally without this switch.

.PARAMETER ReportIntervalSeconds
Minimum number of seconds between displayed reports when ShowReport is
specified.

The default is 300 seconds. This parameter does not affect the connection
sampling interval.

.EXAMPLE
Watch-RemoteIpOnLowListeningTcpPort

Samples TCP connections every 10 seconds and maintains cumulative observations
in memory. It produces no regular report and does not persist the observations.

.EXAMPLE
Watch-RemoteIpOnLowListeningTcpPort `
    -StateFile C:\IT\log\seen_tcp_connections.clixml

Samples TCP connections every 10 seconds, loads any existing observations from
the CLIXML file, and saves the cumulative state at intervals of at least
60 seconds. It does not display the cumulative report.

.EXAMPLE
Watch-RemoteIpOnLowListeningTcpPort `
    -Seconds 5 `
    -StateFile C:\Temp\observed-connections.clixml `
    -ShowReport `
    -ReportIntervalSeconds 300

Samples connections every 5 seconds, saves cumulative state to the CLIXML file,
and displays the cumulative report no more than once every 5 minutes.
#>
function Watch-RemoteIpOnLowListeningTcpPort {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 86400)]
        [int]$Seconds = 10,

        [int]$MaxListeningPortExclusive = 49152,

        [string[]]$States = @(
            'Established',
            'CloseWait',
            'LastAck',
            'FinWait1',
            'FinWait2',
            'TimeWait'
        ),

        [switch]$IncludeLocalMachineConnections,

        [string]$StateFile,

        [ValidateRange(1, 86400)]
        [int]$SaveIntervalSeconds = 60,

        [switch]$ShowReport,

        [ValidateRange(1, 86400)]
        [int]$ReportIntervalSeconds = 300
    )

    $functionName = 'Watch-RemoteIpOnLowListeningTcpPort'
    $stateVersion = 2
    $observed = @{}
    $started = Get-Date
    $lastFileWrite = $null
    $lastReportWrite = $null

    if ($StateFile) {
        $parentDir = Split-Path -Path $StateFile -Parent

        if ($parentDir -and
            -not (Test-Path -LiteralPath $parentDir -PathType Container)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }

        if (Test-Path -LiteralPath $StateFile -PathType Leaf) {
            try {
                $savedState = Import-Clixml -LiteralPath $StateFile -ErrorAction Stop

                if (-not $savedState.FunctionName -or
                    $savedState.FunctionName -ne $functionName -or
                    $null -eq $savedState.Observations) {
                    throw "The file is not a saved state from $functionName."
                }

                if ($savedState.Started) {
                    $started = [datetime]$savedState.Started
                }

                foreach ($item in @($savedState.Observations)) {
                    if (-not $item.RemoteAddress) {
                        throw 'Saved state contains an observation without RemoteAddress.'
                    }

                    $observed[[string]$item.RemoteAddress] = [pscustomobject]@{
                        RemoteAddress = [string]$item.RemoteAddress
                        LocalPorts    = @($item.LocalPorts)
                        States        = @($item.States)
                        FirstSeen     = $item.FirstSeen
                        LastSeen      = $item.LastSeen
                    }
                }

                Write-Verbose "Loaded $($observed.Count) observations from $StateFile"
            } catch {
                throw @"
Could not read '$StateFile' as a saved CLIXML state from $functionName.
Use another StateFile name, or rename/remove the existing file.

Original error:
$($_.Exception.Message)
"@
            }
        }
    }

    while ($true) {
        $now = Get-Date

        try {
            $current = @(
                Get-RemoteIpOnLowListeningTcpPort `
                    -MaxListeningPortExclusive $MaxListeningPortExclusive `
                    -States $States `
                    -IncludeLocalMachineConnections:$IncludeLocalMachineConnections `
                    -ErrorAction Stop
            )
        } catch {
            Write-Warning "TCP connection collection failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $Seconds
            continue
        }

        foreach ($item in $current) {
            $remoteAddress = [string]$item.RemoteAddress

            if (-not $observed.ContainsKey($remoteAddress)) {
                $observed[$remoteAddress] = [pscustomobject]@{
                    RemoteAddress = $remoteAddress
                    LocalPorts    = @()
                    States        = @()
                    FirstSeen     = $now
                    LastSeen      = $now
                }
            }

            $entry = $observed[$remoteAddress]

            $portSet = [System.Collections.Generic.HashSet[int]]::new()
            foreach ($port in @($entry.LocalPorts) + @($item.LocalPorts)) {
                [void]$portSet.Add([int]$port)
            }

            $stateSet = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($state in @($entry.States) + @($item.States)) {
                [void]$stateSet.Add([string]$state)
            }

            $entry.LocalPorts = @($portSet | Sort-Object)
            $entry.States = @($stateSet | Sort-Object)
            $entry.LastSeen = $now
        }

        if ($StateFile -and
            ($null -eq $lastFileWrite -or
             ($now - $lastFileWrite).TotalSeconds -ge $SaveIntervalSeconds)) {

            $observations = @(
                foreach ($remoteAddress in @($observed.Keys | Sort-Object)) {
                    $entry = $observed[$remoteAddress]

                    [pscustomobject]@{
                        RemoteAddress = $entry.RemoteAddress
                        LocalPorts    = @($entry.LocalPorts)
                        States        = @($entry.States)
                        FirstSeen     = $entry.FirstSeen
                        LastSeen      = $entry.LastSeen
                    }
                }
            )

            $state = [pscustomobject]@{
                FunctionName                   = $functionName
                StateVersion                   = $stateVersion
                Started                        = $started
                LastUpdated                    = $now
                MaxListeningPortExclusive      = $MaxListeningPortExclusive
                States                         = @($States)
                IncludeLocalMachineConnections = [bool]$IncludeLocalMachineConnections
                Observations                   = $observations
            }

            $temporaryStateFile = "$StateFile.tmp"

            try {
                $state |
                    Export-Clixml `
                        -LiteralPath $temporaryStateFile `
                        -Force `
                        -ErrorAction Stop

                Move-Item `
                    -LiteralPath $temporaryStateFile `
                    -Destination $StateFile `
                    -Force `
                    -ErrorAction Stop

                $lastFileWrite = $now
                Write-Verbose "Saved CLIXML state to $StateFile"
            } finally {
                if (Test-Path -LiteralPath $temporaryStateFile -PathType Leaf) {
                    Remove-Item -LiteralPath $temporaryStateFile -Force -ErrorAction SilentlyContinue
                }
            }
        }

        if ($ShowReport -and
            ($null -eq $lastReportWrite -or
             ($now - $lastReportWrite).TotalSeconds -ge $ReportIntervalSeconds)) {

            $rows = @(
                foreach ($remoteAddress in @($observed.Keys | Sort-Object)) {
                    $entry = $observed[$remoteAddress]

                    [pscustomobject]@{
                        RemoteAddress = $entry.RemoteAddress
                        LocalPorts    = $entry.LocalPorts -join ', '
                        States        = $entry.States -join ', '
                        FirstSeen     = $entry.FirstSeen
                        LastSeen      = $entry.LastSeen
                    }
                }
            )

            $header = @(
                'Observed remote IPs connected to low listening TCP ports'
                "Since: $started"
                "Now:   $now"
                "State file: $StateFile"
                "Last file write: $lastFileWrite"
                ''
            ) -join [Environment]::NewLine

            Write-Host $header

            if ($rows.Count -gt 0) {
                $rows | Format-Table -AutoSize | Out-Host
            } else {
                Write-Host '(none)'
            }

            $lastReportWrite = $now
        }

        Start-Sleep -Seconds $Seconds
    }
}


function Test-IpReachability {
<#
.SYNOPSIS
Probe point-in-time ICMP reachability for one or more IP targets.

.DESCRIPTION
Sends one or more ICMP echo attempts to each target and returns one output
object per unique target IP.

When a ping attempt cannot be performed due to an internal runtime error,
the target result's lastStatus is set to a string beginning with
"PROGRAM EXCEPTION:".

.OUTPUTS
[pscustomobject]
One object per unique target IP with properties:
- ip (string): The target IP string as provided/normalized.
- responded (bool): $true if any attempt succeeded; otherwise $false.
- attempts (int): Number of attempts made for that target.
- respondedOnAttempt (Nullable[int]): Attempt number of first success;
  otherwise $null.
- rttMs (Nullable[long]): Round-trip time in milliseconds for the
  successful response; otherwise $null.
- lastStatus (string): Final status observed for the target. For runtime
  errors, begins with "PROGRAM EXCEPTION:".

.PARAMETER Ip
One or more target IPs to probe.

Accepts:
- A single value convertible to string.
- An enumerable of values convertible to string.
- A single string containing multiple targets separated by commas and/or
  whitespace.

.PARAMETER Retry
Number of additional attempts per target after the first attempt.

.PARAMETER TimeoutMs
Timeout in milliseconds for each attempt.

.EXAMPLE
Test-IpReachability -Ip '10.1.11.50,10.1.11.55 10.1.11.56' `
  -Retry 1 -TimeoutMs 500 -Verbose
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true,Position=0)][Alias('Ips')][object]$Ip,
    [ValidateRange(1,1000)][int]$Retry=1,
    [ValidateRange(1,60000)][int]$TimeoutMs=500
  )

  $ips=@()
  if($Ip -is [string]){
    $s=$Ip.Trim()
    if($s -match '[,\s]'){ $ips=@($s -split '[,\s]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }) }
    else { $ips=@($s) }
  } elseif($Ip -is [System.Collections.IEnumerable]){
    foreach($x in $Ip){ if($null -ne $x -and "$x".Trim()){ $ips += "$x".Trim() } }
  } else { $ips=@("$Ip".Trim()) }
  if($ips.Count -eq 0){ return @() }
  $ips=@($ips | Select-Object -Unique)

  $state=@{}
  foreach($a in $ips){
    $state[$a]=[pscustomobject]@{ip=$a;responded=$false;attempts=0;respondedOnAttempt=$null;rttMs=$null;lastStatus=$null}
  }

  $retryableStatuses = New-Object 'System.Collections.Generic.HashSet[string]'
  $null = $retryableStatuses.Add('TimedOut')
  $null = $retryableStatuses.Add('Unknown')

  $terminalStatuses = New-Object 'System.Collections.Generic.HashSet[string]'
  @(
    'DestinationHostUnreachable','DestinationNetworkUnreachable','DestinationUnreachable',
    'DestinationProhibited','DestinationProtocolUnreachable','DestinationPortUnreachable',
    'BadRoute','BadDestination','DestinationScopeMismatch','PacketTooBig',
    'ParameterProblem','BadOption','BadHeader','UnrecognizedNextHeader',
    'TtlExpired','TimeExceeded','TtlReassemblyTimeExceeded'
  ) | ForEach-Object { $null = $terminalStatuses.Add($_) }

  $maxAttempts = 1 + $Retry
  $pending = New-Object System.Collections.ArrayList
  $null=$pending.AddRange($ips)

  for($attempt=1; $attempt -le $maxAttempts -and $pending.Count -gt 0; $attempt++){
    $batch=@()
    foreach($a in @($pending)){
      $st=$state[$a]
      if($st.responded){ continue }
      $st.attempts++

      $p=New-Object System.Net.NetworkInformation.Ping
      $t=$null
      try{
        $t=$p.SendPingAsync($a,$TimeoutMs)
      } catch {
        $st.lastStatus="PROGRAM EXCEPTION: $($_.Exception.Message)"
        Write-Verbose "attempt=$attempt/$maxAttempts ip=$a status='$($st.lastStatus)' retry=no (program exception)"
        try{ $p.Dispose() } catch {}
        continue
      }

      $batch += [pscustomobject]@{ip=$a;ping=$p;task=$t}
    }

    $tasks=@($batch | ForEach-Object { $_.task })
    if($tasks.Count -gt 0){
      try{
        [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]$tasks)
      } catch {
        Write-Warning "WaitAll exception: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
      }
    }

    $newPending = New-Object System.Collections.ArrayList

    foreach($b in $batch){
      $a=$b.ip; $st=$state[$a]
      $statusName=$null

      try{
        if($b.task.IsFaulted){
          $msg=$b.task.Exception.InnerException.Message
          $st.lastStatus="PROGRAM EXCEPTION: $msg"
          $statusName=$st.lastStatus
        } elseif($b.task.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion){
          $r=$b.task.Result
          $statusName=$r.Status.ToString()
          $st.lastStatus=$statusName
          if($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success){
            $st.responded=$true
            $st.rttMs=$r.RoundtripTime
            $st.respondedOnAttempt=$attempt
          }
        } else {
          $statusName=$b.task.Status.ToString()
          $st.lastStatus=$statusName
        }
      } catch {
        $st.lastStatus="PROGRAM EXCEPTION: $($_.Exception.Message)"
        $statusName=$st.lastStatus
      } finally {
        try{ $b.ping.Dispose() } catch {}
      }

      $willRetry=$false
      if(-not $st.responded -and $attempt -lt $maxAttempts){
        $ls="$($st.lastStatus)"
        if($retryableStatuses.Contains($ls)){ $willRetry=$true }
      }

      if($st.responded){
        Write-Verbose "attempt=$attempt/$maxAttempts ip=$a status='$statusName' rttMs=$($st.rttMs) retry=no (success)"
      } else {
        $why="no"
        if($attempt -ge $maxAttempts){ $why="no (attempt limit reached)" }
        elseif($terminalStatuses.Contains("$($st.lastStatus)")){ $why="no (terminal status)" }
        elseif($st.lastStatus -like 'PROGRAM EXCEPTION:*'){ $why="no (program exception)" }
        elseif($willRetry){ $why="yes (retryable status)" }
        else { $why="no (non-retryable status)" }
        Write-Verbose "attempt=$attempt/$maxAttempts ip=$a status='$statusName' retry=$why"
      }

      if($willRetry){
        $null=$newPending.Add($a)
      }
    }

    $pending.Clear() | Out-Null
    if($newPending.Count -gt 0){ $null=$pending.AddRange(@($newPending | Select-Object -Unique)) }
  }

  $out = foreach($a in $ips){ $state[$a] }
  $out | Select-Object ip,responded,attempts,respondedOnAttempt,rttMs,lastStatus
}

function Test-TcpPort {
<#
.SYNOPSIS
Quickly tests whether a TCP connection can be established.

.DESCRIPTION
Tests TCP connectivity from the current machine to the specified target
and ports, and returns one result object per requested port.

The target MAY be specified as an IP address or a hostname. If name 
resolution fails, the function throws a terminating error.

Ports are accepted in multiple input forms.

The -TimeoutMs value is a single overall time budget (in milliseconds) for
the entire batch of ports, not a per-port timeout. 

.OUTPUTS
System.Management.Automation.PSCustomObject

One object per normalized port, with these properties:
- port   (int)    The TCP port tested.
- open   (bool)   $true if a connection was established; otherwise $false.
- detail (string) "connected" on success; otherwise an error identifier
                 or "timeout" if the overall time budget was reached.

Objects are emitted in ascending port order.

.PARAMETER Target
Target host to test.

.PARAMETER Ports
Ports to test. Accepts:
- a single integer
- an array of integers
- a string containing one or more port numbers
- an enumerable of values convertible to integers

.PARAMETER TimeoutMs
Overall time budget for the entire batch, in milliseconds. Defaults to
200. When the budget is exhausted, remaining ports are reported as
"timeout".

.EXAMPLE
Test-TcpPort -Target '10.1.11.1' -Ports 80,443,4444

.EXAMPLE
Test-TcpPort -Target 'google.com' -Ports '80,443,4444' `
  -TimeoutMs 1000
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true,Position=0)][string]$Target,
    [Parameter(Mandatory=$true,Position=1)][object]$Ports,
    [int]$TimeoutMs=200
  )

  $target=$Target.Trim()
  $ipObj=$null
  if([System.Net.IPAddress]::TryParse($target,[ref]$ipObj)){
    $ipString=$ipObj.IPAddressToString
  } else {
    try{ $addrs=[System.Net.Dns]::GetHostAddresses($target) } catch { throw "Failed to resolve '$target': $($_.Exception.Message)" }
    if(-not $addrs -or $addrs.Count -eq 0){ throw "Failed to resolve '$target' (no addresses returned)" }
    $pick=($addrs | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1)
    if(-not $pick){ $pick=$addrs | Select-Object -First 1 }
    $ipString=$pick.IPAddressToString
  }

  $portsList=@()
  if($Ports -is [int]){ $portsList=@($Ports) }
  elseif($Ports -is [int[]]){ $portsList=$Ports }
  elseif($Ports -is [string]){
    foreach($tok in ($Ports -split '[^\d]+')){ if($tok -match '^\d+$'){ $portsList += [int]$tok } }
  } elseif($Ports -is [System.Collections.IEnumerable]){
    foreach($p in $Ports){ if($null -ne $p -and "$p" -match '^\d+$'){ $portsList += [int]$p } }
  } else {
    if("$Ports" -match '^\d+$'){ $portsList=@([int]$Ports) }
  }

  $portsList=@($portsList | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object -Unique)
  if($portsList.Count -eq 0){ return @() }

  $items=@()
  foreach($port in $portsList){
    $c=New-Object System.Net.Sockets.TcpClient
    $iar=$c.BeginConnect($ipString,$port,$null,$null)
    $items += [pscustomobject]@{Port=$port;Client=$c;IAR=$iar;Handle=$iar.AsyncWaitHandle}
  }

  $deadline=(Get-Date).AddMilliseconds($TimeoutMs)
  $results=@{}
  $pending=New-Object System.Collections.ArrayList
  $null=$pending.AddRange($items)

  while($pending.Count -gt 0){
    $remaining=[int]([Math]::Max(0, ($deadline-(Get-Date)).TotalMilliseconds))
    if($remaining -le 0){ break }

    $harvested=$false
    for($i=$pending.Count-1; $i -ge 0; $i--){
      $it=$pending[$i]
      if($it.Handle.WaitOne(0,$false)){
        $open=$false; $detail="error"
        try{
          try{
            $it.Client.EndConnect($it.IAR)
            $open=$true; $detail="connected"
          } catch {
            $e=$_.Exception
            if($e -is [System.Net.Sockets.SocketException]){
              $detail=$e.SocketErrorCode.ToString()
            } else {
              $detail=$e.GetType().FullName
            }
          }
        } catch {
          $detail=$_.Exception.GetType().FullName
        }

        $results[$it.Port]=[pscustomobject]@{port=$it.Port;open=$open;detail=$detail}

        try{ $it.Handle.Close() } catch {}
        try{ $it.Client.Close() } catch {}
        $pending.RemoveAt($i) | Out-Null
        $harvested=$true
      }
    }

    if(-not $harvested){
      Start-Sleep -Milliseconds ([Math]::Min(10,$remaining))
    }
  }

  foreach($it in @($pending)){
    $results[$it.Port]=[pscustomobject]@{port=$it.Port;open=$false;detail="timeout"}
    try{ $it.Handle.Close() } catch {}
    try{ $it.Client.Close() } catch {}
  }

  foreach($p in $portsList){ $results[$p] }
}

function Test-NetConnectivityToHost {
<#
Test-NetConnectivityToHost validates that basic network reachability to a target host matches an explicit expectation profile.

What it checks
- ICMP echo (ping): verifies whether the host responds to pings or not.
- TCP ports (optional):
  - OpenPorts: ports that are expected to accept a TCP connection.
  - ClosedPorts: ports that are expected to refuse or time out (treated as CLOSED/FILTERED).

Output / side effects
- Outputs discrepancies using Write-Warning "[<level>] <message>" (<level> can be pass or failure).
- If -ReturnTrueFalse is used, the function returns $true/$false and emits no warnings.

Notes / interpretation
- A TCP port is considered OPEN only if a TCP connect completes successfully within the timeout window.
- A TCP port is considered CLOSED/FILTERED if the connect fails or does not complete within the timeout.
- If OpenPorts/ClosedPorts are omitted, only the ping expectation is validated.
- If -SkipPing is used, only port expectations are validated.
- If -HostFriendlyName is passed, it is used to refer to the host in all messages.

Example
  Test-NetConnectivityToHost -TargetHost 10.30.0.2 -RespondsToPing:$true -OpenPorts @(53,88,135,389,445) -ClosedPorts @(22,3389) -PortTimeoutMs 1000

Example (ports only)
  Test-NetConnectivityToHost -TargetHost 10.30.0.2 -SkipPing -OpenPorts @(443) -PortTimeoutMs 1000

Example (boolean result only)
  Test-NetConnectivityToHost -TargetHost 10.30.0.2 -RespondsToPing:$true -ReturnTrueFalse
#>
  [CmdletBinding(DefaultParameterSetName='Ping')]
  param(
    [Parameter(Mandatory=$true)]
    [Alias('Host')]
    [string]$TargetHost,

    [string]$HostFriendlyName,

    [Parameter(Mandatory=$true, ParameterSetName='Ping')]
    [bool]$RespondsToPing,

    [int[]]$OpenPorts,
    [int[]]$ClosedPorts,

    [Parameter(Mandatory=$true, ParameterSetName='PortsOnly')]
    [switch]$SkipPing,

    [int]$PortTimeoutMs = 1000,
    [switch]$ReturnTrueFalse
  )

  $LogPass = {
    param($m)
    if(-not $ReturnTrueFalse){ Write-Warning "[pass] $m" }
  }

  $LogFailure = {
    param($m)
    if(-not $ReturnTrueFalse){ Write-Warning "[failure] $m" }
  }

  $ok=$true
  $displayName = if ([string]::IsNullOrWhiteSpace($HostFriendlyName)) { $TargetHost } else { $HostFriendlyName }
  
  $openExpected=@(); if($OpenPorts){ $openExpected=@($OpenPorts | ForEach-Object { [int]$_ } | Sort-Object -Unique) }
  $closedExpected=@(); if($ClosedPorts){ $closedExpected=@($ClosedPorts | ForEach-Object { [int]$_ } | Sort-Object -Unique) }

  $overlap=@($openExpected | Where-Object { $closedExpected -contains $_ })
  if($overlap.Count -gt 0){
    throw ("Invalid arguments: port(s) specified as both OPEN and CLOSED: {0}" -f (($overlap | Sort-Object -Unique) -join ', '))
  }

  $targetName = $TargetHost.Trim()
  $TargetIp = $null
  $isIPv4 = ($targetName -match '^\d{1,3}(\.\d{1,3}){3}$')
  $isIPv6 = ($targetName -match '^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$' -or $targetName -match '^::1$')

  if ($isIPv4 -or $isIPv6) {
    $TargetIp = $targetName
  } else {
    try {
      if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        $TargetIp = Resolve-DnsName -Name $targetName -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -First 1
      } else {
        $TargetIp = ([System.Net.Dns]::GetHostAddresses($targetName) | Select-Object -First 1).IPAddressToString
      }
    } catch {
      $ok = $false
      & $LogFailure "Failed to resolve $($displayName): $($_.Exception.Message)"
    }

    if (-not $TargetIp) {
      & $LogFailure "Failed to resolve $displayName"
      if ($ReturnTrueFalse) { return $false }
      return
    }
  }

  $allPorts=@()
  if($openExpected){ $allPorts += $openExpected }
  if($closedExpected){ $allPorts += $closedExpected }

  $portState=@{}
  if($allPorts.Count -gt 0){
    try{
      foreach($r in @(Test-TcpPort -Target $TargetIp -Ports $allPorts -TimeoutMs $PortTimeoutMs)){
        if($null -ne $r -and $null -ne $r.Port){
          $portState[[int]$r.Port] = [bool]$r.Open
        }
      }
    } catch {
      & $LogFailure ("TCP probe failed for host {0}: {1}" -f $displayName, $_.Exception.Message)
      $ok = $false
    }
  }

  if($PSCmdlet.ParameterSetName -eq 'Ping'){
    $pingActual=$false
    $pingObj=$null
    $pingTask=$null

    try { $pingObj = New-Object System.Net.NetworkInformation.Ping } catch {}
    try { if($pingObj){ $pingTask = $pingObj.SendPingAsync($TargetIp,$PortTimeoutMs) } } catch {}

    if($pingTask){
      try{
        if(-not $pingTask.IsCompleted){ $null = $pingTask.Wait($PortTimeoutMs) }
        if($pingTask.IsCompleted -and -not $pingTask.IsFaulted -and $pingTask.Result){
          $pingActual = ($pingTask.Result.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
        }
      } catch {
        $pingActual=$false
      }
    }

    try { if($pingObj){ $pingObj.Dispose() } } catch {}

    if ($RespondsToPing -and -not $pingActual) {
      & $LogFailure "Host $displayName was expected to respond to ping, but does not"
      $ok = $false
    }

    if ((-not $RespondsToPing) -and $pingActual) {
      & $LogFailure "Host $displayName was expected to NOT respond to ping, but it does"
      $ok = $false
    }
  }

  foreach ($p in $openExpected) {
    $isOpen = $false
    if ($portState.ContainsKey($p)) { $isOpen = [bool]$portState[$p] }
    if (-not $isOpen) {
      & $LogFailure "Port $($displayName):$p was expected to be OPEN, but is not"
      $ok = $false
    }
  }

  foreach ($p in $closedExpected) {
    $isOpen = $false
    if ($portState.ContainsKey($p)) { $isOpen = [bool]$portState[$p] }
    if ($isOpen) {
      & $LogFailure "Port $($displayName):$p was expected to be CLOSED/FILTERED, but is not"
      $ok = $false
    }
  }

  if ($ReturnTrueFalse) {
    return $ok
  }

  if ($ok) {
    & $LogPass "Connectivity to $displayName is as expected"
  }
}

function Split-IpByReachability {
<#
.SYNOPSIS
Splits input IPs into Alive vs NotAlive based on whether they respond to pings

.DESCRIPTION
Runs Test-IpReachability for the provided targets and returns a single object
containing two string arrays:
- AliveIps: IPs that responded ($true)
- DeadIps:  IPs that did not respond ($false) or hit errors/timeouts

.INPUTS
Same accepted shapes as Test-IpReachability -Ip.

.OUTPUTS
[pscustomobject] with:
- AliveIps ([string[]])
- DeadIps  ([string[]])
- Results  ([pscustomobject[]]) raw per-IP results (handy for lastStatus/rtt)
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true,Position=0)][Alias('Ips')][object]$Ip,
    [ValidateRange(1,1000)][int]$Retry=1,
    [ValidateRange(1,60000)][int]$TimeoutMs=500
  )

  $results = @(Test-IpReachability -Ip $Ip -Retry $Retry -TimeoutMs $TimeoutMs)

  $alive = @($results | Where-Object { $_.responded } | Select-Object -ExpandProperty ip)
  $dead  = @($results | Where-Object { -not $_.responded } | Select-Object -ExpandProperty ip)

  [pscustomobject]@{
    AliveIps = $alive
    DeadIps  = $dead
    Results  = $results
  }
}

function Test-NetConnectivityToNetwork {
<#
.SYNOPSIS
Assesses reachability of a network by pinging a list of hosts that are known to reply.

.DESCRIPTION
Given a human-friendly network description (e.g. "10.11.x.y/16") and a list of
IP addresses that are expected to respond to ICMP, this function probes them
(using Split-IpByReachability) and outputs the results using:
   Write-Warning "[<level>] ..."
(<level> is one of pass, notice, failure)

If -ReturnListOfAliveHosts is used, the function does not emit warnings and
instead returns the list of responsive hosts.
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true,Position=0)][string]$NetworkDescription,
    [Parameter(Mandatory=$true,Position=1)][object]$KnownHostIps,
    [ValidateRange(1,1000)][int]$Retry=1,
    [ValidateRange(1,60000)][int]$TimeoutMs=500,
    [switch]$ReturnListOfAliveHosts
  )

  $ips=@()
  if($KnownHostIps -is [string]){
    $s=$KnownHostIps.Trim()
    if($s -match '[,\s]'){ $ips=@($s -split '[,\s]+' | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }) }
    else { $ips=@($s) }
  } elseif($KnownHostIps -is [System.Collections.IEnumerable]){
    foreach($x in $KnownHostIps){ if($null -ne $x -and "$x".Trim()){ $ips += "$x".Trim() } }
  } else { $ips=@("$KnownHostIps".Trim()) }
  $ips=@($ips | Where-Object { $_ } | Select-Object -Unique)

  $progress_msg="Pinging $($ips.Count) hosts"
  Write-Progress -Activity $progress_msg -Status "Please wait"
  $split = Split-IpByReachability -Ip $ips -Retry $Retry -TimeoutMs $TimeoutMs
  Write-Progress -Activity $progress_msg -Completed

  $alive=@($split.AliveIps)
  $dead=@($split.DeadIps)

  if($ReturnListOfAliveHosts){
    return $alive
  }
  
  if(-not $alive -or $alive.Count -eq 0){
    $message = "The $NetworkDescription network may be UNRECHABLE because none of the hosts replied to pings"
    $comment = "List of hosts that didn't reply: ($($ips -join ', ')); Maybe some VPN connection is down"
    Write-Warning "[failure] $message`n$comment" 
  } elseif($dead -and $dead.Count -gt 0){
    $message = "The $NetworkDescription network is reachable (at least one host replied to pings)"
    Write-Warning "[pass] $message"
    $message = "Note that some hosts of $NetworkDescription did not reply to pings (that's often normal)"
    $comment = "List of hosts that didn't reply: ($($dead -join ', '))`nIf some hosts are consistently failing, consider if you should update the list of hosts you ping"
    Write-Warning "[notice] $message`n$comment" 
  } else {
    $message = "The $NetworkDescription network is reachable; all known hosts replied to pings"
    $comment = "List of hosts that replied: ($($ips -join ', '))"
    Write-Warning "[pass] $message`n$comment" 
  }
}

function Test-ShareLikelyUp {
<#
.SYNOPSIS
QUICKLY tests whether the host of a UNC share is LIKELY reachable over SMB.

.DESCRIPTION
This is a FAST reachability test, not a definitive share-access test. A positive result means the host likely has SMB available. It does not prove that the share exists or that the current user has access to it.

Optionally verifies that at least one configured DNS server falls within an expected CIDR range (prefer to pass it so that you don't spend time on failed DNS resolutions), resolves the host to IPv4 and/or IPv6 addresses, and tests whether any resolved address accepts a TCP connection on port 445 within a short timeout. Supports hostnames, IPv4 UNC hosts, and Windows IPv6-literal UNC hosts.

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