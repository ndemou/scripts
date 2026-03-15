##############################################################
#
# A collection of helper functions for Networking
#
##############################################################
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
    foreach($x in $Ip){ if($x -ne $null -and "$x".Trim()){ $ips += "$x".Trim() } }
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
      $note=$null

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
Test-TcpPort -Target 'timesheet-gr.forvismazars.com' -Ports '80,443,4444' `
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
  }
  elseif($Ports -is [System.Collections.IEnumerable]){
    foreach($p in $Ports){ if($p -ne $null -and "$p" -match '^\d+$'){ $portsList += [int]$p } }
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

  if($isIPv4 -or $isIPv6){
    $TargetIp = $targetName
  } else {
    try {
      if(Get-Command Resolve-DnsName -ErrorAction SilentlyContinue){
        $TargetIp = Resolve-DnsName -Name $targetName -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -First 1
      } else {
        $TargetIp = ([System.Net.Dns]::GetHostAddresses($targetName) | Select-Object -First 1).IPAddressToString
      }
    } catch {
      $ok=$false
      & $LogFailure "Failed to resolve $($TargetHost): $($_.Exception.Message)"
    }

    if(-not $TargetIp){
      & $LogFailure "Failed to resolve $TargetHost"
      if($ReturnTrueFalse){ return $false }
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
      & $LogFailure ("TCP probe failed for host {0}: {1}" -f $TargetHost, $_.Exception.Message)
      $ok=$false
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

    if($RespondsToPing -and -not $pingActual){
      & $LogFailure "Host $TargetHost was expected to respond to ping, but does not"
      $ok=$false
    }

    if((-not $RespondsToPing) -and $pingActual){
      & $LogFailure "Host $TargetHost was expected to NOT respond to ping, but it does"
      $ok=$false
    }
  }

  foreach($p in $openExpected){
    $isOpen=$false
    if($portState.ContainsKey($p)){ $isOpen = [bool]$portState[$p] }
    if(-not $isOpen){
      & $LogFailure "Port $($TargetHost):$p was expected to be OPEN, but is not"
      $ok=$false
    }
  }

  foreach($p in $closedExpected){
    $isOpen=$false
    if($portState.ContainsKey($p)){ $isOpen = [bool]$portState[$p] }
    if($isOpen){
      & $LogFailure "Port $($TargetHost):$p was expected to be CLOSED/FILTERED, but is not"
      $ok=$false
    }
  }

  if($ReturnTrueFalse){
    return $ok
  }

  if($ok){
    & $LogPass "Connectivity to $TargetHost is as expected"
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
    foreach($x in $KnownHostIps){ if($x -ne $null -and "$x".Trim()){ $ips += "$x".Trim() } }
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