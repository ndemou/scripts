<#
.SYNOPSIS
Shows a compact, admin-friendly timeline of recent boots, shutdowns,
crashes, and update-related restart signals from the System log.

.DESCRIPTION
Use this for first-pass reboot and shutdown triage. It helps answer 
whether a recent restart was clean, unexpected, crash-related, planned
by an administrator or process, or associated with Windows Updates. 

.OUTPUTS
Produces one PSCustomObject per matching event:
  Level       : Event level text.
  Time        : Event time.
  Kind        : Event category. One of:
                Boot, NormalShutdown, PlannedShutdownOrRestart, 
                WindowsUpdatesInstallStarted, WindowsUpdatesInstallCompleted,
                WindowsUpdatesRestartRequired, WindowsUpdatesRestart
                BugCheck, CrashDump, AbnormalShutdown, 
                UnexpectedShutdownFollowup, Other
  Description : First line of the event message with source metadata
                appended as "(id <n> from <provider>)".

Intentionally excludes noise about Microsoft Defender updates.

.EXAMPLE
PS C:\> Get-BootShutdownEvents |ft

Level Time         Kind                       Description
----- ----         ----                       -----------
Info  15/3 6:00:47 WindowsUpdatesInstallStart Installation Started: Windows has started installing the following update: 2026-03 Cumulative Update for Microsoft ...
Info  15/3 6:19:54 WindowsUpdatesRestart      The process C:\WINDOWS\system32\shutdown.exe (SRV2) has initiated the restart of computer SRV2 ...
Info  15/3 6:22:06 NormalShutdown             The Event log service was stopped. (id 6006 from EventLog)
Info  15/3 6:22:12 NormalShutdown             The operating system is shutting down at system time  2026 - 03 - 15T04:22:12.144072600Z. (id 13 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:14 Boot                       The operating system started at system time  2026 - 03 - 15T04:22:14.500000000Z. (id 12 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:22 Boot                       The Event log service was started. (id 6005 from EventLog)
Info  15/3 6:22:44 WindowsUpdatesRestart      The process C:\WINDOWS\servicing\TrustedInstaller.exe (SRV2) has initiated the restart of computer SRV2...
Info  15/3 6:22:45 NormalShutdown             The Event log service was stopped. (id 6006 from EventLog)
Info  15/3 6:22:51 NormalShutdown             The operating system is shutting down at system time  2026 - 03 - 15T04:22:51.294803800Z. (id 13 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:53 Boot                       The operating system started at system time  2026 - 03 - 15T04:22:53.500000000Z. (id 12 from Microsoft-Windows-Kernel-General)
Info  15/3 6:22:59 Boot                       The Event log service was started. (id 6005 from EventLog)
Info  15/3 6:23:20 WindowsUpdatesInstallCompl Installation Successful: Windows successfully installed the following update: 2026-03 Cumulative Update for Microsoft ...
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$LastHours = 48,

    [switch]$NewestFirst
)

$startTimeUtc = (Get-Date).AddHours(-$LastHours).ToUniversalTime().ToString('s') + '.000Z'

$filterXml = @"
<QueryList>
<Query Id="0" Path="System">
<Select Path="System">
  *[
    System[
      TimeCreated[@SystemTime >= '$startTimeUtc']
      and
      (
        (Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12 or EventID=13))
        or
        (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41)
        or
        (Provider[@Name='User32'] and (EventID=1074 or EventID=1076))
        or
        (Provider[@Name='EventLog'] and (EventID=6005 or EventID=6006 or EventID=6008))
        or
        ((Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='BugCheck']) and EventID=1001)
        or
        (Provider[@Name='volmgr'] and (EventID=46 or EventID=161))
        or
        (Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19 or EventID=21 or EventID=43))
      )
    ]
  ]
</Select>
</Query>
</QueryList>
"@

$events = New-Object 'System.Collections.Generic.List[object]'

foreach ($evt in Get-WinEvent -FilterXml $filterXml -ErrorAction Stop) {
    $message = $evt.Message
    $description = if ([string]::IsNullOrWhiteSpace($message)) {
        ''
    } else {
        ($message -split "`r?`n", 2)[0]
    }

    if ($description -match '\bKB2267602\b') {
        continue
    }

    $null = $events.Add([pscustomobject]@{
        Event            = $evt
        ProviderName     = $evt.ProviderName
        Id               = $evt.Id
        LevelDisplayName = $evt.LevelDisplayName
        Message          = $message
        Description      = $description
    })
}

$sortedEvents = $events |
    Sort-Object `
        @{ Expression = { $_.Event.TimeCreated }; Descending = $NewestFirst }, `
        @{ Expression = { $_.Event.RecordId }; Descending = $NewestFirst }

foreach ($item in $sortedEvents) {
    $providerName = $item.ProviderName
    $id = $item.Id
    $message = $item.Message
    $key = "$($providerName)|$($id)"

    $kind = switch ($key) {
        'Microsoft-Windows-Kernel-General|12' { 'Boot'; break }
        'Microsoft-Windows-Kernel-General|13' { 'NormalShutdown'; break }
        'Microsoft-Windows-Kernel-Power|41' { 'AbnormalShutdown'; break }

        'User32|1074' {
            if ($message -match 'TrustedInstaller|Windows Update|Operating System: Upgrade') {
                'WindowsUpdatesRestart'
            } else {
                'PlannedShutdownOrRestart'
            }
            break
        }

        'User32|1076' { 'UnexpectedShutdownFollowup'; break }
        'EventLog|6005' { 'Boot'; break }
        'EventLog|6006' { 'NormalShutdown'; break }
        'EventLog|6008' { 'AbnormalShutdown'; break }
        'Microsoft-Windows-WER-SystemErrorReporting|1001' { 'BugCheck'; break }
        'BugCheck|1001' { 'BugCheck'; break }
        'volmgr|46' { 'CrashDump'; break }
        'volmgr|161' { 'CrashDump'; break }

        'Microsoft-Windows-WindowsUpdateClient|43' { 'WindowsUpdatesInstallStarted'; break }
        'Microsoft-Windows-WindowsUpdateClient|19' { 'WindowsUpdatesInstallCompleted'; break }
        'Microsoft-Windows-WindowsUpdateClient|21' { 'WindowsUpdatesRestartRequired'; break }

        default { 'Other' }
    }

    [pscustomobject]@{
        Level       = $item.LevelDisplayName
        Time        = $item.Event.TimeCreated
        Kind        = $kind
        Description = if ([string]::IsNullOrWhiteSpace($item.Description)) {
            "(id $($id) from $($providerName))"
        } else {
            "$($item.Description) (id $($id) from $($providerName))"
        }
    }
}
