function Get-BootShutdownEvents {
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
}
