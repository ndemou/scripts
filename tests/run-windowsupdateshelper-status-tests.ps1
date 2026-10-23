<#
.SYNOPSIS
Exercises the complete status entry point with a fake WUA session and no system changes.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$statusTestState = @{}
$scriptPath = Join-Path $PSScriptRoot '..\WindowsUpdatesHelper.ps1'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Throws {
    param([scriptblock]$Action)
    $caught = $false
    try { & $Action | Out-Null } catch { $caught = $true }
    Assert-True $caught 'Expected the invocation to fail.'
}

# Intercept every COM creation. Only a search session is available, so attempts
# to create an installer/downloader cannot reach Windows Update.
function New-Object {
    [CmdletBinding()]
    param([string]$ComObject, [string]$TypeName)
    $statusTestState.ComCalls++
    Assert-True ($ComObject -eq 'Microsoft.Update.Session') 'Unexpected object creation.'
    $statusTestState.Session
}
function Fail-SideEffect {
    $statusTestState.SideEffects++
    throw 'Status attempted an operation outside the read-only search.'
}
function Get-ScheduledTask { Fail-SideEffect }
function Unregister-ScheduledTask { Fail-SideEffect }
function Register-ScheduledTask { Fail-SideEffect }
function Start-Transcript { Fail-SideEffect }
function Set-Content { Fail-SideEffect }
function Remove-Item { Fail-SideEffect }
function Start-Service { Fail-SideEffect }
function Add-Type { Fail-SideEffect }
function shutdown.exe { Fail-SideEffect }
function Write-Host { param($Object, $ForegroundColor) $statusTestState.Messages += [string]$Object }

$statusTestState.ComCalls = 0
$statusTestState.SideEffects = 0
$statusTestState.Messages = @()
$statusTestState.Searches = @()
$statusTestState.SearchFailure = $false
$statusTestState.ResultCode = 2
$statusTestState.Updates = @(
    [pscustomobject]@{ IsDownloaded = $true; KBArticleIDs = @('123', '456'); Title = 'Downloaded update'; Identity = [pscustomobject]@{ UpdateID = 'downloaded' } },
    [pscustomobject]@{ IsDownloaded = $false; KBArticleIDs = @('789'); Title = 'Available update'; Identity = [pscustomobject]@{ UpdateID = 'available' } },
    [pscustomobject]@{ IsDownloaded = $true; KBArticleIDs = @(); Title = 'Optional interactive driver'; Identity = [pscustomobject]@{ UpdateID = 'optional' } }
)
$statusTestState.Collection = [pscustomobject]@{ Count = $statusTestState.Updates.Count }
$statusTestState.Collection | Add-Member ScriptMethod Item { param($Index) $statusTestState.Updates[$Index] }
$statusTestState.Searcher = [pscustomobject]@{ Online = $null; CanAutomaticallyUpgradeService = $true; ServerSelection = 0 }
$statusTestState.Searcher | Add-Member ScriptMethod Search {
    param($Criteria)
    $statusTestState.Searches += [pscustomobject]@{ Online = $this.Online; Criteria = $Criteria }
    if ($statusTestState.SearchFailure) { throw 'Simulated scan failure' }
    [pscustomobject]@{ ResultCode = $statusTestState.ResultCode; Updates = $statusTestState.Collection }
}
$statusTestState.Session = [pscustomobject]@{}
$statusTestState.Session | Add-Member ScriptMethod CreateUpdateSearcher { $statusTestState.Searcher }

$offline = @(& $scriptPath -Status offline)
Assert-True ($offline.Count -eq 2 -and ($offline.UpdateID -join ',') -eq 'downloaded,optional') 'Offline must return only downloaded updates, including optional/interactive updates.'
Assert-True (-not $statusTestState.Searches[0].Online) 'Offline must not scan online.'
Assert-True ($offline[0].Downloaded -is [bool] -and $offline[0].KB -eq '123, 456' -and $offline[1].KB -eq '') 'Return usable objects, including multiple or absent KB IDs.'
$online = @(& $scriptPath -Status ONLINE)
Assert-True ($online.Count -eq 3 -and -not $online[1].Downloaded) 'Online must return downloaded and undownloaded updates.'
Assert-True $statusTestState.Searches[1].Online 'Online must scan online.'
Assert-True (-not $statusTestState.Searcher.CanAutomaticallyUpgradeService -and $statusTestState.Searcher.ServerSelection -eq 0) 'Disable agent self-upgrades and preserve the configured source.'
foreach ($search in $statusTestState.Searches) {
    $groups = @($search.Criteria -split ' or ')
    Assert-True ($groups.Count -eq 2) 'Search normal and optional installation deployments.'
    foreach ($group in $groups) {
        Assert-True ($group.Contains('IsInstalled=0') -and $group.Contains('IsHidden=0')) 'Exclude installed and hidden updates in both groups.'
    }
    Assert-True ($groups[0].Contains("DeploymentAction='Installation'") -and $groups[1].Contains("DeploymentAction='OptionalInstallation'")) 'Include both kinds of installation deployment.'
}

$statusTestState.Collection.Count = 0
$empty = @(& $scriptPath -Status Offline)
Assert-True ($empty.Count -eq 0 -and $statusTestState.Messages[-1] -match 'Found 0 pending') 'Empty results must produce no data objects and a clear message.'
$statusTestState.Collection.Count = $statusTestState.Updates.Count
foreach ($code in @(3, 4, 5)) {
    $statusTestState.ResultCode = $code
    Assert-Throws { & $scriptPath -Status Online }
}
$statusTestState.ResultCode = 2
$statusTestState.SearchFailure = $true
Assert-Throws { & $scriptPath -Status Offline }
$statusTestState.SearchFailure = $false

$before = $statusTestState.ComCalls
Assert-Throws { & $scriptPath -Status invalid }
foreach ($option in @('Download', 'Reboot', 'RebootAnyway', 'Interactive', 'AbortReboot', 'ShowHistory', 'ListRecentLogs', 'XXX_RebootNow', 'XXX_ResumeAfterReboot', 'XXX_ContinueAfterReboot')) {
    $arguments = @{ Status = 'Online' }
    $arguments[$option] = $true
    Assert-Throws { & $scriptPath @arguments }
}
foreach ($option in @('RebootAt', 'InstallOptional', 'XXX_RebootArmedAt', 'XXX_ScheduledRebootAt', 'XXX_RebootAtUntil')) {
    $arguments = @{ Status = 'Offline' }
    $arguments[$option] = '2026-11-01T06:14:00Z'
    Assert-Throws { & $scriptPath @arguments }
}
Assert-True ($statusTestState.ComCalls -eq $before) 'Invalid/mixed modes must fail during binding, before any search.'
Assert-True ($statusTestState.SideEffects -eq 0) 'Status must not touch logging, task cleanup, installation setup, or shutdown, even on failure.'
Write-Output 'All WindowsUpdatesHelper status tests passed.'
