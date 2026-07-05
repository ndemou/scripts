<#
.SYNOPSIS
Runs focused regression tests for helpers-processes.ps1.

.DESCRIPTION
Exercises command-line construction helpers without starting scheduled tasks,
remote sessions, or CIM processes.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\helpers-processes.ps1')

function Assert-True {
  param(
    [Parameter(Mandatory)][bool]$Condition,
    [Parameter(Mandatory)][string]$Message
  )

  if (-not $Condition) {
    throw $Message
  }
}

function Assert-Equal {
  param(
    [Parameter(Mandatory)]$Actual,
    [Parameter(Mandatory)]$Expected,
    [Parameter(Mandatory)][string]$Message
  )

  if ($Actual -cne $Expected) {
    throw "$Message`nExpected: $Expected`nActual:   $Actual"
  }
}

function Invoke-TestCase {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Body
  )

  Write-Host "Running $Name"
  & $Body
  Write-Host "PASS    $Name" -ForegroundColor Green
}

function Get-EncodedCommandText {
  param([Parameter(Mandatory)][string]$CommandLine)

  if ($CommandLine -notmatch '(?:^|\s)-EncodedCommand\s+([A-Za-z0-9+/=]+)(?:\s|$)') {
    throw "Command line does not contain an unquoted -EncodedCommand argument: $CommandLine"
  }

  [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
}

$tests = @(
  @{
    Name = 'PowerShell single-quoted literals escape apostrophes'
    Body = {
      $literal = ConvertTo-PowerShellSingleQuotedString -Value "C:\Temp\O'Brien.ps1"

      Assert-Equal $literal "'C:\Temp\O''Brien.ps1'" 'Apostrophes must be doubled inside PowerShell single-quoted literals.'
    }
  },
  @{
    Name = 'Remote command with transcript encodes escaped literal paths'
    Body = {
      $commandLine = New-DetachedPSScriptRemoteCommandLine `
        -PowerShellPath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -RemoteScriptPath "C:\Temp\safe'; Start-Process calc; '.ps1" `
        -LogFile "C:\Temp\x'; Start-Process calc; 'y.log"

      Assert-True ($commandLine -like '* -EncodedCommand *') 'Expected transcript mode to use -EncodedCommand.'
      Assert-True (-not ($commandLine -like '* -Command *')) 'Transcript mode should not pass interpolated source through -Command.'

      $decoded = Get-EncodedCommandText -CommandLine $commandLine
      $expected = "Start-Transcript -Path 'C:\Temp\x''; Start-Process calc; ''y.log' -Append -Force; try { & 'C:\Temp\safe''; Start-Process calc; ''.ps1' } finally { Stop-Transcript }"

      Assert-Equal $decoded $expected 'Encoded transcript command did not escape apostrophes in path literals.'
    }
  },
  @{
    Name = 'Remote command without transcript uses File argument'
    Body = {
      $commandLine = New-DetachedPSScriptRemoteCommandLine `
        -PowerShellPath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        -RemoteScriptPath "C:\Temp\O'Brien.ps1"

      Assert-True ($commandLine -like '* -File *') 'Expected no-transcript mode to launch with -File.'
      Assert-True (-not ($commandLine -like '*-EncodedCommand*')) 'Did not expect -EncodedCommand when no transcript wrapper is needed.'
      Assert-True ($commandLine -like "*O'Brien.ps1*") 'Expected the remote script path to be preserved as a process argument.'
    }
  }
)

$passed = 0
foreach ($test in $tests) {
  Invoke-TestCase -Name $test.Name -Body $test.Body
  $passed++
}

Write-Host ''
Write-Host "All $passed helpers-processes tests passed." -ForegroundColor Green
