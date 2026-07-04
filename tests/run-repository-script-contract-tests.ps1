<#
.SYNOPSIS
Runs repository-level contract tests for published standalone scripts.

.DESCRIPTION
This repository publishes root-level script files as standalone downloads.
These tests avoid executing those scripts. Instead they verify the static
contract that matters for a script collection: each publishable PowerShell
script parses successfully and the test inventory has at least one focused
PowerShell test harness.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

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

function Get-PublishablePowerShellScript {
  Get-ChildItem -LiteralPath $repoRoot -File -Filter *.ps1 |
    Sort-Object Name
}

$tests = @(
  @{
    Name = 'Every publishable PowerShell script parses without executing it'
    Body = {
      $scripts = @(Get-PublishablePowerShellScript)

      Assert-True ($scripts.Count -gt 0) 'Expected at least one publishable PowerShell script.'

      foreach ($script in $scripts) {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
          $script.FullName,
          [ref]$tokens,
          [ref]$errors
        ) | Out-Null

        if ($errors) {
          $relativePath = $script.FullName.Substring($repoRoot.Length).TrimStart('\')
          $messages = @($errors | ForEach-Object { "$($_.Extent.StartLineNumber):$($_.Extent.StartColumnNumber) $($_.Message)" })
          throw "Parse errors in ${relativePath}:`n$($messages -join "`n")"
        }
      }
    }
  },
  @{
    Name = 'Publishable script discovery excludes release and test harness scripts'
    Body = {
      $scripts = @(Get-PublishablePowerShellScript)
      $names = @($scripts | Select-Object -ExpandProperty Name)

      Assert-True ($names -contains 'WindowsUpdatesHelper.ps1') 'Expected root-level standalone scripts to be publishable.'
      Assert-True ($names -contains 'helpers-text-files.ps1') 'Expected root-level function containers to be publishable.'
      Assert-True (-not ($names -contains 'Publish-NewRelease.ps1')) 'Release automation should not be part of the published script set.'
      Assert-True (-not ($names -contains 'run-edit-textfile-tests.ps1')) 'Test harness scripts should not be part of the published script set.'
    }
  },
  @{
    Name = 'Repository has focused PowerShell test harnesses'
    Body = {
      $testScripts = @(Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter 'run-*-tests.ps1')

      Assert-True ($testScripts.Count -ge 3) 'Expected focused PowerShell test harnesses under tests.'
      Assert-Equal @($testScripts | Where-Object Name -eq 'run-repository-script-contract-tests.ps1').Count 1 'Expected this contract test to be discoverable by the release gate.'
    }
  }
)

$passed = 0
foreach ($test in $tests) {
  Invoke-TestCase -Name $test.Name -Body $test.Body
  $passed++
}

Write-Host ''
Write-Host "All $passed repository script contract tests passed." -ForegroundColor Green
