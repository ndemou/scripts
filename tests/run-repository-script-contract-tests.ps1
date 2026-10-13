<#
.SYNOPSIS
Runs repository-level contract tests for published standalone scripts.

.DESCRIPTION
This repository publishes root-level script files as standalone downloads.
These tests avoid executing those scripts. Instead they verify the static
contract that matters for a script collection: each root-level PowerShell
script is BOM-free ASCII, parses successfully, and the test inventory has
at least one focused PowerShell test harness. The byte check also rejects
NUL bytes so BOM-free UTF-16/UTF-32 cannot pass as ASCII script text.
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
  Get-ChildItem -LiteralPath $repoRoot -File -Force -Filter *.ps1 |
    Sort-Object Name
}

function Get-AsciiByteViolation {
  param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

  # Read bytes, not decoded text: a reader could silently strip the BOM or
  # replace invalid characters before the check sees them.
  for ($offset = 0; $offset -lt $Bytes.Length; $offset++) {
    if ($Bytes[$offset] -gt 0x7F -or $Bytes[$offset] -eq 0) {
      return [pscustomobject]@{
        Offset = $offset
        Byte = $Bytes[$offset]
        Reason = if ($Bytes[$offset] -eq 0) { 'NUL byte' } else { 'non-ASCII byte / possible BOM' }
      }
    }
  }
}

$tests = @(
  @{
    Name = 'ASCII byte check accepts plain text and detects BOMs and Unicode'
    Body = {
      foreach ($bytes in @([byte[]]@(), [byte[]]@(9, 10, 13, 32, 65, 126, 127))) {
        Assert-True ($null -eq (Get-AsciiByteViolation -Bytes $bytes)) 'Valid ASCII bytes were rejected.'
      }

      $invalidCases = @(
        @{ Name = 'UTF-8 BOM'; Bytes = [byte[]]@(239, 187, 191, 65); Offset = 0 },
        @{ Name = 'UTF-16LE BOM'; Bytes = [byte[]]@(255, 254, 65, 0); Offset = 0 },
        @{ Name = 'UTF-16BE BOM'; Bytes = [byte[]]@(254, 255, 0, 65); Offset = 0 },
        @{ Name = 'UTF-32LE BOM'; Bytes = [byte[]]@(255, 254, 0, 0, 65, 0, 0, 0); Offset = 0 },
        @{ Name = 'UTF-32BE BOM'; Bytes = [byte[]]@(0, 0, 254, 255, 0, 0, 0, 65); Offset = 0 },
        @{ Name = 'UTF-8 character in body'; Bytes = [byte[]]@(65, 10, 206, 177); Offset = 2 },
        @{ Name = 'UTF-8 emoji'; Bytes = [byte[]]@(240, 159, 152, 128); Offset = 0 },
        @{ Name = 'high-bit byte'; Bytes = [byte[]]@(65, 128); Offset = 1 },
        @{ Name = 'partial BOM'; Bytes = [byte[]]@(239, 187); Offset = 0 },
        @{ Name = 'UTF-16 without BOM'; Bytes = [byte[]]@(65, 0); Offset = 1 },
        @{ Name = 'UTF-32 without BOM'; Bytes = [byte[]]@(65, 0, 0, 0); Offset = 1 }
      )
      foreach ($case in $invalidCases) {
        $violation = Get-AsciiByteViolation -Bytes $case.Bytes
        Assert-True ($null -ne $violation) "Failed to reject $($case.Name)."
        Assert-Equal $violation.Offset $case.Offset "Wrong byte offset for $($case.Name)."
        Assert-Equal $violation.Byte $case.Bytes[$case.Offset] "Wrong offending byte for $($case.Name)."
      }
    }
  },
  @{
    Name = 'Every root-level PowerShell script is ASCII only with no BOM'
    Body = {
      $scripts = @(Get-PublishablePowerShellScript)
      Assert-True ($scripts.Count -gt 0) 'Expected at least one root-level PowerShell script.'

      $violations = @(
        foreach ($script in $scripts) {
          $violation = Get-AsciiByteViolation -Bytes ([IO.File]::ReadAllBytes($script.FullName))
          if ($null -ne $violation) {
            '{0}: byte offset {1} = 0x{2:X2} ({3})' -f $script.Name, $violation.Offset, $violation.Byte, $violation.Reason
          }
        }
      )
      Assert-True ($violations.Count -eq 0) ("Scripts must be BOM-free ASCII text (offsets are zero-based):`n" + ($violations -join "`n"))
    }
  },
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
      Assert-Equal @($testScripts | Where-Object Name -eq 'run-get-textfileencoding-tests.ps1').Count 1 'Expected Get-TextFileEncoding tests to be discoverable by the release gate.'
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
