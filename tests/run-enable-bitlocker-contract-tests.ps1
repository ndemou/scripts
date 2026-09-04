<#
.SYNOPSIS
Checks the security and interactive-workflow contracts of the BitLocker script.

.DESCRIPTION
Parses Invoke-EnableBitLockerForDriveC.ps1 without executing its BitLocker,
directory, TPM, or device-registration operations. Pure formatting and parsing
helpers are loaded from the AST for focused behavior checks.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot '..\Invoke-EnableBitLockerForDriveC.ps1'
$source = [System.IO.File]::ReadAllText($scriptPath)
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  $scriptPath,
  [ref]$tokens,
  [ref]$parseErrors
)

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

function Import-FunctionFromScriptAst {
  param([Parameter(Mandatory)][string]$Name)

  $functionAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq $Name
  }, $true)

  if ($null -eq $functionAst) {
    throw "Function not found: $Name"
  }

  Invoke-Expression ('function script:{0} {1}' -f $Name, $functionAst.Body.Extent.Text)
  return $functionAst.Body.Extent.Text
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

$tests = @(
  @{
    Name = 'Script parses and expected stops use the interactive problem UI'
    Body = {
      Assert-Equal @($parseErrors).Count 0 'The BitLocker script has parse errors.'
      Assert-True ($source -notmatch '(?m)^#Requires\s+-RunAsAdministrator\s*$') 'RunAsAdministrator would bypass the friendly elevation message.'
      Assert-True ($source -match 'function Write-Problem') 'Expected the red interactive problem UI.'
      Assert-True ($source -match "No usable recovery escrow destination[\s\S]+Write-Problem") 'Expected unavailable escrow to use the interactive problem UI.'
    }
  },
  @{
    Name = 'Recovery secret warning streams are suppressed without suppressing errors'
    Body = {
      Assert-True ($source -match "WarningAction\s*=\s*'SilentlyContinue'") 'Enable-BitLocker does not suppress its warning stream.'
      Assert-True ($source -match '(?s)Add-BitLockerKeyProtector.+?-WarningAction\s+SilentlyContinue.+?-ErrorAction\s+Stop') 'Add-BitLockerKeyProtector stream handling changed unexpectedly.'
      Assert-True ($source -match "ErrorAction\s*=\s*'Stop'") 'Enable-BitLocker must keep terminating errors enabled.'
    }
  },
  @{
    Name = 'Protection is auto-resumed only for a fully encrypted volume'
    Body = {
      Assert-True ($source -match '\$currentStatus\s+-eq\s+''FullyEncrypted''\s+-and\s+\$currentProtection\s+-eq\s+''Off''') 'The resume guard does not require FullyEncrypted plus ProtectionStatus Off.'
      Assert-True ($source -notmatch '\$currentStatus\s+-ne\s+''FullyDecrypted''\s+-and\s+\$currentProtection\s+-eq\s+''Off''') 'The unsafe broad resume guard is still present.'
    }
  },
  @{
    Name = 'Relevant FVE policy values are read and explained'
    Body = {
      $null = Import-FunctionFromScriptAst -Name 'Format-FvePolicyValue'
      foreach ($name in @(
        'OSRecovery',
        'OSRecoveryPassword',
        'OSRecoveryKey',
        'OSActiveDirectoryBackup',
        'OSRequireActiveDirectoryBackup',
        'OSActiveDirectoryInfoToStore'
      )) {
        Assert-True ($source.Contains($name)) "Missing FVE policy value: $name"
      }
      Assert-Equal (Format-FvePolicyValue -Name OSRecoveryPassword -Value 1) '1 (required)' 'Unexpected recovery-password policy description.'
      Assert-Equal (Format-FvePolicyValue -Name OSRecoveryKey -Value 2) '2 (allowed)' 'Unexpected recovery-key policy description.'
      Assert-Equal (Format-FvePolicyValue -Name OSActiveDirectoryInfoToStore -Value 1) '1 (recovery passwords and key packages)' 'Unexpected AD information policy description.'
    }
  },
  @{
    Name = 'Entra status parsing supports hybrid join and device health output'
    Body = {
      $null = Import-FunctionFromScriptAst -Name 'Get-DsRegStatusValue'
      $sample = @(
        '  AzureAdJoined : YES',
        '  DomainJoined : YES',
        '  DeviceAuthStatus : SUCCESS'
      )
      Assert-Equal (Get-DsRegStatusValue -Output $sample -Name AzureAdJoined) 'YES' 'AzureAdJoined was not parsed.'
      Assert-Equal (Get-DsRegStatusValue -Output $sample -Name DomainJoined) 'YES' 'DomainJoined was not parsed.'
      Assert-Equal (Get-DsRegStatusValue -Output $sample -Name DeviceAuthStatus) 'SUCCESS' 'DeviceAuthStatus was not parsed.'
      Assert-True ($source.Contains('Yes - Hybrid joined')) 'Hybrid join is not reported explicitly.'
    }
  },
  @{
    Name = 'AD verification compares only the recovery GUID and remains best effort'
    Body = {
      $verificationFunction = Import-FunctionFromScriptAst -Name 'Test-AdRecoveryProtectorRecord'
      Assert-True ($verificationFunction -match 'msFVE-RecoveryGuid') 'AD verification does not read the recovery GUID.'
      Assert-True ($verificationFunction -notmatch 'msFVE-RecoveryPassword') 'AD verification must never read the recovery password.'
      Assert-True ($source.Contains("State  = 'Unavailable'")) 'AD read restrictions must be represented as unavailable, not failure.'
      Assert-True ($source.Contains("State = 'Not confirmed'")) 'An inconclusive AD lookup must not be represented as failure.'
    }
  }
)

$passed = 0
foreach ($test in $tests) {
  Invoke-TestCase -Name $test.Name -Body $test.Body
  $passed++
}

Write-Host ''
Write-Host "All $passed BitLocker contract tests passed." -ForegroundColor Green
