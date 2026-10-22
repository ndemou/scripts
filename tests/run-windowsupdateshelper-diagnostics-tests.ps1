<#
.SYNOPSIS
Tests install diagnostics without running Windows Update or scheduled tasks.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\WindowsUpdatesHelper.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  $scriptPath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors) { throw $parseErrors[0].Message }

# Import only the formatter and isolate the diagnostic statement. Never run
# the script entry point or the rest of the install function.
$formatter = $ast.Find({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-DbgDump'
}, $true)
. ([scriptblock]::Create($formatter.Extent.Text))
$install = $ast.Find({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-InstallPhase'
}, $true)
$diagnostics = @($install.Body.EndBlock.Statements | Where-Object { $_.Extent.Text -match 'InstallPhase.ParamsAndEnv' })
if ($diagnostics.Count -ne 1) { throw 'Expected one install diagnostic statement.' }
$diagnosticBlock = [scriptblock]::Create($diagnostics[0].Extent.Text)

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Invoke-DiagnosticCase {
  param([bool]$Enabled, [switch]$FailRegistryRead)

  $script:WuDebugOutputEnabled = $Enabled
  $messages = [System.Collections.Generic.List[string]]::new()
  $registryReads = [System.Collections.Generic.List[string]]::new()

  function Write-Host {
    param($Object, $ForegroundColor)
    $messages.Add([string]$Object)
  }
  function Get-CimInstance { throw 'Install diagnostics must not query WMI.' }
  function Get-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath)

    Assert-True ($messages.Count -gt 0) 'Expected a progress message before reading the registry.'
    $registryReads.Add($LiteralPath)
    if ($FailRegistryRead) { Write-Error 'Simulated registry read failure'; return }
    [pscustomobject]@{ ProductName = 'Test Windows'; CurrentBuild = '12345' }
  }

  & $diagnosticBlock
  [pscustomobject]@{ Messages = $messages; RegistryReads = $registryReads }
}

$disabled = Invoke-DiagnosticCase -Enabled $false
Assert-True ($disabled.RegistryReads.Count -eq 0) 'Debug-disabled runs must not collect OS diagnostics.'
Assert-True ($disabled.Messages.Count -eq 0) 'Debug-disabled runs must not print install diagnostics.'
Write-Host 'PASS    Debug-disabled runs skip diagnostic collection.'

$enabled = Invoke-DiagnosticCase -Enabled $true
Assert-True ($enabled.RegistryReads.Count -eq 1) 'Expected one registry read for debug output.'
Assert-True ($enabled.RegistryReads[0] -eq 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') 'Unexpected registry path.'
$dump = $enabled.Messages[$enabled.Messages.Count - 1] | ConvertFrom-Json
Assert-True ($dump.OS.ProductName -eq 'Test Windows' -and $dump.OS.CurrentBuild -eq '12345') 'Expected registry OS metadata in the JSON dump.'
Write-Host 'PASS    Debug-enabled runs use registry metadata and log before reading it.'

$failed = Invoke-DiagnosticCase -Enabled $true -FailRegistryRead
Assert-True ($failed.RegistryReads.Count -eq 1) 'Expected the failing registry read to be attempted once.'
Assert-True (($failed.Messages -join "`n") -match 'WARNING:.*Simulated registry read failure') 'Expected a diagnostic warning.'
$dump = $failed.Messages[$failed.Messages.Count - 1] | ConvertFrom-Json
Assert-True ($dump.OS -eq 'unavailable') 'Expected an unavailable marker after a registry error.'
Assert-True ($dump.PID -eq $PID -and $dump.PSVersion -eq $PSVersionTable.PSVersion.ToString()) 'Expected remaining diagnostics after a registry error.'
Write-Host 'PASS    Registry errors remain non-fatal and preserve the remaining diagnostics.'

Write-Host 'All 3 WindowsUpdatesHelper diagnostic tests passed.' -ForegroundColor Green
