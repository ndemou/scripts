<#
.SYNOPSIS
Runs all local tests and rebuilds index.html when they pass.

.DESCRIPTION
This is the publish step for this repository's static script index, not a
GitHub Release workflow. It executes every PowerShell test script under
.\tests\ and stops on the first failure. If all tests pass, it runs
python .\build_index.py to regenerate index.html.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testsRoot = Join-Path $repoRoot 'tests'
$buildIndexPath = Join-Path $repoRoot 'build_index.py'

if (-not (Test-Path -LiteralPath $testsRoot -PathType Container)) {
  throw "Tests folder not found: $testsRoot"
}

if (-not (Test-Path -LiteralPath $buildIndexPath -PathType Leaf)) {
  throw "build_index.py not found: $buildIndexPath"
}

$testScripts = @(Get-ChildItem -LiteralPath $testsRoot -Recurse -File -Filter *.ps1 | Sort-Object FullName)
if ($testScripts.Count -eq 0) {
  throw "No test scripts were found under $testsRoot"
}

Push-Location $repoRoot
try {
  foreach ($testScript in $testScripts) {
    $relativePath = $testScript.FullName.Substring($repoRoot.Length).TrimStart('\')
    Write-Host "Running $relativePath" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File $testScript.FullName
    if ($LASTEXITCODE -ne 0) {
      throw "Test script failed with exit code ${LASTEXITCODE}: $relativePath"
    }
  }

  Write-Host "Running build_index.py" -ForegroundColor Cyan
  & python $buildIndexPath
  if ($LASTEXITCODE -ne 0) {
    throw "build_index.py failed with exit code $LASTEXITCODE"
  }

  Write-Host "Publish completed successfully." -ForegroundColor Green
}
finally {
  Pop-Location
}
