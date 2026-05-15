<#
.SYNOPSIS
Runs focused regression tests for Edit-TextFile.

.DESCRIPTION
Creates temporary files under the system temp directory, exercises the main
Edit-TextFile behaviors, and throws if any assertion fails. Intended as a
lightweight local regression harness without external test dependencies.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\helpers-text-files.ps1')

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

function New-TestFile {
  param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Content,
    [switch]$Utf8Bom
  )

  $path = Join-Path $Directory $Name
  if ($Utf8Bom) {
    $enc = [System.Text.UTF8Encoding]::new($true)
    [System.IO.File]::WriteAllText($path, $Content, $enc)
  } else {
    $enc = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($path, $Content, $enc)
  }
  return $path
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

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("edit-textfile-tests-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

$tests = @(
  @{
    Name = 'Regex replacement updates content and creates backup'
    Body = {
      $file = New-TestFile -Directory $tempRoot -Name 'regex.ps1' -Content "alpha`r`nbeta`r`n" -Utf8Bom
      $result = Edit-TextFile -File $file -Pattern 'beta' -Replacement 'gamma'

      Assert-True ($result.Changed) 'Expected regex replacement to report Changed=$true.'
      Assert-Equal $result.Details 'Changes made' 'Unexpected Details for regex replacement.'
      Assert-Equal ([System.IO.File]::ReadAllText($file)) "alpha`r`ngamma`r`n" 'Regex replacement did not update file contents.'
      Assert-True (Test-Path -LiteralPath "$file.bak") 'Expected default backup file to be created.'
      Assert-Equal ([System.IO.File]::ReadAllText("$file.bak")) "alpha`r`nbeta`r`n" 'Backup file did not preserve original content.'
    }
  },
  @{
    Name = 'Literal replacement treats regex metacharacters as plain text'
    Body = {
      $file = New-TestFile -Directory $tempRoot -Name 'literal.ps1' -Content 'foo? + foo?'
      $result = Edit-TextFile -File $file -Pattern 'foo?' -Replacement 'bar' -Literal -Backup ''

      Assert-True ($result.Changed) 'Expected literal replacement to report Changed=$true.'
      Assert-Equal ([System.IO.File]::ReadAllText($file)) 'bar + bar' 'Literal replacement did not treat the pattern as plain text.'
      Assert-True (-not (Test-Path -LiteralPath "$file.bak")) 'Did not expect a backup file when -Backup "" is used.'
    }
  },
  @{
    Name = 'ReplaceMap applies substitutions sequentially'
    Body = {
      $file = New-TestFile -Directory $tempRoot -Name 'map.ps1' -Content 'cat dog'
      $map = [ordered]@{
        'cat' = 'dog'
        'dog' = 'fox'
      }
      $result = Edit-TextFile -File $file -ReplaceMap $map -Backup ''

      Assert-True ($result.Changed) 'Expected ReplaceMap to report Changed=$true.'
      Assert-Equal ([System.IO.File]::ReadAllText($file)) 'fox fox' 'ReplaceMap did not apply substitutions sequentially.'
    }
  },
  @{
    Name = 'Pattern not found reports no change'
    Body = {
      $file = New-TestFile -Directory $tempRoot -Name 'not-found.ps1' -Content 'keep this'
      $result = Edit-TextFile -File $file -Pattern 'missing' -Replacement 'new' -Backup ''

      Assert-True (-not $result.Changed) 'Expected a missing pattern to report Changed=$false.'
      Assert-Equal $result.Details 'Pattern(s) not found' 'Unexpected Details for missing pattern.'
      Assert-Equal ([System.IO.File]::ReadAllText($file)) 'keep this' 'File content changed even though the pattern was not found.'
    }
  },
  @{
    Name = 'Empty file is ignored'
    Body = {
      $file = Join-Path $tempRoot 'empty.ps1'
      [System.IO.File]::WriteAllBytes($file, [byte[]]@())
      $result = Edit-TextFile -File $file -Pattern 'x' -Replacement 'y' -Backup ''

      Assert-True (-not $result.Changed) 'Expected an empty file to report Changed=$false.'
      Assert-Equal $result.Details 'Ignored empty file' 'Unexpected Details for empty file.'
    }
  },
  @{
    Name = 'Invalid regex throws before file processing'
    Body = {
      $file = New-TestFile -Directory $tempRoot -Name 'invalid-regex.ps1' -Content 'c:\it\logs'
      $threw = $false

      try {
        Edit-TextFile -File $file -Pattern 'c:\it\logs' -Replacement 'c:\it\log' -ErrorAction Stop | Out-Null
      }
      catch {
        $threw = $true
        Assert-True ($_.Exception.Message -like "Invalid regex or replace failed on pattern 'c:\it\logs':*") 'Unexpected error message for invalid regex.'
      }

      Assert-True $threw 'Expected invalid regex input to throw.'
      Assert-Equal ([System.IO.File]::ReadAllText($file)) 'c:\it\logs' 'File content changed even though regex validation should fail immediately.'
    }
  }
)

$passed = 0
try {
  foreach ($test in $tests) {
    Invoke-TestCase -Name $test.Name -Body $test.Body
    $passed++
  }

  Write-Host ''
  Write-Host "All $passed Edit-TextFile tests passed." -ForegroundColor Green
}
finally {
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
