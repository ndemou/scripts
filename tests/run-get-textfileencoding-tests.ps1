<#
.SYNOPSIS
Runs focused regression tests for Get-TextFileEncoding.

.DESCRIPTION
Creates exact-byte fixtures under the system temp directory and exercises
encoding detection without relying on the host PowerShell version's text-file
defaults. Detector-dependent branches use a generated fake uchardet executable.
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
    [Parameter(Mandatory)][AllowNull()]$Actual,
    [Parameter(Mandatory)][AllowNull()]$Expected,
    [Parameter(Mandatory)][string]$Message
  )

  if ($Actual -cne $Expected) {
    throw "$Message`nExpected: $Expected`nActual:   $Actual"
  }
}

function Assert-Null {
  param(
    [AllowNull()]$Actual,
    [Parameter(Mandatory)][string]$Message
  )

  if ($null -ne $Actual) {
    throw "$Message`nExpected: <null>`nActual:   $Actual"
  }
}

function Assert-ByteArrayEqual {
  param(
    [AllowNull()][AllowEmptyCollection()][byte[]]$Actual,
    [AllowNull()][AllowEmptyCollection()][byte[]]$Expected,
    [Parameter(Mandatory)][string]$Message
  )

  $actualBytes = @($Actual)
  $expectedBytes = @($Expected)
  if ($actualBytes.Count -ne $expectedBytes.Count) {
    throw "$Message`nExpected length: $($expectedBytes.Count)`nActual length:   $($actualBytes.Count)"
  }

  for ($i = 0; $i -lt $expectedBytes.Count; $i++) {
    if ($actualBytes[$i] -ne $expectedBytes[$i]) {
      $expectedHex = ($expectedBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
      $actualHex = ($actualBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
      throw "$Message`nExpected: $expectedHex`nActual:   $actualHex"
    }
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

function New-ByteArray {
  param([Parameter(Mandatory)][int[]]$Values)

  $bytes = New-Object byte[] $Values.Count
  for ($i = 0; $i -lt $Values.Count; $i++) {
    $bytes[$i] = [byte]$Values[$i]
  }
  return $bytes
}

function Join-ByteArrays {
  param([Parameter(Mandatory)][byte[][]]$Arrays)

  $length = 0
  foreach ($array in $Arrays) {
    if ($null -ne $array) { $length += $array.Length }
  }

  $result = New-Object byte[] $length
  $offset = 0
  foreach ($array in $Arrays) {
    if ($null -eq $array -or $array.Length -eq 0) { continue }
    [Array]::Copy($array, 0, $result, $offset, $array.Length)
    $offset += $array.Length
  }
  return $result
}

function New-StringFromCodePoints {
  param([Parameter(Mandatory)][int[]]$CodePoints)

  $builder = New-Object System.Text.StringBuilder
  foreach ($codePoint in $CodePoints) {
    [void]$builder.Append([char]$codePoint)
  }
  return $builder.ToString()
}

function Write-TestBytes {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
  )

  $path = Join-Path $script:TempRoot $Name
  $directory = Split-Path -Parent $path
  if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  [System.IO.File]::WriteAllBytes($path, $Bytes)
  return $path
}

function Get-AsciiBytes {
  param([Parameter(Mandatory)][string]$Text)
  return [System.Text.Encoding]::ASCII.GetBytes($Text)
}

function Get-Utf8NoBomBytes {
  param([Parameter(Mandatory)][string]$Text)
  $encoding = New-Object System.Text.UTF8Encoding($false)
  return $encoding.GetBytes($Text)
}

function Get-EncodingBytes {
  param(
    [Parameter(Mandatory)][System.Text.Encoding]$Encoding,
    [Parameter(Mandatory)][string]$Text,
    [switch]$WithPreamble
  )

  $body = $Encoding.GetBytes($Text)
  if (-not $WithPreamble) { return $body }
  return Join-ByteArrays -Arrays @($Encoding.GetPreamble(), $body)
}

function Compile-FakeUchardet {
  param([Parameter(Mandatory)][string]$Directory)

  $source = @'
using System;
using System.IO;
using System.Threading;

public static class FakeUchardet
{
    public static int Main(string[] args)
    {
        string mode = Environment.GetEnvironmentVariable("GTE_FAKE_UCHARDET_MODE");
        if (String.IsNullOrEmpty(mode)) { mode = "iso88591"; }

        string recordPath = Environment.GetEnvironmentVariable("GTE_FAKE_UCHARDET_RECORD_PATH");
        if (!String.IsNullOrEmpty(recordPath) && args.Length > 0)
        {
            FileInfo input = new FileInfo(args[0]);
            File.WriteAllText(recordPath, args[0] + Environment.NewLine + input.Length.ToString());
        }

        switch (mode.ToLowerInvariant())
        {
            case "empty":
                return 0;
            case "nonzero":
                Console.Error.WriteLine("fake uchardet failure");
                return 7;
            case "timeout":
                Thread.Sleep(10000);
                Console.WriteLine("ISO-8859-1");
                return 0;
            case "utf16le":
                Console.WriteLine("UTF-16LE");
                return 0;
            case "windows1252":
                Console.WriteLine("WINDOWS-1252");
                return 0;
            case "iso88591":
                Console.WriteLine("ISO-8859-1");
                return 0;
            default:
                Console.WriteLine(mode);
                return 0;
        }
    }
}
'@

  $exePath = Join-Path $Directory 'fake-uchardet.exe'
  Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $exePath -OutputType ConsoleApplication
  return $exePath
}

function Set-FakeUchardetMode {
  param(
    [Parameter(Mandatory)][string]$Mode,
    [string]$RecordPath
  )

  $env:GTE_FAKE_UCHARDET_MODE = $Mode
  if ([string]::IsNullOrWhiteSpace($RecordPath)) {
    Remove-Item Env:\GTE_FAKE_UCHARDET_RECORD_PATH -ErrorAction SilentlyContinue
  } else {
    $env:GTE_FAKE_UCHARDET_RECORD_PATH = $RecordPath
  }
}

function Clear-FakeUchardetMode {
  Remove-Item Env:\GTE_FAKE_UCHARDET_MODE -ErrorAction SilentlyContinue
  Remove-Item Env:\GTE_FAKE_UCHARDET_RECORD_PATH -ErrorAction SilentlyContinue
}

function Assert-EncodingResult {
  param(
    [Parameter(Mandatory)]$Result,
    [Parameter(Mandatory)][string]$Type,
    [AllowNull()]$EncodingDescription,
    [AllowNull()]$NewlineStyle,
    [AllowEmptyCollection()][byte[]]$BomBytes = @(),
    [AllowNull()]$DotNetWebName
  )

  Assert-Equal $Result.Type $Type 'Unexpected Type.'
  if ($null -eq $EncodingDescription) {
    Assert-Null $Result.EncodingDescription 'Unexpected EncodingDescription.'
  } else {
    Assert-Equal $Result.EncodingDescription $EncodingDescription 'Unexpected EncodingDescription.'
  }
  if ($null -eq $NewlineStyle) {
    Assert-Null $Result.NewlineStyle 'Unexpected NewlineStyle.'
  } else {
    Assert-Equal $Result.NewlineStyle $NewlineStyle 'Unexpected NewlineStyle.'
  }
  Assert-ByteArrayEqual ([byte[]]$Result.BOMBytes) $BomBytes 'Unexpected BOMBytes.'

  if ($null -eq $DotNetWebName) {
    Assert-Null $Result.DotNetEncodingObj 'Unexpected DotNetEncodingObj.'
  } else {
    Assert-True ($null -ne $Result.DotNetEncodingObj) 'Expected a DotNetEncodingObj.'
    if ($Result.DotNetEncodingObj.WebName -ine $DotNetWebName) {
      throw "Unexpected DotNetEncodingObj.WebName.`nExpected: $DotNetWebName`nActual:   $($Result.DotNetEncodingObj.WebName)"
    }
  }
}

function Get-WithErrorCapture {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$UchardetPath,
    [int]$TimeoutMs = 3000
  )

  $beforeErrorCount = $Error.Count
  $result = Get-TextFileEncoding -Path $Path -UchardetPath $UchardetPath -TimeoutMs $TimeoutMs -ErrorAction SilentlyContinue
  $newErrorCount = $Error.Count - $beforeErrorCount
  $newErrors = @()
  for ($i = 0; $i -lt $newErrorCount; $i++) {
    $newErrors += $Error[$i]
  }
  return [pscustomobject]@{
    Result = $result
    Errors = @($newErrors)
  }
}

$script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("get-textfileencoding-tests-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$utf16LeBom = New-Object System.Text.UnicodeEncoding($false, $true)
$utf16BeBom = New-Object System.Text.UnicodeEncoding($true, $true)
$utf32LeBom = New-Object System.Text.UTF32Encoding($false, $true)
$utf32BeBom = New-Object System.Text.UTF32Encoding($true, $true)
$cp1252 = [System.Text.Encoding]::GetEncoding('windows-1252')
$cp1253 = [System.Text.Encoding]::GetEncoding('windows-1253')

$greekText = New-StringFromCodePoints -CodePoints @(0x039A,0x03B1,0x03BB,0x03B7,0x03BC,0x03AD,0x03C1,0x03B1)
$accentedText = 'Cafe ' + [char]0x00E9 + ' resume ' + [char]0x00E9

$fakeUchardet = $null

$tests = @(
  @{
    Name = 'Empty file reports EMPTY with no encoding'
    Body = {
      $file = Write-TestBytes -Name 'empty.txt' -Bytes ([byte[]]@())
      $result = Get-TextFileEncoding -Path $file -ErrorAction Stop

      Assert-EncodingResult -Result $result -Type 'EMPTY' -EncodingDescription $null -NewlineStyle $null -BomBytes ([byte[]]@()) -DotNetWebName $null
      Assert-Equal $result.BytesRead 0 'Expected empty file BytesRead=0.'
      Assert-Equal $result.BytesIgnored 0 'Expected empty file BytesIgnored=0.'
    }
  },
  @{
    Name = 'ASCII files prefer UTF-8 by default and report newline styles'
    Body = {
      $fixtures = @(
        @{ Name = 'ascii-none.txt'; Text = 'alpha beta'; Newline = 'None' },
        @{ Name = 'ascii-crlf.txt'; Text = "alpha`r`nbeta`r`n"; Newline = 'CRLF' },
        @{ Name = 'ascii-lf.txt'; Text = "alpha`nbeta`n"; Newline = 'LF' },
        @{ Name = 'ascii-cr.txt'; Text = "alpha`rbeta`r"; Newline = 'CR' },
        @{ Name = 'ascii-mixed.txt'; Text = "alpha`r`nbeta`ngamma`r"; Newline = 'Mixed' }
      )

      foreach ($fixture in $fixtures) {
        $file = Write-TestBytes -Name $fixture.Name -Bytes (Get-AsciiBytes -Text $fixture.Text)
        $result = Get-TextFileEncoding -Path $file -ErrorAction Stop

        Assert-EncodingResult -Result $result -Type 'ASCII-TEXT' -EncodingDescription 'UTF-8' -NewlineStyle $fixture.Newline -BomBytes ([byte[]]@()) -DotNetWebName 'utf-8'
        Assert-Equal $result.BytesRead ([System.IO.FileInfo]$file).Length "Unexpected BytesRead for $($fixture.Name)."
        Assert-Equal $result.BytesIgnored 0 "Unexpected BytesIgnored for $($fixture.Name)."
      }

      $asciiFile = Join-Path $script:TempRoot 'ascii-none.txt'
      $asciiResult = Get-TextFileEncoding -Path $asciiFile -DontPreferUTF8 -ErrorAction Stop
      Assert-EncodingResult -Result $asciiResult -Type 'ASCII-TEXT' -EncodingDescription 'ASCII' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'us-ascii'
    }
  },
  @{
    Name = 'BOM files report authoritative Unicode encodings'
    Body = {
      $fixtures = @(
        @{ Name = 'bom-utf8.txt'; Encoding = $utf8Bom; Expected = 'UTF-8 (With BOM)'; Bom = (New-ByteArray @(0xEF,0xBB,0xBF)); WebName = 'utf-8' },
        @{ Name = 'bom-utf16le.txt'; Encoding = $utf16LeBom; Expected = 'UTF-16LE (With BOM)'; Bom = (New-ByteArray @(0xFF,0xFE)); WebName = 'utf-16' },
        @{ Name = 'bom-utf16be.txt'; Encoding = $utf16BeBom; Expected = 'UTF-16BE (With BOM)'; Bom = (New-ByteArray @(0xFE,0xFF)); WebName = 'utf-16BE' },
        @{ Name = 'bom-utf32le.txt'; Encoding = $utf32LeBom; Expected = 'UTF-32LE (With BOM)'; Bom = (New-ByteArray @(0xFF,0xFE,0x00,0x00)); WebName = 'utf-32' },
        @{ Name = 'bom-utf32be.txt'; Encoding = $utf32BeBom; Expected = 'UTF-32BE (With BOM)'; Bom = (New-ByteArray @(0x00,0x00,0xFE,0xFF)); WebName = 'utf-32BE' }
      )

      foreach ($fixture in $fixtures) {
        $bytes = Get-EncodingBytes -Encoding $fixture.Encoding -Text 'alpha' -WithPreamble
        $file = Write-TestBytes -Name $fixture.Name -Bytes $bytes
        $result = Get-TextFileEncoding -Path $file -ErrorAction Stop

        Assert-EncodingResult -Result $result -Type 'BOM-TEXT' -EncodingDescription $fixture.Expected -NewlineStyle 'None' -BomBytes $fixture.Bom -DotNetWebName $fixture.WebName
      }
    }
  },
  @{
    Name = 'UTF-8 without BOM covers valid non-ASCII and incomplete final sequence'
    Body = {
      $greekFile = Write-TestBytes -Name 'utf8-greek.txt' -Bytes (Get-Utf8NoBomBytes -Text $greekText)
      $greekResult = Get-TextFileEncoding -Path $greekFile -ErrorAction Stop
      Assert-EncodingResult -Result $greekResult -Type 'NON-ASCII-TEXT' -EncodingDescription 'UTF-8' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'utf-8'

      $accentedFile = Write-TestBytes -Name 'utf8-accented.txt' -Bytes (Get-Utf8NoBomBytes -Text $accentedText)
      $accentedResult = Get-TextFileEncoding -Path $accentedFile -ErrorAction Stop
      Assert-EncodingResult -Result $accentedResult -Type 'NON-ASCII-TEXT' -EncodingDescription 'UTF-8' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'utf-8'

      $incompleteFile = Write-TestBytes -Name 'utf8-incomplete-final-sequence.txt' -Bytes (New-ByteArray @(0x41,0x42,0x43,0xE2,0x82))
      $incompleteResult = Get-TextFileEncoding -Path $incompleteFile -ErrorAction Stop
      Assert-EncodingResult -Result $incompleteResult -Type 'NON-ASCII-TEXT' -EncodingDescription 'UTF-8' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'utf-8'
    }
  },
  @{
    Name = 'Windows producer default fixtures map to expected encodings'
    Body = {
      Set-FakeUchardetMode -Mode 'windows1252'

      $cp1252Bytes = $cp1252.GetBytes('Cafe ' + [char]0x00E9 + '! tail')
      $ansiFixtures = @(
        'notepad-legacy-ansi-cp1252.txt',
        'windows-powershell-5-setcontent-ansi-cp1252.txt'
      )
      foreach ($name in $ansiFixtures) {
        $file = Write-TestBytes -Name $name -Bytes $cp1252Bytes
        $result = Get-TextFileEncoding -Path $file -UchardetPath $fakeUchardet -ErrorAction Stop
        Assert-EncodingResult -Result $result -Type 'NON-ASCII-TEXT' -EncodingDescription 'WINDOWS-1252' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'windows-1252'
      }

      $utf8Fixtures = @(
        'notepad-modern-utf8-nobom.txt',
        'powershell-7-outfile-utf8-nobom.txt',
        'powershell-7-redirection-utf8-nobom.txt',
        'powershell-7-setcontent-utf8-nobom.txt'
      )
      foreach ($name in $utf8Fixtures) {
        $file = Write-TestBytes -Name $name -Bytes (Get-Utf8NoBomBytes -Text ('Cafe ' + [char]0x00E9 + '!'))
        $result = Get-TextFileEncoding -Path $file -ErrorAction Stop
        Assert-EncodingResult -Result $result -Type 'NON-ASCII-TEXT' -EncodingDescription 'UTF-8' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'utf-8'
      }

      $utf16Fixtures = @(
        'windows-powershell-5-outfile-utf16le-bom.txt',
        'windows-powershell-5-redirection-utf16le-bom.txt'
      )
      foreach ($name in $utf16Fixtures) {
        $file = Write-TestBytes -Name $name -Bytes (Get-EncodingBytes -Encoding $utf16LeBom -Text 'alpha' -WithPreamble)
        $result = Get-TextFileEncoding -Path $file -ErrorAction Stop
        Assert-EncodingResult -Result $result -Type 'BOM-TEXT' -EncodingDescription 'UTF-16LE (With BOM)' -NewlineStyle 'None' -BomBytes (New-ByteArray @(0xFF,0xFE)) -DotNetWebName 'utf-16'
      }
    }
  },
  @{
    Name = 'Path resolution handles FileInfo, wildcard, ambiguity, directory, and missing paths'
    Body = {
      $single = Write-TestBytes -Name 'path-single.txt' -Bytes (Get-AsciiBytes 'single')
      $wildcardResult = Get-TextFileEncoding -Path (Join-Path $script:TempRoot 'path-single.*') -ErrorAction Stop
      Assert-Equal $wildcardResult.File.FullName ([System.IO.FileInfo]$single).FullName 'Wildcard should resolve the single matching file.'

      $fileInfoResult = Get-TextFileEncoding -Path ([System.IO.FileInfo]$single) -ErrorAction Stop
      Assert-Equal $fileInfoResult.File.FullName ([System.IO.FileInfo]$single).FullName 'FileInfo input should resolve directly.'

      [void](Write-TestBytes -Name 'path-wildcard-a.txt' -Bytes (Get-AsciiBytes 'a'))
      [void](Write-TestBytes -Name 'path-wildcard-b.txt' -Bytes (Get-AsciiBytes 'b'))

      $ambiguous = @(Get-TextFileEncoding -Path (Join-Path $script:TempRoot 'path-wildcard-*.txt') -ErrorAction SilentlyContinue)
      Assert-Equal $ambiguous.Count 0 'Ambiguous wildcard should produce no result.'

      $directoryResult = @(Get-TextFileEncoding -Path $script:TempRoot -ErrorAction SilentlyContinue)
      Assert-Equal $directoryResult.Count 0 'Directory path should produce no result.'

      $missingResult = @(Get-TextFileEncoding -Path (Join-Path $script:TempRoot 'missing.txt') -ErrorAction SilentlyContinue)
      Assert-Equal $missingResult.Count 0 'Missing path should produce no result.'
    }
  },
  @{
    Name = 'Pipeline input returns one result per file'
    Body = {
      $pipelineA = Write-TestBytes -Name 'pipeline-a.txt' -Bytes (Get-AsciiBytes 'a')
      $pipelineB = Write-TestBytes -Name 'pipeline-b.txt' -Bytes (Get-AsciiBytes 'b')

      $results = @($pipelineA, $pipelineB | Get-TextFileEncoding -ErrorAction Stop)
      Assert-Equal $results.Count 2 'Pipeline input should return two results.'
      Assert-Equal @($results | Where-Object { $_.File.Name -eq 'pipeline-a.txt' }).Count 1 'Expected pipeline-a result.'
      Assert-Equal @($results | Where-Object { $_.File.Name -eq 'pipeline-b.txt' }).Count 1 'Expected pipeline-b result.'
    }
  },
  @{
    Name = 'Invalid UTF-8 in the middle falls through to fake detector'
    Body = {
      $invalid = Write-TestBytes -Name 'invalid-utf8.txt' -Bytes (New-ByteArray @(0x41,0xC3,0x28,0x42,0x43,0x44,0x45))

      Set-FakeUchardetMode -Mode 'iso88591'
      $defaultResult = Get-TextFileEncoding -Path $invalid -UchardetPath $fakeUchardet -ErrorAction Stop
      Assert-EncodingResult -Result $defaultResult -Type 'NON-ASCII-TEXT' -EncodingDescription 'Windows-1252' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'windows-1252'
      Assert-Equal $defaultResult.UCharDetEncoding 'ISO-8859-1' 'Expected fake detector output to be recorded.'

      $isoResult = Get-TextFileEncoding -Path $invalid -UchardetPath $fakeUchardet -PreferISOEncodings -ErrorAction Stop
      Assert-EncodingResult -Result $isoResult -Type 'NON-ASCII-TEXT' -EncodingDescription 'ISO-8859-1' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'iso-8859-1'
    }
  },
  @{
    Name = 'Fake detector UTF output gets no-BOM suffix'
    Body = {
      $invalid = Write-TestBytes -Name 'fake-utf16le-detector.txt' -Bytes (New-ByteArray @(0x41,0xC3,0x28,0x42,0x43,0x44,0x45))
      Set-FakeUchardetMode -Mode 'utf16le'

      $result = Get-TextFileEncoding -Path $invalid -UchardetPath $fakeUchardet -ErrorAction Stop
      Assert-EncodingResult -Result $result -Type 'NON-ASCII-TEXT' -EncodingDescription 'UTF-16LE (No BOM)' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'utf-16'
      Assert-Equal $result.UCharDetEncoding 'UTF-16LE' 'Expected fake UTF-16LE detector output to be recorded.'
    }
  },
  @{
    Name = 'Fake detector failure modes emit errors and return OTHER'
    Body = {
      $invalid = Write-TestBytes -Name 'unknown-ansi-no-uchardet.txt' -Bytes (New-ByteArray @(0x41,0xC3,0x28,0x42,0x43,0x44,0x45))

      foreach ($case in @(
        @{ Mode = 'empty'; Timeout = 3000 },
        @{ Mode = 'nonzero'; Timeout = 3000 },
        @{ Mode = 'timeout'; Timeout = 100 }
      )) {
        Set-FakeUchardetMode -Mode $case.Mode
        $captured = Get-WithErrorCapture -Path $invalid -UchardetPath $fakeUchardet -TimeoutMs $case.Timeout
        Assert-True ($captured.Errors.Count -gt 0) "Expected at least one error for fake detector mode $($case.Mode)."
        Assert-EncodingResult -Result $captured.Result -Type 'OTHER' -EncodingDescription $null -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName $null
      }

      $missingCaptured = Get-WithErrorCapture -Path $invalid -UchardetPath (Join-Path $script:TempRoot 'missing-uchardet.exe')
      Assert-True ($missingCaptured.Errors.Count -gt 0) 'Expected at least one error for missing detector with unknown ANSI.'
      Assert-EncodingResult -Result $missingCaptured.Result -Type 'OTHER' -EncodingDescription $null -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName $null
    }
  },
  @{
    Name = 'Greek ANSI fallback works when detector is missing'
    Body = {
      $greekAnsi = Write-TestBytes -Name 'greek-ansi-fallback.txt' -Bytes ($cp1253.GetBytes($greekText))

      $captured = Get-WithErrorCapture -Path $greekAnsi -UchardetPath (Join-Path $script:TempRoot 'missing-uchardet.exe')
      Assert-EncodingResult -Result $captured.Result -Type 'NON-ASCII-TEXT' -EncodingDescription 'Windows-1253' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'windows-1253'
    }
  },
  @{
    Name = 'Binary-looking invalid samples are forced to OTHER when detector guesses non-UTF'
    Body = {
      Set-FakeUchardetMode -Mode 'iso88591'

      $nulHeavy = Write-TestBytes -Name 'binary-nul-heavy.bin' -Bytes (New-ByteArray @(0x41,0x00,0x00,0x00,0x00,0xC3,0x28,0x00,0x00,0x00,0x42))
      $nulResult = Get-TextFileEncoding -Path $nulHeavy -UchardetPath $fakeUchardet -ErrorAction Stop
      Assert-EncodingResult -Result $nulResult -Type 'OTHER' -EncodingDescription '' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName $null

      $lfcr = Write-TestBytes -Name 'binary-lfcr-pattern.bin' -Bytes (New-ByteArray @(0x41,0x0A,0x0D,0xC3,0x28,0x42,0x43,0x44,0x45))
      $lfcrResult = Get-TextFileEncoding -Path $lfcr -UchardetPath $fakeUchardet -ErrorAction Stop
      Assert-EncodingResult -Result $lfcrResult -Type 'OTHER' -EncodingDescription '' -NewlineStyle 'N/A' -BomBytes ([byte[]]@()) -DotNetWebName $null
    }
  },
  @{
    Name = 'MaxBytes limits reads, ignores later bytes, and detector receives the sample'
    Body = {
      $largeBytes = New-ByteArray @(0x41,0x42,0x43,0x44,0x45,0x46,0x47,0xC3,0x28,0x48,0x49,0x4A,0x4B)
      $large = Write-TestBytes -Name 'large-ascii-prefix-then-nonascii.txt' -Bytes $largeBytes

      $prefixResult = Get-TextFileEncoding -Path $large -MaxBytes 7 -ErrorAction Stop
      Assert-EncodingResult -Result $prefixResult -Type 'ASCII-TEXT' -EncodingDescription 'UTF-8' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'utf-8'
      Assert-Equal $prefixResult.BytesRead 7 'Expected MaxBytes-limited read.'
      Assert-Equal $prefixResult.BytesIgnored 6 'Expected remaining bytes to be ignored.'

      $recordPath = Join-Path $script:TempRoot 'fake-uchardet-record.txt'
      Set-FakeUchardetMode -Mode 'iso88591' -RecordPath $recordPath
      $sampled = Get-TextFileEncoding -Path $large -MaxBytes 12 -UchardetPath $fakeUchardet -ErrorAction Stop
      Assert-EncodingResult -Result $sampled -Type 'NON-ASCII-TEXT' -EncodingDescription 'Windows-1252' -NewlineStyle 'None' -BomBytes ([byte[]]@()) -DotNetWebName 'windows-1252'

      $record = Get-Content -LiteralPath $recordPath
      Assert-Equal ([int64]$record[1]) 12 'Expected fake detector to receive a MaxBytes-sized sample file.'
    }
  },
  @{
    Name = 'Optional real uchardet smoke handles CP1252-like invalid UTF-8'
    Body = {
      $cmd = Get-Command -Name 'uchardet' -CommandType Application -ErrorAction SilentlyContinue
      if (-not $cmd) {
        Write-Host 'SKIP    Optional real uchardet smoke handles CP1252-like invalid UTF-8 (uchardet not found)' -ForegroundColor Yellow
        return
      }

      $file = Write-TestBytes -Name 'cp1252-ambiguous.txt' -Bytes ($cp1252.GetBytes('Cafe ' + [char]0x00E9 + '! tail'))
      $result = Get-TextFileEncoding -Path $file -ErrorAction Stop
      Assert-Equal $result.Type 'NON-ASCII-TEXT' 'Expected real uchardet smoke to classify the fixture as non-ASCII text.'
      Assert-True (-not [string]::IsNullOrWhiteSpace($result.EncodingDescription)) 'Expected real uchardet smoke to return an encoding description.'
      Assert-True (-not [string]::IsNullOrWhiteSpace($result.UCharDetEncoding)) 'Expected real uchardet smoke to record detector output.'
    }
  }
)

$passed = 0
try {
  $fakeUchardet = Compile-FakeUchardet -Directory $script:TempRoot

  foreach ($test in $tests) {
    Clear-FakeUchardetMode
    Invoke-TestCase -Name $test.Name -Body $test.Body
    $passed++
  }

  Write-Host ''
  Write-Host "All $passed Get-TextFileEncoding tests passed." -ForegroundColor Green
}
finally {
  Clear-FakeUchardetMode
  Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
