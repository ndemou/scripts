function sed {
<#
.SYNOPSIS
Performs an in-place search and replace on a text file (similar to Linux sed -i).

.DESCRIPTION
Reads the contents of the specified file, performs a search and replace,
and writes the modified contents back to the same file in UTF-8 encoding.
By default, the search pattern is treated as a regular expression.
Use -Literal to match the pattern as plain text.

.PARAMETER File
The path to the text file to modify.

.PARAMETER Pattern
The text or regex pattern to search for.

.PARAMETER Replacement
The replacement text to insert in place of matches.

.PARAMETER Literal
If specified, the search pattern will be treated as literal text instead of regex.

.EXAMPLE
sed 'file.txt' 'old' 'new'
Replaces all occurrences of "old" with "new" in file.txt (regex mode).

.EXAMPLE
sed 'file.txt' '\d+' 'NUMBER'
Replaces all numbers with the text "NUMBER" in file.txt (regex mode).

.EXAMPLE
sed 'file.txt' 'e.t.c.' 'etc.' -Literal
Replaces the literal string "e.t.c." with "etc." in file.txt.

.NOTES
Without -Literal, the -replace operator uses regex syntax.
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]$File,

        [Parameter(Mandatory=$true)]
        [string]$Pattern,

        [Parameter(Mandatory=$true)]
        [string]$Replacement,

        [switch]$Literal
    )

    if ($Literal) {
        $Pattern = [regex]::Escape($Pattern)
    }

    (Get-Content $File -Raw) -replace $Pattern, $Replacement |
        Set-Content $File -Encoding utf8
}


# -------------------------------------------
<# [System.Text.Encoding]::GetEncoding(1253) or 'iso-8859-7' will not work in PowerShell 7 (only UTF encodings are available by default). To load legacy encodings you must call:
    [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
#>
try {
  if ($PSVersionTable.PSEdition -eq 'Core') {
    [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
  }
} catch {}
# -------------------------------------------

function Test-LegacyGreekEncodingAmbiguous {
<#
.SYNOPSIS
Tests if the legacy Greek encoding of a text file is ambiguous (can be either CP1253 or ISO-8859-7)
Reads the first N bytes of the file, decodes them both as CP1253 and as ISO-8859-7, and returns $true if both give the same text.

.PARAMETER Path
File to inspect.

.PARAMETER Bytes
How many bytes to read from the start (default 65536, 64KB).

.OUTPUTS
$True if file can be decoded either with ISO8859-7 or CP1253
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position=0)][string]$Path,
    [int]$Bytes = 65536
  )

  # Resolve bare or relative path to current directory
  if (-not (Split-Path -Path $Path -IsAbsolute)) {
    $Path = Join-Path (Get-Location) $Path
  }

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }

  $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
  try {
    $toRead = [Math]::Min([int64]$Bytes, $fs.Length)
    $buf = New-Object byte[] $toRead
    [void]$fs.Read($buf, 0, $toRead)
  } finally { $fs.Dispose() }

  $enc1253  = [System.Text.Encoding]::GetEncoding(1253)
  $encIso97 = [System.Text.Encoding]::GetEncoding('iso-8859-7')

  $s1253  = $enc1253.GetString($buf, 0, $buf.Length)
  $sIso97 = $encIso97.GetString($buf, 0, $buf.Length)

  return ($s1253 -ceq $sIso97)
}

#--------------------------

function Get-FileBom {
<#
.SYNOPSIS
  Returns a file's BOM (UTF-8/16/32, LE/BE)

.DESCRIPTION
  Reads first few bytes, and matches against known BOMs. Returns:
    Bytes   : byte[] of the BOM (empty array if none)
    Meaning : description of the BOM (e.g., 'UTF-8 with BOM' or 'None (no BOM)').

.PARAMETER Path
  File path(s) to inspect. Accepts pipeline input and wildcards.

.EXAMPLE
  Get-FileBom ascii.txt
.EXAMPLE
  Get-ChildItem *.txt | Get-FileBom
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position=0)]
    [Alias('FullName','LiteralPath')]
    [string[]]$Path
  )

  begin {
    $bomTable = @(
      @{ Bytes = [byte[]](0xEF,0xBB,0xBF);      Meaning = 'UTF-8 with BOM' }
      @{ Bytes = [byte[]](0xFF,0xFE);           Meaning = 'UTF-16 Little Endian' }
      @{ Bytes = [byte[]](0xFE,0xFF);           Meaning = 'UTF-16 Big Endian' }
      @{ Bytes = [byte[]](0xFF,0xFE,0x00,0x00); Meaning = 'UTF-32 Little Endian' }
      @{ Bytes = [byte[]](0x00,0x00,0xFE,0xFF); Meaning = 'UTF-32 Big Endian' }
    )
    $maxLen = ($bomTable | ForEach-Object { $_.Bytes.Length } | Measure-Object -Maximum).Maximum

    function Invoke-CheckBom([string]$ResolvedPath) {
      try {
        $fs = [System.IO.File]::Open($ResolvedPath,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read)
      } catch {
        return [pscustomobject]@{ Bytes = [byte[]]@(); Meaning = "Cannot open file: $($_.Exception.Message)" }
      }
      try {
        $buffer = [byte[]]::new($maxLen)
        $read = $fs.Read($buffer,0,$maxLen)
        foreach ($entry in $bomTable) {
          $bom = $entry.Bytes
          if ($read -ge $bom.Length) {
            $match = $true
            for ($i=0; $i -lt $bom.Length; $i++) { if ($buffer[$i] -ne $bom[$i]) { $match = $false; break } }
            if ($match) { return [pscustomobject]@{ Bytes = $bom; Meaning = $entry.Meaning } }
          }
        }
        [pscustomobject]@{ Bytes = [byte[]]@(); Meaning = 'None (no BOM)' }
      } finally { $fs.Dispose() }
    }
  }

  process {
    foreach ($p in $Path) {
      $resolvedItems = @()
      try {
        $resolvedItems = Resolve-Path -Path $p -ErrorAction Stop
      } catch {
        # Try literal (no wildcard expansion)
        try {
          $resolvedItems = Resolve-Path -LiteralPath $p -ErrorAction Stop
        } catch {
          [pscustomobject]@{ Bytes = [byte[]]@(); Meaning = "File not found: $p" }
          continue
        }
      }

      foreach ($ri in $resolvedItems) {
        $rp = $ri.ProviderPath
        if (-not $rp) { $rp = $ri.Path }
        if (-not (Test-Path -LiteralPath $rp -PathType Leaf)) {
          [pscustomobject]@{ Bytes = [byte[]]@(); Meaning = "Not a file: $rp" }
          continue
        }
        Invoke-CheckBom -ResolvedPath $rp
      }
    }
  }
}
