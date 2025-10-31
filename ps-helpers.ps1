<#
TODO:
  1) FIX THIS STRANGE BUG:

	C:\Users\NickDemou> . 'C:\Users\NickDemou\OneDrive - enLogic\ps-helpers.ps1'
	C:\Users\NickDemou> $out4 = (ls c:\temp -File | Test-TextFileEncoding)
	C:\Users\NickDemou> Test-TextFileEncoding C:\temp\1.png.tmp.3

	File                     : C:\temp\1.png.tmp.3
	Type                     : OTHER
	UCharDetEncoding         : WINDOWS-1250
	FinalEncodingDescription : Binary (or WINDOWS-1250)
	FinalEncodingObject      :

	C:\Users\NickDemou> $out4 | ?{$_.file.name -like '1*'}

	File                     : 1.png.tmp.3
	Type                     : NON-ASCII-TEXT
	UCharDetEncoding         : WINDOWS-1250
	FinalEncodingDescription : WINDOWS-1250
	FinalEncodingObject      : System.Text.SBCSCodePageEncoding
	
  2) Make sed function use Test-TextFileEncoding
  
  3) I have a few functions with this comment:
     # Internal function DO NOT PUBLISH
	 They are used only by Test-TextFileEncoding but I can't inline them inside it
	 without abandoning the begin/process style that allows stuff like 
	    ls -File | Test-TextFileEncoding
  
#>
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


function sed {
<#
.SYNOPSIS
Performs an in-place search and replace on a text file (similar to Linux sed -i).

.DESCRIPTION
Reads the contents of the specified file, performs a search and replace,
and writes the modified contents back to the same file.
Uses UTF8 encoding.
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

    (Get-Content $File -Raw -Encoding UTF8) -replace $Pattern, $Replacement |
        Set-Content $File -Encoding UTF8
}


function Write-FunctionError {
<#
.SYNOPSIS
Build an ErrorRecord and write it so -ErrorAction controls behavior.

.NOTES
USED INTERNALLY by other ps-helpers functions
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message,
    [Parameter()][ValidateSet(
      'NotSpecified','InvalidArgument','ObjectNotFound','ResourceUnavailable','OperationTimeout','PermissionDenied'
    )][string]$Category = 'NotSpecified',
    [Parameter()][Object]$TargetObject = $null,
    [Parameter()][string]$ErrorId = 'Test-TextFileEncoding'
  )
  $ex = New-Object System.Exception($Message)
  $ec = [System.Management.Automation.ErrorCategory]::$Category
  $er = New-Object System.Management.Automation.ErrorRecord($ex, $ErrorId, $ec, $TargetObject)
  $PSCmdlet.WriteError($er)
}

<#
.SYNOPSIS
Resolve a pipeline/file argument to a FileInfo and reject directories. Respects -ErrorAction.

.NOTES
USED INTERNALLY by other ps-helpers functions
#>
function Resolve-InputFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName','LiteralPath','PSPath','Name')]
    [Object]$Path
  )
  process {
    try {
      $fi =
        if ($Path -is [IO.FileInfo]) { $Path }
        elseif ($Path -is [string])  { [IO.FileInfo]([IO.Path]::GetFullPath($Path)) }
        else {
          Write-FunctionError -Message "Unsupported Path type: $($Path.GetType().FullName)" -Category InvalidArgument -TargetObject $Path
          return $null
        }

      if (-not $fi.Exists) {
        Write-FunctionError -Message "File not found: $($fi.FullName)" -Category ObjectNotFound -TargetObject $fi.FullName
        return $null
      }
      if ($fi.Attributes -band [IO.FileAttributes]::Directory) {
        Write-FunctionError -Message "Path is a directory: $($fi.FullName)" -Category InvalidArgument -TargetObject $fi.FullName
        return $null
      }
      return $fi
    } catch {
      Write-FunctionError -Message $_.Exception.Message -Category NotSpecified -TargetObject $Path
      return $null
    }
  }
}

<#
.SYNOPSIS
Read up to N bytes from the start of a file (shared read).

.NOTES
USED INTERNALLY by other ps-helpers functions
#>
function Read-SampleBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][int]$Count
  )
  try {
    $toRead = [math]::Min([int64]$Count, [int64]$File.Length)
    $buf = New-Object byte[] $toRead
    $fs  = [IO.File]::Open($File.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
      $offset = 0
      while ($offset -lt $toRead) {
        $n = $fs.Read($buf, $offset, $toRead - $offset)
        if ($n -le 0) { break }
        $offset += $n
      }
      if ($offset -lt $toRead) {
        # shrink to actual bytes read
        $shrink = New-Object byte[] $offset
        [Array]::Copy($buf, 0, $shrink, 0, $offset)
        $buf = $shrink
      }
    } finally { $fs.Dispose() }
    [pscustomobject]@{ Buffer = $buf; BytesRead = [int]$buf.Length }
  } catch {
    Write-FunctionError -Message "Failed to read sample: $($_.Exception.Message)" -Category ResourceUnavailable -TargetObject $File.FullName
    [pscustomobject]@{ Buffer = [byte[]]@(); BytesRead = 0 }
  }
}


<#
.SYNOPSIS
Detect BOM and return presence, bytes, and a simple encoding label. Needs a byte array with the first bytes of a file.

.EXAMPLE
Get-FileBomFromPrefix (Read-SampleBytes -File $file -Count 4)

.NOTES
USED INTERNALLY by other ps-helpers functions
#>
function Get-FileBomFromPrefix {
  [CmdletBinding()]
  param([Parameter(Mandatory)][byte[]]$Buffer)
  $b = $Buffer
  if ($b.Length -ge 3 -and $b[0]-eq 0xEF -and $b[1]-eq 0xBB -and $b[2]-eq 0xBF) { return @{ Exists=$true; Bytes=@(0xEF,0xBB,0xBF); Enc='UTF-8'    } }
  if ($b.Length -ge 2 -and $b[0]-eq 0xFF -and $b[1]-eq 0xFE)                    { return @{ Exists=$true; Bytes=@(0xFF,0xFE);      Enc='UTF-16LE' } }
  if ($b.Length -ge 2 -and $b[0]-eq 0xFE -and $b[1]-eq 0xFF)                    { return @{ Exists=$true; Bytes=@(0xFE,0xFF);      Enc='UTF-16BE' } }
  if ($b.Length -ge 4 -and $b[0]-eq 0xFF -and $b[1]-eq 0xFE -and $b[2]-eq 0x00 -and $b[3]-eq 0x00) { return @{ Exists=$true; Bytes=@(0xFF,0xFE,0x00,0x00); Enc='UTF-32LE' } }
  if ($b.Length -ge 4 -and $b[0]-eq 0x00 -and $b[1]-eq 0x00 -and $b[2]-eq 0xFE -and $b[3]-eq 0xFF) { return @{ Exists=$true; Bytes=@(0x00,0x00,0xFE,0xFF); Enc='UTF-32BE' } }
  return @{ Exists=$false; Bytes=@(); Enc=$null }
}

<#
.SYNOPSIS
Returns newline style in a string ('CRLF','LF','CR','Mixed','None').

.NOTES
USED INTERNALLY by other ps-helpers functions
#>
function Get-NewlineStyleFromString {
  [CmdletBinding()]
  param([AllowNull()][string]$Text)
  if ($null -eq $Text) { return 'None' }
  $hasCRLF = $Text -match "`r`n"
  $hasLF   = $Text -match "(?<!`r)`n"
  $hasCR   = $Text -match "`r(?!`n)"
  if (-not $hasCRLF -and -not $hasLF -and -not $hasCR) { return 'None' }
  $k = @($hasCRLF,$hasLF,$hasCR) | Where-Object {$_} | Measure-Object | Select-Object -ExpandProperty Count
  if ($k -gt 1) { return 'Mixed' }
  if ($hasCRLF) { return 'CRLF' }
  if ($hasLF)   { return 'LF' }
  if ($hasCR)   { return 'CR' }
  'Mixed'
}


  function Invoke-Uchardet {
    # Run uchardet with robust quoting and timeout. Never throws; returns a result object.
	# Internal function DO NOT PUBLISH
    [CmdletBinding()]
    param(
      [Parameter(Mandatory)][string]$FilePath,
      [Parameter(Mandatory)][int]$TimeoutMs,
      [Parameter(Mandatory)][string]$ExePath
    )
    $result = [ordered]@{ 
      Ok=$false; 
      Encoding=$null; 
      ExitCode=$null; 
      StdErr=$null; 
      TimedOut=$false; 
      ErrorMessage=$null; 
      Ms=0 
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
      $psi = New-Object System.Diagnostics.ProcessStartInfo
      $psi.FileName = $ExePath
      # Quote the single argument; double quotes cannot exist in NTFS names, so simple quoting is safe.
      $psi.Arguments = '"' + $FilePath + '"'
      $psi.UseShellExecute = $false
      $psi.RedirectStandardOutput = $true
      $psi.RedirectStandardError  = $true
      $psi.CreateNoWindow = $true
  
      $p = New-Object System.Diagnostics.Process
      $p.StartInfo = $psi
  
      if (-not $p.Start()) {
        $result.ErrorMessage = "Failed to start uchardet."
        return [pscustomobject]$result
      }
  
      if (-not $p.WaitForExit($TimeoutMs)) {
        try { $p.CloseMainWindow() | Out-Null } catch {}
        Start-Sleep -Milliseconds 150
        try { if (-not $p.HasExited) { $p.Kill() } } catch {}
        $result.TimedOut = $true
        $result.ErrorMessage = "uchardet timeout after $TimeoutMs ms"
        return [pscustomobject]$result
      }
  
      $stdout = $p.StandardOutput.ReadToEnd().Trim()
      $stderr = $p.StandardError.ReadToEnd()
      $result.ExitCode = $p.ExitCode
      $result.StdErr   = $stderr
  
      if ($p.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($stderr)) {
        $result.ErrorMessage = "uchardet failed. ExitCode=$($p.ExitCode). Stderr: $stderr"
        return [pscustomobject]$result
      }
  
      $result.Ok = $true
      $result.Encoding = ($stdout -replace '\s+$','')
      return [pscustomobject]$result
    } catch {
      $result.ErrorMessage = $_.Exception.Message
      return [pscustomobject]$result
    } finally {
      $sw.Stop()
      $result.Ms = [int]$sw.ElapsedMilliseconds
    }
  }

  function Write-BytesToTempFile {
    # Write bytes to a temp file and return the path.
	# Internal function DO NOT PUBLISH	
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Buffer)
    try {
      $tmp = [IO.Path]::GetTempFileName()
      [IO.File]::WriteAllBytes($tmp,$Buffer)
      return $tmp
    } catch {
      Write-FunctionError -Message "Failed to write temp sample: $($_.Exception.Message)" -Category ResourceUnavailable
      return $null
    }
  }
  
  function Get-EncodingObjectFromDescription {
    # Convert a final description to a .NET Encoding object, if possible.
	# Internal function DO NOT PUBLISH	
    [CmdletBinding()]
    param([string]$Description)
    function Map-UchardetToDotNetName {
      # Map uchardet labels to Windows/.NET encoding names where they differ.
      [CmdletBinding()]
      param([string]$UchardetName)
      if (-not $UchardetName) { return $null }
      switch -Regex ($UchardetName.ToUpperInvariant()) {
        '^MAC-CENTRALEUROPE$' { 'x-mac-ce'; break }
        '^MAC-CYRILLIC$'      { 'x-mac-cyrillic'; break }
        '^ISO-2022-CN$'       { 'x-cp50227'; break }
        '^TIS-620$'           { 'windows-874'; break }
        '^ISO-8859-11$'       { 'windows-874'; break }
        '^CP1253$'            { 'windows-1253'; break }
        '^ISO-8859-7$'        { 'iso-8859-7'; break }
        '^ASCII$'             { 'us-ascii'; break }
        default               { $UchardetName }
      }
    }
    if (-not $Description) { return $null }
    $base = ($Description -replace '\s+\(With BOM\)$','' -replace '\s+\(No BOM\)$','')
    $name = switch -Regex ($base.ToUpperInvariant()) {
      '^UTF-16LE$' { 'utf-16' }
      '^UTF-16BE$' { 'unicodeFFFE' }
      '^UTF-32LE$' { 'utf-32' }
      '^UTF-32BE$' { 'utf-32BE' }
      '^UTF-8$'    { 'utf-8' }
      '^ASCII$'    { 'us-ascii' }
      '^CP1253$'   { 'windows-1253' }
      default      { Map-UchardetToDotNetName $base }
    }
    try { [Text.Encoding]::GetEncoding($name) } catch { $null }
  }


function Test-FileExtSuggestsBinaryFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [Alias('FullName','LiteralPath','PSPath','Name')]
    [string]$Path
  )

  $ext = [IO.Path]::GetExtension($Path)
  if (-not $ext) { return $false }
  $ext = $ext.TrimStart('.').ToLowerInvariant()

  $binaryExt = @(
    'jpg','jpeg','png','gif','bmp','tif','tiff','webp','ico',
    'mp4','mkv','mov','avi','wmv','flv','mpeg','mpg','webm',
    'mp3','wav','ogg','flac','aac','m4a','mid','midi',
    'pdf','doc','docx','xls','xlsx','ppt','pptx','odt','ods','odp',
    'zip','rar','7z','tar','gz','bz2','iso','msi','cab',
    'exe','dll','sys','com','so','dmg','app',
    'ttf','otf','woff','woff2'
  )

  return $binaryExt -contains $ext
}

function Measure-BinaryLikelihood {
  <#
  .SYNOPSIS
    Estimate how likely a file is "binary" based on control-character density (ANSI-only).
  .DESCRIPTION
    Counts C0 controls (0x00–0x1F) and DEL (0x7F), excluding benign 0x09,0x0A,0x0D (and optionally 0x0C).
    Bytes >= 0x80 are treated as normal text (ANSI assumption). NULLs can be given higher weight.
    Returns a 0..1 Likelihood plus counts and a Binary boolean using a threshold.
  .PARAMETER Path
    File path (supports pipeline of strings/FileInfo). Directories are skipped.
  .PARAMETER MaxBytes
    Max bytes to sample from the start of the file.
  .PARAMETER NullWeight
    Weight multiplier for NULL (0x00) bytes.
  .PARAMETER OtherControlWeight
    Weight multiplier for other penalized controls (excluding TAB/CR/LF[/FF]).
  .PARAMETER AllowFormFeed
    Also treat 0x0C as benign (excluded from penalty).
  .PARAMETER BinaryThreshold
    If Likelihood >= threshold, Binary=$true.
  .OUTPUTS
    PSCustomObject with fields: Path, BytesRead, NullBytes, PenalizedControlBytes, AllowedControlBytes, 
    WeightedControlScore, Likelihood, Binary, BinaryThreshold, IsSmallSample.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName','LiteralPath','PSPath','Name')]
    [string]$Path,
    [int]$MaxBytes = 65536,
    [double]$NullWeight = 1.0,
    [double]$OtherControlWeight = 0.5,
    [switch]$AllowFormFeed,
    [double]$BinaryThreshold = 0.01
  )
  begin {
    $allowed = [System.Collections.BitArray]::new(256,$false)
    $allowed[0x09] = $true; $allowed[0x0A] = $true; $allowed[0x0D] = $true
    if($AllowFormFeed){ $allowed[0x0C] = $true }
    $isControl = [System.Collections.BitArray]::new(256,$false)
    for($i=0;$i -le 0x1F;$i++){ $isControl[$i] = $true }
    $isControl[0x7F] = $true
  }
  process {
    $item = $null
    try { $item = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { return }
    if($item.PSIsContainer){ return }
    $bytesRead = 0; $nulls = 0; $penalized = 0; $allowedCtrls = 0
    try {
      $fs = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        $buf = New-Object byte[] (8192)
        while($bytesRead -lt $MaxBytes){
          $toRead = [Math]::Min($buf.Length, $MaxBytes - $bytesRead)
          $n = $fs.Read($buf,0,$toRead)
          if($n -le 0){ break }
          for($k=0;$k -lt $n;$k++){
            $b = $buf[$k]
            $bytesRead++
            if($b -ge 0x80){ continue }                    # ANSI: high bytes are normal text
            if(-not $isControl[$b]){ continue }            # printable ASCII
            if($allowed[$b]){ $allowedCtrls++; continue }  # benign controls
            if($b -eq 0x00){ $nulls++ } else { $penalized++ }
          }
        }
      } finally { $fs.Dispose() }
    } catch {
      Write-Error -Category ResourceUnavailable -ErrorId 'ReadFailed' -Message "Failed to read '$($item.FullName)': $($_.Exception.Message)"
      return
    }
    $weighted = ($nulls * $NullWeight) + ($penalized * $OtherControlWeight)
    $likelihood = if($bytesRead -gt 0){ [Math]::Min(1.0, $weighted / $bytesRead) } else { 0.0 }
    [pscustomobject]@{
      Path                    = $item.FullName
      BytesRead               = $bytesRead
      NullBytes               = $nulls
      PenalizedControlBytes   = $penalized
      AllowedControlBytes     = $allowedCtrls
      WeightedControlScore    = [math]::Round($weighted,6)
      Likelihood              = [math]::Round($likelihood,6)
      Binary                  = ($likelihood -ge $BinaryThreshold)
      BinaryThreshold         = $BinaryThreshold
      IsSmallSample           = ($bytesRead -lt 1024)
      NullWeight              = $NullWeight
      OtherControlWeight      = $OtherControlWeight
      AllowedControls         = ('0x09','0x0A','0x0D') + ($(if($AllowFormFeed){ '0x0C' } else { @() }))
    }
  }
}


<#
.SYNOPSIS
  Test if a file seems to contain plain text and, if so, return its encoding.

.DESCRIPTION
  Uses uchardet (winget install uchardet) and some other simple BOM/ASCII checks.
  Especially for Greek ANSI texts tries to be smart regarding CP1253 & ISO-8859-7
  (two encodings that are hard to distinguish).
  By default considers only the first 64KB of the file, prefers CP1253 over 
  ISO-8859-7 and UTF-8 over ASCII.
  
  Returns an object with these properties:
    Most useful: 
      Type                      : "ASCII-TEXT","NON-ASCII-TEXT","EMPTY","OTHER","OTHER (ext)"
      FinalEncodingDescription  : "ASCII","UTF-8","ISO-8859-7","CP1253",
                                  "UTF-8 (With BOM)","UTF-16LE (With BOM)","UTF-16BE (With BOM)",
                                  "UTF-32LE (With BOM)","UTF-32BE (With BOM)",
                                  "<Encoding as reported by uchardet> (No BOM)"
								  "Binary (or <Encoding as reported by uchardet>)"
      FinalEncodingObject       : .NET Encoding object or $null
      NewlineStyle              : "CRLF","LF","CR","Mixed","None" or $null if -CheckNewLineStyle was not used.
      File                      : The file object
    Debug info: 
      BOMExists =               : $true, $false
      BOMBytes                  : The first 4 bytes
      BOMEncoding               : "UTF-8","UTF-16LE","UTF-16BE","UTF-32LE","UTF-32BE"
      UCharDetEncoding          : Encoding reported by uchardet 
      BytesRead                 : The number of bytes read
      UCharDetTimeMs            : msec spent running uchardet
      TotalTimeMs               : Total elapsed msec

.NOTES
  Respects -ErrorAction.
  
  These are the default encoding used on Notepad, PS5 & PS7 per windows version
  +------------------------+---------+----------+----------------+---------------+
  |OS / Version            | Notepad | PS 5.1 > | PS 5.1         | PS 7          |
  |                        |         | operator | Out-File       | > or Out-File |
  |------------------------+---------+----------+----------------+---------------|
  |Server 2016/Win 10 1607 | ANSI    | ANSI     | UTF-16 LE +BOM | UTF-8         |
  |Server 2019/Win 10 1809 | ANSI    | ANSI     | UTF-16 LE +BOM | UTF-8         |
  |Server 2022/Win 10 21H2 | UTF-8   | ANSI     | UTF-16 LE +BOM | UTF-8         |
  |Server 2025/Win 10 24H2 | UTF-8   | ANSI     | UTF-16 LE +BOM | UTF-8         |
  +------------------------+---------+----------+----------------+---------------+
  UTF-8 is always without BOM.
  Examples of Greek ANSI encodings are "CP1253"(Windows default) & "ISO-8859-7". 
#>
function Test-TextFileEncoding {
  [CmdletBinding(SupportsShouldProcess=$false)]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName','LiteralPath','PSPath','Name')]
    [Object]$Path,
    [switch]$NoPreferCp1253,
    [switch]$NoPreferUTF8,
    [switch]$CheckNewLineStyle,
    [int]$MaxBytes = 65536,
    [int]$TimeoutMs = 3000,
    [string]$UchardetPath
  )

  begin {
    $uchardetExe = if ($UchardetPath) { $UchardetPath } else { 'uchardet' }
  }
  process {
    $totalSw = [Diagnostics.Stopwatch]::StartNew()

    $file = Resolve-InputFile -Path $Path
    if ($null -eq $file) {
      $totalSw.Stop()
      return
    }

    if ($file.Length -eq 0) {
      $totalSw.Stop()
      return [pscustomobject]@{
        File=$file; Type='EMPTY'; BOMExists=$false; BOMBytes=[byte[]]@(); BOMEncoding=$null;
        UCharDetEncoding=$null; FinalEncodingDescription=$null; FinalEncodingObject=$null;
        NewlineStyle=$null; BytesRead=0; UCharDetTimeMs=0; TotalTimeMs=[int]$totalSw.ElapsedMilliseconds
      }
    }

    $sample    = Read-SampleBytes -File $file -Count $MaxBytes
    $bytes     = $sample.Buffer
    $bytesRead = $sample.BytesRead

    $bom = Get-FileBomFromPrefix -Buffer $bytes

    $encoding = $null
    $uMs  = 0
    $finalDesc = $null
    $finalObj  = $null
    $type      = 'OTHER' 

    if ($bom.Exists) {
      # Don't run uchardet if BOM exists
      $encoding = $null
      $finalDesc = "$($bom.Enc) (With BOM)"
      $finalObj  = Get-EncodingObjectFromDescription -Description $bom.Enc
      $type      = 'NON-ASCII-TEXT'
    } else {
      # Not as easy as having a BOM
	  $ucdEncoding = $null

      # Is it ASCII? 
      $isAscii   = $true
      foreach($x in $bytes){ if($x -ge 0x80){ $isAscii   = $false; break } }
      
      # Is it UTF8
      if ($isAscii) {
        $isUTF8 = $true
      } else {
        $utf8 = New-Object System.Text.UTF8Encoding($false,$true)
        $isUTF8 = $false
        try { [void]$utf8.GetString($Bytes); $isUTF8=$true } catch { }    
      }
	  
	  if (!$isAscii -and !$isUTF8) {
		  # if file's extension is a popular binary file extension don't bother checking it
		  if (Test-FileExtSuggestsBinaryFile $file) {
			$totalSw.Stop()
            return [pscustomobject]@{
			  File=$file; Type='OTHER (ext)'; BOMExists=$false; BOMBytes=[byte[]]@(); BOMEncoding=$null;
              UCharDetEncoding=$null; FinalEncodingDescription=$null; FinalEncodingObject=$null;
              NewlineStyle=$null; BytesRead=$bytesRead; UCharDetTimeMs=0; TotalTimeMs=[int]$totalSw.ElapsedMilliseconds
            }
		  }
	  }
      
	  if ($isUTF8) {
	    $encoding = "UTF-8"
	  } else {
        $targetPath = $file.FullName
        $tmp = $null
        if ($file.Length -gt $MaxBytes) {
          $tmp = Write-BytesToTempFile -Buffer $bytes
          if ($null -eq $tmp) {
            # Could not prepare temp; record error and continue without uchardet.
            Write-FunctionError -Message "Failed to prepare sample for uchardet." -Category ResourceUnavailable -TargetObject $file.FullName
          } else {
            $targetPath = $tmp
          }
        }
	    
        $uRes = $null
        if ($targetPath) {
          $uRes = Invoke-Uchardet -FilePath $targetPath -TimeoutMs $TimeoutMs -ExePath $uchardetExe
          $uMs  = [int]$uRes.Ms
          if (-not $uRes.Ok) {
            $cat = if ($uRes.TimedOut) { 'OperationTimeout' } else { 'ResourceUnavailable' }
            $errMsg = if ($uRes.ErrorMessage) { $uRes.ErrorMessage } else { 'Unknown' }
            Write-FunctionError -Message ("uchardet error: " + $errMsg) -Category $cat -TargetObject $file.FullName
            $encoding = $null
          } else {
            $encoding = if ([string]::IsNullOrWhiteSpace($uRes.Encoding)) { $null } else { $uRes.Encoding }
			$ucdEncoding = $encoding
			
			if ($encoding -like 'Windows-*' -or $encoding -like 'ISO-*') {
              $out= Measure-BinaryLikelihood $file -MaxBytes $MaxBytes
			  if ($out.Binary) {
			    $encoding = "Binary (or $encoding)"
			  }
			}
          }
        }
	  }

      if ($tmp -and (Test-Path $tmp)) { Remove-Item -Force -ErrorAction SilentlyContinue $tmp }

      if ($encoding) {
        $uUpper = $encoding.ToUpperInvariant()
        if ($uUpper -like 'UTF-*') {
          $finalDesc = "$encoding (No BOM)" 
        }
        elseif ($uUpper -eq 'ASCII') {
          if ($isAscii -and (-not $NoPreferUTF8)) { $finalDesc = 'UTF-8' } else { $finalDesc = 'ASCII' }
        } 
        elseif ($uUpper -eq 'ISO-8859-7') {
          if ($NoPreferCp1253) { $finalDesc = 'ISO-8859-7' } 
          else {
            # Decodes $sample bytes using both iso-8859-7 and windows-1253.
            # The encoding is ambiguous if it gets the same text from both.
            $ambiguous = [string]::Equals(
                [Text.Encoding]::GetEncoding('iso-8859-7').GetString($sample.Buffer),
                [Text.Encoding]::GetEncoding('windows-1253').GetString($sample.Buffer),
                [System.StringComparison]::Ordinal)         
            $finalDesc = if ($ambiguous) { 'CP1253' } else { 'ISO-8859-7' }
          }
        }
        else {
          $finalDesc = $encoding 
        }
      }

      $finalObj = Get-EncodingObjectFromDescription -Description $finalDesc

      # ASCII bytes => ASCII-TEXT regardless of label (except BOM case already handled)
      if ($isAscii) {
        $type = 'ASCII-TEXT' 
      } elseif ($finalDesc -and $finalDesc -notlike 'Binary *') {
        $type = 'NON-ASCII-TEXT'
      } else {
        $type = 'OTHER'
      }
    }

    # Newline style
    if ($CheckNewLineStyle) {
      if ($finalObj) {
        $decoded = $finalObj.GetString($bytes)
        $nl = Get-NewlineStyleFromString -Text $decoded
      } else {
        $nl = 'None'
      }
    } else {
      $nl = $null
    }

    $totalSw.Stop()
    [pscustomobject]@{
      File=$file
      Type=$type # 'EMPTY','OTHER','NON-ASCII-TEXT','ASCII-TEXT'
      BOMExists=[bool]$bom.Exists
      BOMBytes=[byte[]]$bom.Bytes
      BOMEncoding=$bom.Enc
      UCharDetEncoding=$ucdEncoding
      FinalEncodingDescription=$finalDesc
      FinalEncodingObject=$finalObj
      NewlineStyle=$nl
      BytesRead=$bytesRead
      UCharDetTimeMs=[int]$uMs
      TotalTimeMs=[int]$totalSw.ElapsedMilliseconds
    }
  }
}

<#
.SYNOPSIS
Highlights text matching a regex with ANSI color codes.

.DESCRIPTION
Reads text from pipeline input, applies a regex pattern, and wraps each match
with ANSI escape sequences to colorize the matched text in the console.
Supports named colors, 0-255 ANSI palette values, or #RRGGBB truecolor codes.

This is intended for inline highlighting during text inspection in the terminal.

.PARAMETER InputObject
Text to process from the pipeline.

.PARAMETER Pattern
Regex pattern whose matches will be colorized.

.PARAMETER Color
Color to use for matches. Can be a named color (e.g. 'Red','BrightYellow'),
an ANSI 256-color number (0-255), or a #RRGGBB hex code. Default is Yellow.

.PARAMETER CaseSensitive
If specified, the regex match is case-sensitive. Default is case-insensitive.

.PARAMETER Multiline
If specified, enables multiline mode so ^ and $ match line boundaries.

.OUTPUTS
String with ANSI escape codes embedded around matches.

.EXAMPLE
"test foo lala" | Colorize-Matches -Pattern "foo" -Color BrightRed

.EXAMPLE
Get-Content .\log.txt -Raw | Colorize-Matches -Pattern '\d{2}:\d{2}' -Color '#00B7EB'

.NOTES
ANSI coloring requires a console host that supports VT escape sequences
(Windows Terminal, PowerShell 7+, or conhost with VT enabled).
#>
function Colorize-Matches {
  [CmdletBinding()]
  param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]$InputObject,
    [Parameter(Mandatory=$true)]
    [string]$Pattern,
    [string]$Color = 'Yellow',
    [switch]$CaseSensitive,
    [switch]$Multiline
  )
  begin {
    $sb = New-Object System.Text.StringBuilder
    $esc = [char]27
    function Get-AnsiSeq([string]$c){
      $map=@{Black='30';Red='31';Green='32';Yellow='33';Blue='34';Magenta='35';Cyan='36';White='37';
             BrightBlack='90';BrightRed='91';BrightGreen='92';BrightYellow='93';BrightBlue='94';BrightMagenta='95';BrightCyan='96';BrightWhite='97'}
      if($map.ContainsKey($c)){ return "$esc[$($map[$c])m" }
      if($c -match '^\d{1,3}$' -and [int]$c -ge 0 -and [int]$c -le 255){ return "$esc[38;5;$c"+"m" }
      if($c -match '^#?([0-9A-Fa-f]{6})$'){
        $hex=$Matches[1]; $r=[Convert]::ToInt32($hex.Substring(0,2),16); $g=[Convert]::ToInt32($hex.Substring(2,2),16); $b=[Convert]::ToInt32($hex.Substring(4,2),16)
        return "$esc[38;2;$r;$g;$b"+"m"
      }
      throw "Unknown color '$c'. Use named color, 0-255, or #RRGGBB."
    }
    $reset = "$esc[0m"
    $ansi  = Get-AnsiSeq $Color
    $opts  = [System.Text.RegularExpressions.RegexOptions]::None
    if(-not $CaseSensitive){ $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    if($Multiline){ $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::Multiline }
  }
  process {
    if($null -ne $InputObject){ [void]$sb.AppendLine($InputObject) }
  }
  end {
    $text = $sb.ToString(); if(-not $text){ return }
    [System.Text.RegularExpressions.Regex]::Replace(
      $text, $Pattern,
      { param($m) $ansi + $m.Value + $reset },
      $opts
    )
  }
}
