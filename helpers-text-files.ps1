##############################################################
#
# A collection of helper functions for handling text files
#
##############################################################

# ----------------------------------------------------
# For Edit-TextFile and Get-TextFileEncoding on PS 7 CoreLib
# ----------------------------------------------------
# 
# [System.Text.Encoding]::GetEncoding(1252) or 'iso-8859-1' will not work in PowerShell 7 (only UTF encodings are available by default). 
# 
# The following code will try to register the CodePagesEncodingProvider so legacy 
# encodings like windows-1252 / iso-8859-1 are available via 
# [Text.Encoding]::GetEncoding(). 
try{
  if($PSVersionTable.PSVersion.Major -ge 6){
    $t=[Type]::GetType('System.Text.Encoding, System.Private.CoreLib',$false)
    if($t -and $t.GetMethod('RegisterProvider',[Type[]]@([Type]::GetType('System.Text.EncodingProvider, System.Private.CoreLib',$false)))){
      $provType=[Type]::GetType('System.Text.CodePagesEncodingProvider, System.Text.Encoding.CodePages',$false)
      if($provType){
        $inst=$provType.GetMethod('get_Instance',[Type[]]@()).Invoke($null,@())
        if($inst){ [System.Text.Encoding]::RegisterProvider($inst) }
      }
    }
  }
}catch{}
# ----------------------------------------------------
# END: For Edit-TextFile and Get-TextFileEncoding on PS 7 CoreLib
# ----------------------------------------------------

# ================================
# Edit-TextFile helpers (internal)
# ================================

<# Normalizes -Backup into a suffix string like '.bak' or $null; empty/whitespace means "no kept backup". #>
function _Etf_NormalizeBackupSuffix {
  [CmdletBinding()] param([AllowNull()][string]$Backup)
  if([string]::IsNullOrWhiteSpace($Backup)){ return $null }
  $suffix=$Backup.Trim()
  if($suffix -notmatch '^\.' ){ $suffix='.'+$suffix }
  $suffix
}

<# Wraps Get-TextFileEncoding and normalizes BOMBytes to a non-null [byte[]]; returns {EncodingObj; Enc(.NET); BomBytes; HasBom}; throws if encoding can't be determined. #>
function _Etf_GetEncodingContext {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][string]$ResolvedPath,
    [Parameter()][switch]$DontPreferUTF8,
    [Parameter()][switch]$PreferISOEncodings
  )

  $EncodingObj = Get-TextFileEncoding -Path $ResolvedPath -DontPreferUTF8:$DontPreferUTF8 -PreferISOEncodings:$PreferISOEncodings -ErrorAction Stop
  if($null -eq $EncodingObj -or $null -eq $EncodingObj.DotNetEncodingObj){
    throw "Edit-TextFile: Could not determine text encoding for file: $ResolvedPath"
  }

  $enc = $EncodingObj.DotNetEncodingObj
  $bomBytes = [byte[]]@()
  if($EncodingObj.PSObject.Properties.Match('BOMBytes').Count -gt 0 -and $EncodingObj.BOMBytes){
    try { $bomBytes = [byte[]]$EncodingObj.BOMBytes } catch { $bomBytes = [byte[]]@() }
  }
  $hasBom = ($bomBytes.Length -gt 0)

  [pscustomobject]@{ EncodingObj=$EncodingObj; Enc=$enc; BomBytes=$bomBytes; HasBom=$hasBom }
}

<# Formats the "Encoding" string for Edit-TextFile output; preserves BOM semantics and appends '(No BOM)' for UTF-* when appropriate. #>
function _Etf_FormatEncoding {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][object]$EncodingObj,
    [Parameter(Mandatory)][System.Text.Encoding]$Enc,
    [Parameter(Mandatory)][bool]$HasBom
  )

  $encWritten = [string]$EncodingObj.EncodingDescription
  if([string]::IsNullOrWhiteSpace($encWritten)){ $encWritten = $Enc.WebName }

  if($HasBom){
    if($encWritten -notmatch '\(With BOM\)\s*$'){ $encWritten = "$encWritten (With BOM)" }
  } else {
    if($encWritten -notmatch '\(No BOM\)\s*$' -and $Enc.WebName -match '^utf-'){ $encWritten = "$encWritten (No BOM)" }
  }

  $encWritten
}

<# Encodes text to bytes using the provided .NET Encoding and prepends BomBytes (if any); treats $null BomBytes as empty and strips leading U+FEFF defensively. #>
function _Etf_EncodeWithBom {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][System.Text.Encoding]$Enc,
    [AllowNull()][byte[]]$BomBytes,
    [AllowNull()][AllowEmptyString()][string]$Text
  )
  if($null -eq $BomBytes){ $BomBytes = [byte[]]@() }
  if($null -eq $Text){ $Text = '' }
  if($BomBytes.Length -gt 0 -and $Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF){ $Text=$Text.Substring(1) }
  $pre=$BomBytes; $body=$Enc.GetBytes($Text)
  $all=New-Object byte[] ($pre.Length + $body.Length)
  if($pre.Length){ [Array]::Copy($pre,0,$all,0,$pre.Length) }
  if($body.Length){ [Array]::Copy($body,0,$all,$pre.Length,$body.Length) }
  $all
}


<# Plans temp/backup paths in the same directory as the target file; returns {Tmp; Bak; UserBackup} (UserBackup indicates if Bak is user-requested). #>
function _Etf_GetSwapPaths {
  [CmdletBinding()] param([Parameter(Mandatory)][string]$ResolvedPath,[string]$BackupSuffixOrNull)

  $dir = [IO.Path]::GetDirectoryName($ResolvedPath)
  $guid = [Guid]::NewGuid().ToString('N')
  $tmp = Join-Path $dir (".sed_tmp_$guid.tmp")

  $userBackup = $false
  if($BackupSuffixOrNull){
    $bak = $ResolvedPath + $BackupSuffixOrNull
    $userBackup = $true
  } else {
    $bak = Join-Path $dir (".sed_bak_$guid.bak")
  }

  [pscustomobject]@{ Tmp=$tmp; Bak=$bak; UserBackup=$userBackup }
}

<#
.SYNOPSIS
  Replaces a file's contents with specified bytes, optionally retaining
a backup.

.DESCRIPTION
  Behavior and guarantees:
    - Writes the new content to -TmpPath first, then attempts to replace -ResolvedPath with it.
    - Primary path uses [IO.File]::Replace(), which is the best option on local NTFS:
        * Readers see either the old or the new file, not a partially-written file.
        * A backup at -BakPath is created/overwritten as part of the replace.
    - If Replace() fails (common on non-NTFS volumes, SMB shares with varying semantics, or transient locks
      e.g. AV/OneDrive/indexing), it falls back to Copy-Item + Move-Item with best-effort rollback:
        * This fallback is NOT atomic. It is provided for compatibility and "works in more places".
        * If the move fails after the backup copy, the function attempts to restore from -BakPath.

  Backup semantics:
    - -BakPath is always used as the safety copy when swapping.
    - If -UserBackup is $true, -BakPath is considered caller-visible and is preserved.
    - If -UserBackup is $false, -BakPath is a transient safety backup and may be deleted on success.

  Cleanup:
    - Always attempts to delete -TmpPath in a finally block.
    - Does not promise preservation of metadata/streams in the fallback path (ACLs, ADS, timestamps, etc.)
      beyond what the underlying filesystem/provider naturally keeps.

.PARAMETER ResolvedPath
  The existing target file to be replaced (must be on the same volume as -TmpPath for best behavior).

.PARAMETER TmpPath
  A temp file path in the same directory as the target (recommended) containing the new bytes to commit.

.PARAMETER BakPath
  Path for the backup copy used during the swap. May be a user-requested backup (kept) or a transient one.

.PARAMETER UserBackup
  Indicates whether -BakPath is user-requested (keep it) or internal/transient (delete on success).

.PARAMETER Bytes
  The final bytes to be written/committed to the target file.

.NOTES
  - Intended for "in-place update" workflows: generate full new content, then commit in one swap.
  - For OneDrive/SMB scenarios, transient failures are normal; callers may want a small retry policy
    around the Replace() stage (if not implemented inside this function).
#>
function Replace-FileBytesSafely {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][string]$ResolvedPath,
    [Parameter(Mandatory)][string]$TmpPath,
    [Parameter(Mandatory)][string]$BakPath,
    [Parameter(Mandatory)][bool]$UserBackup,
    [Parameter(Mandatory)][byte[]]$Bytes,
    [int]$Retries=2,
    [int]$RetryDelayMs=120,
    [switch]$StrictAtomic
  )

  try {
    [IO.File]::WriteAllBytes($TmpPath,$Bytes)

    $replaced=$false
    for($i=0;$i -le $Retries;$i++){
      try{
        if(Test-Path -LiteralPath $BakPath){ Remove-Item -LiteralPath $BakPath -Force -ErrorAction SilentlyContinue }
        [IO.File]::Replace($TmpPath,$ResolvedPath,$BakPath,$true)
        $replaced=$true
        break
      } catch [System.IO.IOException] {
        if($i -lt $Retries){ Start-Sleep -Milliseconds $RetryDelayMs; continue }
        break
      } catch [System.UnauthorizedAccessException] {
        if($i -lt $Retries){ Start-Sleep -Milliseconds $RetryDelayMs; continue }
        break
      }
    }

    if($replaced){
      if(-not $UserBackup -and (Test-Path -LiteralPath $BakPath)){ Remove-Item -LiteralPath $BakPath -Force -ErrorAction SilentlyContinue }
      return
    }

    if($StrictAtomic){ throw "Atomic replace failed (File.Replace) and StrictAtomic is set." }

    Copy-Item -LiteralPath $ResolvedPath -Destination $BakPath -Force -ErrorAction Stop
    try {
      Move-Item -LiteralPath $TmpPath -Destination $ResolvedPath -Force -ErrorAction Stop
      if(-not $UserBackup -and (Test-Path -LiteralPath $BakPath)){ Remove-Item -LiteralPath $BakPath -Force -ErrorAction SilentlyContinue }
    } catch {
      if(Test-Path -LiteralPath $BakPath){
        Move-Item -LiteralPath $BakPath -Destination $ResolvedPath -Force -ErrorAction SilentlyContinue
      }
      throw
    }

  } finally {
    if(Test-Path -LiteralPath $TmpPath){ Remove-Item -LiteralPath $TmpPath -Force -ErrorAction SilentlyContinue }
  }
}

<#
.SYNOPSIS
Searches and replaces text in files while maintaining the existing
text encoding (but will switch ASCII to UTF8 if replacement is unicode).

.DESCRIPTION
Performs an in-place regex (or literal) search/replace on a text file, 
while preserving the file's actual encoding. For _really_ hard cases it
may mistake the encoding. In such cases it may fail to find the pattern
and/or change the encoding of the input file. 

You may pass wildcards like "*.txt" to -File.

To apply one substitution use `-Patern 'a' -Replacement 'b'`. To apply 
multiple substitutions use `-ReplaceMap` (see examples).

Without -Literal considers Pattern(s) to be a regex pattern.

By default keeps a backup with .bak extension. To skip the Backup
use -Backup "". To change the extension use -Backup "ext".

If the sampled bytes are pure 7-bit ASCII and no BOM is present, the 
function by default assumes a UTF8 encoding (even though ASCII is also 
valid). This is intentional: it allows replacements to introduce Unicode
without changing the reported encoding unexpectedly. Use -DontPreferUTF8 
to force ASCII encoding.

.OUTPUTS
Produces a psCustomObject for each evaluated file:
  File        = The file path
  Changed     = True/False
  EncodingStr = Human readable encoding.
  EncodingObj = The output of Get-TextFileEncoding
  Details     = Human readable outcome. E.g.:
                "Changes made"
                "Pattern(s) not found"
                "Skipped too big file ..."
                "Ignored empty file"
                "No files matched pattern"

.PARAMETER MaxFileSize
Files larger than these many bytes are ignored.

.PARAMETER PreferISOEncodings
When set, ISO encodings are selected when multiple encodings represent
the text equivalently; otherwise, Windows encodings are selected.

.EXAMPLE
Edit-TextFile -file .\ansi.txt -Pattern "foo" -Replacement="_FOO_"

.EXAMPLE
Edit-TextFile -file .\ansi.txt -Pattern "foo?" -Replacement="_FOO_?" -Literal

.EXAMPLE
Edit-TextFile -file .\ansi.txt -ReplaceMap ([ordered]@{"foo"="_FOO_"; "bar"="_BAR_"})

.NOTES
The operation writes modified content to temporary storage before
replacing the target file. Original files are backed up prior to the
modification. If a terminating error occurs during the file swap, the
target file might remain in its prior state and intermediate temporary
files might remain on the storage volume.

Files exceeding the configured maximum size limit or containing no
data are skipped. Substitutions are evaluated sequentially.
#>
function Edit-TextFile {
  [CmdletBinding(DefaultParameterSetName='SingleReplace')]
  param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$File,

    [Parameter(Mandatory=$true, ParameterSetName='SingleReplace')]
    [string]$Pattern,

    [Parameter(ParameterSetName='SingleReplace')]
    [string]$Replacement="",

    [Parameter(Mandatory=$true, ParameterSetName='MapReplace')]
    [System.Collections.Specialized.IOrderedDictionary]$ReplaceMap,

    [Parameter()]
    [switch]$Literal,

    [Parameter()]
    [long]$MaxFileSize=1001001,

    [Parameter()]
    [switch]$DontPreferUTF8,

    [Parameter()]
    [switch]$PreferISOEncodings,

    [Parameter()]
    [string]$Backup="bak"
  )

  # Normalize inputs into a standard ordered dictionary regardless of the parameter set used
  $replacementsToProcess = [System.Collections.Specialized.OrderedDictionary]::new()
  if ($PSCmdlet.ParameterSetName -eq 'MapReplace') {
    foreach ($key in $ReplaceMap.Keys) {
      $replacementsToProcess[$key] = $ReplaceMap[$key]
    }
  } else {
    $replacementsToProcess[$Pattern] = $Replacement
  }

  $backupSuffix = _Etf_NormalizeBackupSuffix -Backup $Backup

  $targets = @()
  $hasWildcards = [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($File)

  if($hasWildcards){
    $targets = @(Get-ChildItem -Path $File -File -ErrorAction Stop)
    if($targets.Count -eq 0){
      return [pscustomobject]@{ File=$File; Changed=$false; EncodingStr=$null; EncodingObj=$null; Details="No files matched pattern" }
    }
  } else {
    $resolved = (Resolve-Path -LiteralPath $File -ErrorAction Stop).ProviderPath
    $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if($item.PSIsContainer){ throw "Path is a directory, not a file: $resolved" }
    $targets = @($item)
  }

  $results = foreach($t in $targets){
    $resolved = $t.FullName

    $fileSize = (Get-Item -LiteralPath $resolved).Length
    if ($fileSize -eq 0) {
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$null; EncodingObj=$null; Details="Ignored empty file" }
      continue
    } elseif ($fileSize -gt $MaxFileSize) {
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$null; EncodingObj=$null; Details="Skipped too big file (use -MaxFileSize to change limit)" }
      continue
    }

    $objGec = _Etf_GetEncodingContext -ResolvedPath $resolved -DontPreferUTF8:$DontPreferUTF8 -PreferISOEncodings:$PreferISOEncodings
    $EncodingObj = $objGec.EncodingObj
    $enc = $objGec.Enc
    $bomBytes = $objGec.BomBytes
    $hasBom = $objGec.HasBom
    $encWritten = _Etf_FormatEncoding -EncodingObj $EncodingObj -Enc $enc -HasBom:$hasBom

    $text = $null
    try { $text = [IO.File]::ReadAllText($resolved, $enc) }
    catch {
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$encWritten; EncodingObj=$EncodingObj; Details=("Read failed: " + $_.Exception.Message) }
      continue
    }

    if($hasBom -and $text.Length -gt 0 -and $text[0] -eq [char]0xFEFF){ $text = $text.Substring(1) }

    $newText = $text
    $replaceError = $null

    # Iterate sequentially through our normalized queue of replacements
    foreach ($pat in $replacementsToProcess.Keys) {
      $rep = $replacementsToProcess[$pat]
      $effectivePattern = if($Literal){ [regex]::Escape($pat) } else { $pat }
      
      try { 
        $rx = [regex]::new($effectivePattern)
        $newText = $rx.Replace($newText, $rep)
      }
      catch {
        $replaceError = "Invalid regex or replace failed on pattern '$pat': " + $_.Exception.Message
        break # Break out of the replacement loop early on failure
      }
    }

    if ($null -ne $replaceError) {
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$encWritten; EncodingObj=$EncodingObj; Details=$replaceError }
      continue
    }

    if($newText -ceq $text){
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$encWritten; EncodingObj=$EncodingObj; Details="Pattern(s) not found" }
      continue
    }

    $all = $null
    try { $all = _Etf_EncodeWithBom -Enc $enc -BomBytes $bomBytes -Text $newText }
    catch {
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$encWritten; EncodingObj=$EncodingObj; Details=("Encode failed: " + $_.Exception.Message) }
      continue
    }

    $paths = _Etf_GetSwapPaths -ResolvedPath $resolved -BackupSuffixOrNull $backupSuffix
    try {
      Replace-FileBytesSafely -ResolvedPath $resolved -TmpPath $paths.Tmp -BakPath $paths.Bak -UserBackup:$paths.UserBackup -Bytes $all -ErrorAction Stop
      [pscustomobject]@{ File=$resolved; Changed=$true; EncodingStr=$encWritten; EncodingObj=$EncodingObj; Details="Changes made" }
    } catch {
      [pscustomobject]@{ File=$resolved; Changed=$false; EncodingStr=$encWritten; EncodingObj=$EncodingObj; Details=("Write/commit failed: " + $_.Exception.Message) }
    }
  }

  if($hasWildcards){ return @($results) }
  return $results | Select-Object -First 1
}

<# 
.SYNOPSIS
Try decoding Bytes as ANSI/8-bit Greek text and return success statistics.

.DESCRIPTION
Returns:
    SuspiciousCtrlChars: Count of suspicious control characters (BYTE<32 except TAB, CR, LF)
    GreekLetters       : Count of Greek Letters in text
    GreekRuns          : Count of _contiguous_ sequences of Greek letters
    SurelyISO88597     : If text is Greek, and this is $true, the encoding is definetely ISO-8859-7
    SurelyCP1253       : If text is Greek, and this is $true, the encoding is definetely CP1253
#>
function _Get-GreekLetterStats {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][byte[]]$Bytes
  )

  # Step 1: Decode bytes as CP1253 (Windows-1253)
  $enc=[Text.Encoding]::GetEncoding('windows-1253')
  $s=$enc.GetString($bytes)
  $len=$s.Length
  if($len -eq 0){
      return [pscustomobject]@{SuspiciousCtrlChars=0;GreekLetters=0;GreekRuns=0;SurelyISO88597=$false;SurelyCP1253=$false}
  }


  # Step 2: Count suspicious control characters. That is:
  # ASCII control codes in the range 0x00-0x1F, excluding: TAB, CR, LF
  $ctrlRe='[\x00-\x08\x0B\x0C\x0E-\x1F]'
  $susCtrlCount=[regex]::Matches($s,$ctrlRe).Count

  # Step 3: Measure Greek letters among all letters + Greek letter runs
  # (a contiguous sequence of Greek letters)
  $greekRe='[\u0370-\u03FF\u1F00-\u1FFF]'
  $greekRunRe='[\u0370-\u03FF\u1F00-\u1FFF]{2,}'
  $greekLetters=[regex]::Matches($s,$greekRe).Count
  $letters=[regex]::Matches($s,'\p{L}').Count
  $greekRuns=[regex]::Matches($s,$greekRunRe).Count

  # Step 4: focus on Greek Capital Alpha Tonos (the only letter that is encoded
  # differently between Cp1253 and ISO-8859-7
  # u0386 is a Greek Capital Alpha Tonos encoded and decoded with CP1253
  # u00B6 is a Greek Capital Alpha Tonos encoded with ISO-8859-7 and decoded with CP1253
  $greekCapAlphaTonosWinCount=[regex]::Matches($s,'\u0386').Count 
  $greekCapAlphaTonosISOcount=[regex]::Matches($s,'\u00B6').Count

  [pscustomobject]@{
    SuspiciousCtrlChars=$susCtrlCount
    GreekLetters=$greekLetters
    GreekRuns=$greekRuns
    SurelyISO88597=[boolean]$greekCapAlphaTonosISOcount
    SurelyCP1253=[boolean]$greekCapAlphaTonosWinCount
  }
}

<# Detects if bytes represent Greek 8-bit text and returns "CP1253" or  "ISO-8859-7".
Returns "UNKNOWN", if it doesn't. #>
function _Detect-GreekAnsiEncoding {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][byte[]]$Bytes,
    [switch]$PreferISOEncodings
  )

  $st=_Get-GreekLetterStats -Bytes $Bytes
  $n=$Bytes.Length
  if($n -le 0){ return 'UNKNOWN' }

  $ctrlPct=100.0*$st.SuspiciousCtrlChars/$n
  if($ctrlPct -lt 0.1 -and $st.GreekLetters -gt 3){
    # Doesn't look binary, and has at least 3 Greek letters
    if($st.SurelyISO88597){ return 'ISO-8859-7' }
    if($st.SurelyCP1253){ return 'Windows-1253' }
    if($PreferISOEncodings){ return 'ISO-8859-7' } else {return 'Windows-1253'}
  }
  'UNKNOWN'
}


<#
.SYNOPSIS
Returns the Windows encoding if it produces the same
text as the ISO one, otherwise returns the ISO one.

.DESCRIPTION
It reads the first MaxBytes of the file, decodes them 
using the ISO encoding and then decodes them again with the 
coresponding Windows encoding. If the two texts Match
it returns the Windows encoding, otherwise returns the ISO one.
#>
function _Get-WinEncodingIfSuitable {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][string]$ISOEncoding,
    [Parameter(Mandatory)][string]$WinEncoding,
    [Parameter(Mandatory)][int]$MaxBytes
  )
  $sample = Read-FirstBytes -File $File -Count $MaxBytes
  $encIso   = [Text.Encoding]::GetEncoding($ISOEncoding)
  $encWin  = [Text.Encoding]::GetEncoding($WinEncoding)
  $strIso = $encIso.GetString($sample.Buffer)
  $strWin = $encWin.GetString($sample.Buffer)
  $match = [string]::Equals($strIso,$strWin,[System.StringComparison]::Ordinal)
  write-verbose "_Get-WinEncodingIfSuitable: 'both encodings produce same result'= $match"
  if ($match) {return $WinEncoding} else {return $ISOEncoding}
}

<#
.SYNOPSIS
Use this when something is wrong but you want to respect -ErrorAction

.DESCRIPTION
Provides consistent, PowerShell-style non-terminating errors.

Use _Write-FunctionError when something is wrong but the function should
respect the caller's -ErrorAction:

  - Continue           -> show the error, keep going
  - SilentlyContinue  -> suppress the error
  - Stop              -> turn it into a terminating error (try/catch)

Call it for invalid inputs, missing files, failed I/O, external-tool
failures, or any situation where you want to report a proper ErrorRecord
without unconditionally throwing.

Example:
    _Write-FunctionError -Message "File not found: $Path" `
                        -Category ObjectNotFound `
                        -TargetObject $Path
#>
function _Write-FunctionError {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message,
    [Parameter()][ValidateSet(
      'NotSpecified','InvalidArgument','ObjectNotFound','ResourceUnavailable','OperationTimeout','PermissionDenied'
    )][string]$Category = 'NotSpecified',
    [Parameter()][Object]$TargetObject = $null,
    [Parameter()][string]$ErrorId = 'Get-TextFileEncoding'
  )
  $ex = New-Object System.Exception($Message)
  $ec = [System.Management.Automation.ErrorCategory]::$Category
  $er = New-Object System.Management.Automation.ErrorRecord($ex, $ErrorId, $ec, $TargetObject)
  $PSCmdlet.WriteError($er)
}

<#
.SYNOPSIS
  Safe(shared) read of up to Count bytes from the start of a file.
#>
function Read-FirstBytes {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][int]$Count
  )
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
}


<#
.SYNOPSIS
  Detect BOM and return presence, bytes, and a simple encoding label.
#>
function _Get-FileBomFromPrefix {
  [CmdletBinding()] param([Parameter(Mandatory)][byte[]]$Buffer)
  if($Buffer.Length -ge 4 -and $Buffer[0] -eq 0xFF -and $Buffer[1] -eq 0xFE -and $Buffer[2] -eq 0x00 -and $Buffer[3] -eq 0x00){ 
    return @{Exists=$true;Bytes=@(0xFF,0xFE,0x00,0x00);Enc='UTF-32LE'} 
  }
  if($Buffer.Length -ge 4 -and $Buffer[0] -eq 0x00 -and $Buffer[1] -eq 0x00 -and $Buffer[2] -eq 0xFE -and $Buffer[3] -eq 0xFF){ 
    return @{Exists=$true;Bytes=@(0x00,0x00,0xFE,0xFF);Enc='UTF-32BE'} 
  }
  if($Buffer.Length -ge 3 -and $Buffer[0] -eq 0xEF -and $Buffer[1] -eq 0xBB -and $Buffer[2] -eq 0xBF){ 
    return @{Exists=$true;Bytes=@(0xEF,0xBB,0xBF);Enc='UTF-8'} 
  }
  if($Buffer.Length -ge 2 -and $Buffer[0] -eq 0xFF -and $Buffer[1] -eq 0xFE){ 
    return @{Exists=$true;Bytes=@(0xFF,0xFE);Enc='UTF-16LE'} 
  }
  if($Buffer.Length -ge 2 -and $Buffer[0] -eq 0xFE -and $Buffer[1] -eq 0xFF){ 
    return @{Exists=$true;Bytes=@(0xFE,0xFF);Enc='UTF-16BE'} 
  }
  @{Exists=$false;Bytes=@();Enc=$null}
}

<#
.SYNOPSIS
  Classify a byte buffer sample as ASCII / NON-ASCII / BINARYorUTF1632 and infer line termination style.

.DESCRIPTION
  Heuristic classifier intended for "text vs binary" decisions. Use it to quickly decide "safe to treat as text"
  and "what newline convention is present".
  Works on raw bytes; does not attempt to validate UTF-8 or distinguish ANSI code pages.
  It scans up to the first $MaxBytesToTest bytes of the input buffer and computes simple signals:
    - Detection of any NON-ASCII BYTE (>= 0x80)
    - Detection of "strange" control bytes (strange control bytes are DEL (0x7F) and bytes <0x20 excluding TAB, CR, LF, ESC)
    - Long runs of "strange" control bytes.
    - Newline signals: counts CR, LF, CRLF, LFCR patterns.

  Classification rules (guestimate):
    Content = BINARYorUTF1632 if any of these hold:
      1) LFCR count > 0
      2) CR>0 and LF>0 and either (strangeCtrlRunsCount>0) or (strangePercent>0.01)
      3) strangePercent > 0.1
      4) strangeCtrlRunsCount > 5
      5) maxStrangeCtrlLength > 6
      6) DEL observed AND strangePercent is above a small threshold (DEL is treated as a stronger signal)

    Else Content = NON-ASCII if any byte >= 0x80, otherwise ASCII.

  LineTermination output:
    - For non-binary: 'CRLF', 'LF', 'CR', 'Mixed', or 'None' (no newlines in sample)

  This is intentionally a heuristic: it favors operational usefulness over perfect accuracy, and is
  designed to be fast and allocation-free.

.OUTPUTS
  PSCustomObject with:
    - Content:         'ASCII' | 'NON-ASCII' | 'BINARYorUTF1632'
    - LineTermination: 'CR' | 'LF' | 'CRLF' | 'Mixed' | 'None'

.PARAMETER Buffer
  Byte array to sample (only the first $MaxBytesToTest bytes are analyzed).
#>
function _Get-ByteSampleTextClassification {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][byte[]]$Buffer,
    [byte[]]$BomBytes = @(),
    [int]$MaxBytesToTest = 1024
  )

  $n=0; if($Buffer){ $n=[math]::Min($MaxBytesToTest,[int]$Buffer.Length) }
  $hasNonAscii=$false
  $strangeCtrlCharsCount=0
  $strangeCtrlRunsCount=0
  $maxStrangeCtrlLength=0
  $delCount=0
  $crCount=0; $lfCount=0; $crlfCount=0; $lfcrCount=0
  $run=0

  for($i=$BomBytes.Length;$i -lt $n;$i++){
    $b=$Buffer[$i]
    if($b -ge 0x80){ $hasNonAscii=$true }

    if($b -eq 0x0D){
      $crCount++
      if($i+1 -lt $n -and $Buffer[$i+1] -eq 0x0A){ $crlfCount++ }
    } elseif($b -eq 0x0A){
      $lfCount++
      if($i+2 -lt $n -and $Buffer[$i+1] -eq 0x0D -and $Buffer[$i+2] -ne 0x0A){ $lfcrCount++ }
      # Note that this code avoids missdetecting LFCR in this case:
      # CR-LF-CR-LF
      #    =====
    }

    $isDel = ($b -eq 0x7F)
    if($isDel){ $delCount++ }

    $isStrange = (($b -lt 0x20 -and $b -ne 0x09 -and $b -ne 0x0A -and $b -ne 0x0D -and $b -ne 0x1B) -or $isDel)
    if($isStrange){
      $strangeCtrlCharsCount++
      $run++
    } else {
      if($run -gt 0){
        if($run -gt $maxStrangeCtrlLength){ $maxStrangeCtrlLength=$run }
        if($run -gt 3){ $strangeCtrlRunsCount++ }
        $run=0
      }
    }
  }
  if($run -gt 0){
    if($run -gt $maxStrangeCtrlLength){ $maxStrangeCtrlLength=$run }
    if($run -gt 3){ $strangeCtrlRunsCount++ }
  }

  $strangePercent = if($n -gt 0){ $strangeCtrlCharsCount / [double]$n } else { 0.0 }

  $isBinary1 = ($lfcrCount -gt 0) 
  $isBinary2 = (($crCount -gt 0 -and $lfCount -gt 0) -and (($strangeCtrlRunsCount -gt 0) -or ($strangePercent -gt 0.01))) 
  $isBinary3 = ($strangePercent -gt 0.1) 
  $isBinary4 = ($strangeCtrlRunsCount -gt 5) 
  $isBinary5 = ($maxStrangeCtrlLength -gt 6) 
  $isBinary6 = (($delCount -gt 0) -and ($strangePercent -gt 0.01))
  $isBinary = $isBinary1 -or $isBinary2 -or $isBinary3 -or $isBinary4 -or $isBinary5 -or $isBinary6
  write-verbose "isBinary: $isBinary (1=$isBinary1 2=$isBinary2 3=$isBinary3 4=$isBinary4 5=$isBinary5 6=$isBinary6)"

  $content = if($isBinary){ 'BINARYorUTF1632' } elseif($hasNonAscii){ 'NON-ASCII' } else { 'ASCII' }

  $hasCRLF = ($crlfCount -gt 0)
  $hasCR   = (($crCount - $crlfCount) -gt 0)
  $hasLF   = (($lfCount - $crlfCount) -gt 0)

  $lt = if($hasCRLF -and -not $hasCR -and -not $hasLF){ 'CRLF' }
        elseif(-not $hasCRLF -and $crCount -gt 0 -and $lfCount -eq 0){ 'CR' }
        elseif(-not $hasCRLF -and $lfCount -gt 0 -and $crCount -eq 0){ 'LF' }
        elseif($crCount -eq 0 -and $lfCount -eq 0 -and $crlfCount -eq 0 -and $lfcrCount -eq 0){'None'}
        elseif($isBinary){'N/A'}
        else { 'Mixed' }

  [pscustomobject]@{ Content=$content; LineTermination=$lt }
}

<#
.SYNOPSIS
  Tests whether an executable can be resolved either as a full path or via PATH/PATHEXT.

.DESCRIPTION
  Accepts either:
    - A rooted path (e.g. C:\Tools\uchardet or C:\Tools\uchardet.exe), in which case it checks existence and,
      if no extension was given, also tries common executable extensions (.exe/.cmd/.bat/.com).
    - A bare command name (e.g. uchardet), in which case it resolves it the same way PowerShell would when
      launching a process (Get-Command + PATHEXT).
  Returns $true if the executable can be found, otherwise $false.
#>
function Test-ExeFound {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,Position=0)][string]$Exe
  )

  if([string]::IsNullOrWhiteSpace($Exe)){ return $false }
  $x = $Exe.Trim()

  if([IO.Path]::IsPathRooted($x)){
    if(Test-Path -LiteralPath $x){ return $true }
    $ext = [IO.Path]::GetExtension($x)
    if([string]::IsNullOrWhiteSpace($ext)){
      foreach($e in @('.exe','.cmd','.bat','.com')){
        if(Test-Path -LiteralPath ($x + $e)){ return $true }
      }
    }
    return $false
  }

  $c = Get-Command -Name $x -CommandType 'Application' -ErrorAction SilentlyContinue
  if($c){ return $true }

  $pathext = ($env:PATHEXT -split ';' | Where-Object { $_ } | ForEach-Object { $_.Trim() })
  if($x -match '\.'){ return $false }
  foreach($e in $pathext){
    if(Get-Command -Name ($x + $e) -ErrorAction SilentlyContinue){ return $true }
  }
  return $false
}


<#
.SYNOPSIS
  Runs uchardet with safe quoting and a hard timeout.
.DESCRIPTION
  Never throws; returns a result object with Ok/Encoding, or ErrorMessage on failure.
#>
function Invoke-Uchardet {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][string]$FilePath,
    [string]$ExePath='uchardet',
    [int]$TimeoutMs=3000
  )

  $result=[ordered]@{Ok=$false;Encoding=$null;ExitCode=$null;StdErr=$null;TimedOut=$false;ErrorMessage=$null;Ms=0}
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $p=$null

  try {
    $cmd = Get-Command -Name $ExePath -CommandType Application -ErrorAction SilentlyContinue
    if(-not $cmd){ $result.ErrorMessage='EXE-NOT-FOUND'; return [pscustomobject]$result }

    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=$cmd.Path
    $psi.Arguments=('"'+($FilePath -replace '"','""')+'"')
    $psi.UseShellExecute=$false
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.CreateNoWindow=$true

    $p=New-Object Diagnostics.Process
    $p.StartInfo=$psi
    if(-not $p.Start()){ $result.ErrorMessage='FAILED-TO-START'; return [pscustomobject]$result }

    if(-not $p.WaitForExit($TimeoutMs)){
      try{ $p.CloseMainWindow()|Out-Null }catch{}
      Start-Sleep -Milliseconds 150
      try{ if(-not $p.HasExited){ $p.Kill() } }catch{}
      $result.TimedOut=$true
      $result.ErrorMessage="TIMEOUT ($TimeoutMs ms)"
      return [pscustomobject]$result
    }

    $stdout=$p.StandardOutput.ReadToEnd().Trim()
    $stderr=$p.StandardError.ReadToEnd()

    $result.ExitCode=$p.ExitCode
    $result.StdErr=$stderr

    if($p.ExitCode -ne 0){
      $result.ErrorMessage=("EXITCODE {0}: {1}" -f $p.ExitCode, $stderr)
      return [pscustomobject]$result
    }

    if([string]::IsNullOrWhiteSpace($stdout)){
      $result.ErrorMessage='EMPTY-STDOUT'
      return [pscustomobject]$result
    }

    if(-not [string]::IsNullOrWhiteSpace($stderr)){
      $result.StdErr=$stderr.Trim()
    }

    $result.Ok=$true
    $result.Encoding=$stdout
    return [pscustomobject]$result

  } catch {
    $result.ErrorMessage=$_.Exception.Message
    return [pscustomobject]$result

  } finally {
    $sw.Stop()
    $result.Ms=[int]$sw.ElapsedMilliseconds
    if($p){ try{ $p.Dispose() } catch {} }
  }
}

# ================================
# Internal helpers for Get-TextFileEncoding
# ================================

<# 
Returns a .NET [Text.Encoding] from an "encoding description" string 
(e.g. 'UTF-8 (with BOM)', 'UTF-8 (No BOM)', 'CP1252').
Returns $null if description is unknown. 
NOTE: EncodingDescription strings may contain "(With BOM)" / "(No BOM)" for reporting,
but the returned .NET Encoding object does not include the BOM policy.
BOM handling is implemented explicitly by preserving/prepending BOMBytes when writing.
#>
function _Resolve-TextEncodingString {
  [CmdletBinding()] param(
      [AllowNull()][string]$Description
  )

  <# Normalizes uchardet-style encoding names to .NET GetEncoding()-friendly names
  Returns $null for empty input. #>
  function _Gte_MapUchardetToDotNetName {
    [CmdletBinding()] param([AllowNull()][string]$UchardetName)
    if(-not $UchardetName){return $null}
    $n=$UchardetName.Trim().ToUpperInvariant() -replace '_','-'
    switch -Regex ($n) {
      '^ASCII$' { 'us-ascii'; break }
      '^MAC-CENTRALEUROPE$' { 'x-mac-ce'; break }
      '^MAC-CYRILLIC$' { 'x-mac-cyrillic'; break }
      '^ISO-2022-CN$' { 'x-cp50227'; break }
      '^TIS-620$' { 'windows-874'; break }
      '^ISO-8859-11$' { 'windows-874'; break }
      '^CP(\d{3,5})$' { "windows-$($Matches[1])"; break }
      '^WINDOWS-(\d{3,5})$' { "windows-$($Matches[1])"; break }
      '^ISO-8859-(\d{1,2})$' { "iso-8859-$($Matches[1])"; break }
      default { $UchardetName }
    }
  }


  if (-not $Description) { return $null }
  $base = ($Description -replace '\s+\(With BOM\)\s*$','' -replace '\s+\(No BOM\)\s*$','')
  $name = switch -Regex ($base.ToUpperInvariant()) {
    '^UTF-16LE$' { 'utf-16' }
    '^UTF-16BE$' { 'unicodeFFFE' }
    '^UTF-32LE$' { 'utf-32' }
    '^UTF-32BE$' { 'utf-32BE' }
    '^UTF-8$'    { 'utf-8' }
    '^ASCII$'    { 'us-ascii' }
    '^CP1253$'   { 'windows-1253' }
    default      { _Gte_MapUchardetToDotNetName $base }
  }
  try { [Text.Encoding]::GetEncoding($name) } catch { $null }
}

<#
.SYNOPSIS
  Resolve a path to exactly one existing FileSystem file ([IO.FileInfo]) or return $null.

.DESCRIPTION
  Accepts a path (or FileInfo/DirectoryInfo) and enforces strict "one real file" semantics:
    - Must exist
    - Must be FileSystem provider
    - Must not be a directory
    - If wildcards are used, they must match exactly one item

  On failure, emits a tagged _Write-FunctionError ([RFFP-*]) including both the original input and (when available)
  the resolved full path, then returns $null (caller decides whether to stop via -ErrorAction).

.OUTPUTS
  System.IO.FileInfo or $null.
#>
function Resolve-FileFromPath {
  [CmdletBinding()] param([Parameter(Mandatory)][object]$Path)

  $orig=$Path
  $s=$null

  if($Path -is [IO.FileInfo]){
    $fi=$Path
    if(-not $fi.Exists){ _Write-FunctionError -Message ("File not found [RFFP-NOTFOUND]: input='{0}' resolved='{1}'" -f $orig,$fi.FullName) -Category ObjectNotFound -TargetObject $orig; return $null }
    if($fi.Attributes -band [IO.FileAttributes]::Directory){ _Write-FunctionError -Message ("Path is a directory [RFFP-DIR]: input='{0}' resolved='{1}'" -f $orig,$fi.FullName) -Category InvalidArgument -TargetObject $orig; return $null }
    return [IO.FileInfo]$fi
  }

  if($Path -is [IO.DirectoryInfo]){
    _Write-FunctionError -Message ("Path is a directory [RFFP-DIR]: input='{0}' resolved='{1}'" -f $orig,$Path.FullName) -Category InvalidArgument -TargetObject $orig
    return $null
  }

  $s=("$Path").Trim()
  if([string]::IsNullOrWhiteSpace($s)){
    _Write-FunctionError -Message ("Empty path [RFFP-EMPTY]: input='{0}'" -f $orig) -Category InvalidArgument -TargetObject $orig
    return $null
  }

  $useWildcard=[System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($s)

  try {
    $items = if($useWildcard){
      Get-Item -Path $s -Force -ErrorAction Stop
    } else {
      Get-Item -LiteralPath $s -Force -ErrorAction Stop
    }
  } catch {
    _Write-FunctionError -Message ("File not found [RFFP-NOTFOUND]: input='{0}'" -f $orig) -Category ObjectNotFound -TargetObject $orig
    return $null
  }

  $items=@($items)
  if($items.Count -ne 1){
    $sample=@($items | Select-Object -First 3 | ForEach-Object { $_.FullName }) -join '; '
    _Write-FunctionError -Message ("Ambiguous path [RFFP-MULTI]: input='{0}' matches={1} sample='{2}'" -f $orig,$items.Count,$sample) -Category InvalidArgument -TargetObject $orig
    return $null
  }

  $item=$items[0]
  $resolved=$item.FullName

  if($item.PSProvider.Name -ne 'FileSystem'){
    _Write-FunctionError -Message ("Non-FileSystem path [RFFP-NONFS]: input='{0}' provider='{1}' resolved='{2}'" -f $orig,$item.PSProvider.Name,$resolved) -Category InvalidArgument -TargetObject $orig
    return $null
  }
  if($item.PSIsContainer){
    _Write-FunctionError -Message ("Path is a directory [RFFP-DIR]: input='{0}' resolved='{1}'" -f $orig,$resolved) -Category InvalidArgument -TargetObject $orig
    return $null
  }
  if(-not ($item -is [IO.FileInfo])){
    _Write-FunctionError -Message ("Not a file [RFFP-NOTFILE]: input='{0}' resolved='{1}' type='{2}'" -f $orig,$resolved,$item.GetType().FullName) -Category InvalidArgument -TargetObject $orig
    return $null
  }

  [IO.FileInfo]$item
}

<#
.SYNOPSIS
  Detect newline style in a decoded string. Returns 'CRLF','LF','CR','Mixed','None','NotChecked'.
#>
function Get-NewlineStyle {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][string]$Text
  )
  $hasCRLF = $Text -match "`r`n"
  $hasLF   = $Text -match "(?<!`r)`n"
  $hasCR   = $Text -match "`r(?!`n)"
  if (-not $hasCRLF -and -not $hasLF -and -not $hasCR) { return 'None' }
  $k = @($hasCRLF,$hasLF,$hasCR) | Where-Object {$_} | Measure-Object | Select-Object -ExpandProperty Count
  if ($k -gt 1) { return 'Mixed' }
  if ($hasCRLF) { return 'CRLF' }
  if ($hasLF)   { return 'LF' }
  if ($hasCR)   { return 'CR' }
  return 'Mixed'
}

<#
Validates that a byte[] buffer is UTF-8, while intentionally tolerating an incomplete final UTF-8 sequence.
Returns $true if the buffer contains no invalid UTF-8 sequences in its body.
#>
function Test-BufferIsValidUtf8 {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][byte[]]$Bytes
  )

  $n = if($Bytes){ [int]$Bytes.Length } else { 0 }
  if($n -eq 0){ return $true }

  $utf8Strict = New-Object System.Text.UTF8Encoding($false,$true)

  $maxTrim = if($n -gt 3){ 3 } else { $n }
  for($trim=0; $trim -le $maxTrim; $trim++){
    $len = $n - $trim
    try {
      $dec = $utf8Strict.GetDecoder()
      if($len -gt 0){ $null = $dec.GetCharCount($Bytes,0,$len,$true) } else { $null = $dec.GetCharCount($Bytes,0,0,$true) }
      return $true
    } catch [System.Text.DecoderFallbackException] {
    } catch {
    }
  }

  return $false
}


<# Runs uchardet on the file; Returns Invoke-Uchardet's result object. Note: if file > -MaxBytes it writes SampleBytes to a temp file and runs on that; always cleans temp #>
function _Gte_InvokeUchardetOnFileOrSample {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][byte[]]$SampleBytes,
    [Parameter(Mandatory)][int]$MaxBytes,
    [Parameter(Mandatory)][int]$TimeoutMs,
    [Parameter(Mandatory)][string]$ExePath
  )

  $targetPath = $File.FullName
  $tmp = $null

  if ($File.Length -gt $MaxBytes) {
    try {
      $tmp = [IO.Path]::GetTempFileName()
      [IO.File]::WriteAllBytes($tmp,$SampleBytes)
      if ($null -ne $tmp) { $targetPath = $tmp }
    } catch {
      _Write-FunctionError -Message "Failed to prepare sample for uchardet." -Category ResourceUnavailable -TargetObject $File.FullName
      $targetPath = $File.FullName
      $tmp = $null
    }
  }

  $uRes = Invoke-Uchardet -FilePath $targetPath -TimeoutMs $TimeoutMs -ExePath $ExePath

  if ($tmp -and (Test-Path $tmp)) { Remove-Item -Force -ErrorAction SilentlyContinue $tmp }

  $uRes
}

<# May change uchardet's encoding string 
   returning a final description string 

   These are the ISO encodings that will be translated to Windows ones
   if the Windows ones produce the same text.
     ISO-8859-1  vs Windows-1252 (Western European)
     ISO-8859-9  vs Windows-1254 (Turkish)
     ISO-8859-7  vs Windows-1253 (Greek)
     ISO-8859-8  vs Windows-1255 (Hebrew)
     ISO-8859-13 vs Windows-1257 (Baltic)
#>
function _Gte_LeaveIsoOrSwitchToWin {
  [CmdletBinding()] param(
    [Parameter(Mandatory)][string]$UchardetEncoding,
    [Parameter(Mandatory)][IO.FileInfo]$File,
    [Parameter(Mandatory)][int]$MaxBytes
  )
  $encUpper = $UchardetEncoding.ToUpperInvariant()
    switch($encUpper){
      'ISO-8859-1'  { return (_Get-WinEncodingIfSuitable -File $File -ISOEncoding $encUpper -WinEncoding 'Windows-1252' -MaxBytes $MaxBytes) }
      'ISO-8859-9'  { return (_Get-WinEncodingIfSuitable -File $File -ISOEncoding $encUpper -WinEncoding 'Windows-1254' -MaxBytes $MaxBytes) }
      'ISO-8859-7'  { return (_Get-WinEncodingIfSuitable -File $File -ISOEncoding $encUpper -WinEncoding 'Windows-1253' -MaxBytes $MaxBytes) }
      'ISO-8859-8'  { return (_Get-WinEncodingIfSuitable -File $File -ISOEncoding $encUpper -WinEncoding 'Windows-1255' -MaxBytes $MaxBytes) }
      'ISO-8859-13' { return (_Get-WinEncodingIfSuitable -File $File -ISOEncoding $encUpper -WinEncoding 'Windows-1257' -MaxBytes $MaxBytes) }
    }

  return $UchardetEncoding
}

<#
.SYNOPSIS
  Detect (if possible) or guess the encoding of Text Files.
.DESCRIPTION
  Uses uchardet (CLI) and simple BOM/ASCII checks.
  Returns an object like this:
    File                : C:\tempansi.txt
    Type                : NON-ASCII-TEXT
    BOMBytes            : {}
    UCharDetEncoding    : ISO-8859-1
    EncodingDescription : CP1252
    DotNetEncodingObj   : System.Text.SBCSCodePageEncoding
    NewlineStyle        :
    BytesRead           : 22
    UCharDetTimeMs      : 0
    TotalTimeMs         : 55

.PARAMETER
   -DontPreferUTF8: If the sampled bytes are pure 7-bit ASCII and no BOM 
      is present, the function returns UTF-8 by default (even though ASCII 
      is also valid). This is intentional: it allows later writes/replacements 
      to introduce Unicode without changing the reported encoding unexpectedly. 
      Use -DontPreferUTF8 to return ASCII instead.
      In other words: The default UTF-8 return value is not a strict 
      "encoding detection" result; it is a compatibility policy for downstream 
      editing workflows.
   -PreferISOEncodings: by default we return Windows encodings instead of ISO ones 
      WHEN BOTH PRODUCE THE SAME TEXT. This switch overides that behavior.

.NOTES
  - Will fail for pathological files (e.g. BOM indicates UTF-8 
    but file is UTF-16).
  - It consumes RAM to read the file's bytes, possible twice. 
    (That's why -MaxBytes is by default 512KB)
  - It may fail in very hard cases like:
      - Files larger than 512KB that appear as ASCII in the first
        -MaxBytes and then have some ANSI or UTF-8 bytes.
      - Files with ambiguous ASCII encodings (e.g. ISO-8859-1 /
        CP1252)
  - Respects -ErrorAction by emitting non-terminating errors.
  - By default (without -PreferISOEncodings) it will assume a file
    is encoded with a Windows(CP) encoding if it can be either 
    an ISO encoding (e.g. ISO-8859-1) or a windows one (e.g. CP1251)
    (Since a lot of these encodings are very similar, a file with plenty
    of text but none of the few characters that are encoded
    differently between the ISO/CP encodings can be encoded with both giving
    exactly the same bytes)

For reference these are the default encoding for Notepad, 
PS5 & PS7 per windows version:

-----------------+----------+---------+-----------+--------------
                 |          | PS 5.1  | PS 5.1    | PS 7 either  
Operating System | Notepad  | > a.txt | Out-File  | > or Out-File
-----------------+----------+---------+-----------+--------------
2016 (1607 LTSC) |  ANSI    | ANSI    | UTF-16 LE*|   UTF-8*     
2019 (1809 LTSC) |  ANSI    | ANSI    | UTF-16 LE*|   UTF-8*     
2022 (21H2 LTSC) |  UTF-8*  | ANSI    | UTF-16 LE*|   UTF-8*     
2025 (24H2 LTSC) |  UTF-8*  | ANSI    | UTF-16 LE*|   UTF-8*     
-----------------+----------+---------+-----------+--------------
    *: UTF-8 always without BOM, UTF-16 always with BOM

TODO:
Offer help on how to install uchardet if not found.
#>
function Get-TextFileEncoding {
  [CmdletBinding(SupportsShouldProcess=$false)]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName','LiteralPath','PSPath','Name')]
    [Object]$Path,
    [int]$MaxBytes = 512*1024,
    [int]$TimeoutMs = 3000,
    [switch]$CheckNewLineStyle,
    [string]$UchardetPath,
    [switch]$PreferISOEncodings,
    [switch]$DontPreferUTF8
  )

  begin {
    $uchardetExe = if ($UchardetPath) { $UchardetPath } else { 'uchardet' }
  }

  process {
    $preferIsoEffective = [bool]$PreferISOEncodings

    $totalSw = [Diagnostics.Stopwatch]::StartNew()

    # Step 1 - Resolve + validate the input path (file exists, not a directory)
    write-verbose $Path
    $file = Resolve-FileFromPath -Path $Path
    write-verbose $file.FullName
    if ($null -eq $file) { $totalSw.Stop(); return }

    if ($file.Length -eq 0) {
      $totalSw.Stop()
      return [pscustomobject]@{
        File=$file; 
        Type='EMPTY'
        EncodingDescription=$null
        DotNetEncodingObj=$null
        BOMBytes=[byte[]]@() 
        NewlineStyle=$null
        BytesRead=0
        BytesIgnored=0
        UCharDetEncoding=$null
        UCharDetTimeMs=0
        TotalTimeMs=[int]$totalSw.ElapsedMilliseconds
      }
    }

    # Step 2 - Read up to -MaxBytes and compute quick signals (ASCII-only? BOM?)
    $sample = Read-FirstBytes -File $file -Count $MaxBytes
    $bytes = $sample.Buffer
    $bytesRead = $sample.BytesRead
    Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms Read-FirstBytes done"
    $bom = _Get-FileBomFromPrefix -Buffer $bytes
    Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms _Get-FileBomFromPrefix done"
    if ($bom.Exists) {$maxBytesToTest=1024} else {$maxBytesToTest=$bytesRead}
    $gbstc = _Get-ByteSampleTextClassification -Buffer $bytes -BomBytes $bom.Bytes -MaxBytesToTest $maxBytesToTest
    # Content:         'ASCII' | 'NON-ASCII' | 'BINARYorUTF1632'
    # LineTermination: 'CR' | 'LF' | 'CRLF' | 'Mixed' | 'None' | 'N/A'
    $contentGuesstimate = $gbstc.Content
    $LineTermination = $gbstc.LineTermination
    Write-Verbose  "_Get-ByteSampleTextClassification Content= $contentGuesstimate"
    Write-Verbose  "_Get-ByteSampleTextClassification LineTermination= $LineTermination"
    Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms _Get-ByteSampleTextClassification done"

    $uMs = 0
    $encoding = $null
    $ucdEncoding = $null
    $dgaeEncoding = $null
    $type = 'OTHER'

    # Step 3 - tree of choices
    # 3.1 - if BOM exists: treat BOM as authoritative
    if ($bom.Exists) {
      $encoding = "$($bom.Enc) (With BOM)"
      $type = 'BOM-TEXT'
    } else {

      # 3.2 - If first 1KB is ASCII-only consider ASCII/UTF-8
      if ($contentGuesstimate -eq 'ASCII') {
        $encoding = if ($DontPreferUTF8) { 'ASCII' } else { 'UTF-8' }
        $type = 'ASCII-TEXT'
      } else {

        # 3.3 - if strict UTF-8 validation passes consider UTF-8
        $utf8Ok = Test-BufferIsValidUtf8 -Bytes $bytes
        Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms Test-BufferIsValidUtf8 done"
        if ($utf8Ok) {
          $encoding = 'UTF-8'
          $type = 'NON-ASCII-TEXT'
        } else {
          # 3.4 - no strong easy clues,run uchardet 
          $uRes = _Gte_InvokeUchardetOnFileOrSample -File $file -SampleBytes $bytes -MaxBytes $MaxBytes -TimeoutMs $TimeoutMs -ExePath $uchardetExe
          Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms _Gte_InvokeUchardetOnFileOrSample done"
          $uMs = [int]$uRes.Ms

          if (-not $uRes.Ok) {
            $cat = if ($uRes.TimedOut) { 'OperationTimeout' } else { 'ResourceUnavailable' }
            $errMsg = if ($uRes.ErrorMessage) { $uRes.ErrorMessage } else { 'Unknown' }
            if ($errMsg -eq "EXE-NOT-FOUND") {
              # Attempt to detect ANSI Greek texts without uchardet
              $dgaeEncoding = _Detect-GreekAnsiEncoding $bytes -PreferISOEncodings:$PreferIsoEffective
              if ($dgaeEncoding -ne "UNKNOWN") {
                Write-Verbose  "WARNING: uchardet was not found. Is it installed? Using dgaeEncoding: $dgaeEncoding"
                $encoding = $dgaeEncoding
                $preferIsoEffective = $true
              } else {
                if ($UchardetPath) {$comment = "Are you sure it's at $UchardetPath?"} else {$comment = "Are you sure it's in the path?"}
                _Write-FunctionError -Message ("uchardet was not found. Is it installed? $comment") -Category $cat -TargetObject $file.FullName
              }
            } else {
              _Write-FunctionError -Message ("uchardet error: " + $errMsg) -Category $cat -TargetObject $file.FullName
            }
          } else {
            $ucdEncoding = $uRes.Encoding
            $encoding = if ([string]::IsNullOrWhiteSpace($ucdEncoding)) { $null } else { $ucdEncoding }
            Write-Verbose  "UchardetEncoding = $ucdEncoding"
            if ($contentGuesstimate -eq 'BINARYorUTF1632' -and $ucdEncoding -notlike '*UTF*') {
              # overide Uchardet's guess (it often guesses ISO/Windows encodings for binary files
              $encoding = ""
            }
          }

          # Minor fix: UTF-x --> UTF-x (No BOM)" }
          Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms Encoding #1 = $encoding"
          if ($encoding -like 'UTF-*') { $encoding = "$encoding (No BOM)" }

          # Step 3 - Post-process uchardet output for the special case of similar ISO/Windows encodings
          Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms Encoding #2 = $encoding"
          if (-not $preferIsoEffective -and ($encoding -ne $dgaeEncoding) -and $encoding) {
            $encoding = _Gte_LeaveIsoOrSwitchToWin -UchardetEncoding $encoding -File $file -MaxBytes $MaxBytes
          }
          Write-Verbose  "$([int]$totalSw.ElapsedMilliseconds)ms Encoding #3 = $encoding"

          # Step 5 - Classify the file (ASCII bytes win for Type unless BOM case already handled)
          if ($contentGuesstimate -eq 'ASCII') { $type = 'ASCII-TEXT' }
          elseif ($encoding) { $type = 'NON-ASCII-TEXT' }
          else { $type = 'OTHER' }
        }
      }
    }

    $totalSw.Stop()

    [pscustomobject]@{
      File=$file
      Type=$type
      EncodingDescription=$encoding
      DotNetEncodingObj=(_Resolve-TextEncodingString -Description $encoding)
      BOMBytes=[byte[]]$bom.Bytes
      NewlineStyle=$LineTermination
      BytesRead=$bytesRead
      BytesIgnored=$file.length - $bytesRead
      UCharDetEncoding=$ucdEncoding
      UCharDetTimeMs=[int]$uMs
      TotalTimeMs=[int]$totalSw.ElapsedMilliseconds
    }
  }
}

function Remove-TypographyUnicodeFromTextFile {
<#
.SYNOPSIS
Substitutes Unicode typography characters with ASCII characters in one or
more target text files. Mimics the interface of Edit-TextFile.

.DESCRIPTION
Modifies the specified file or files (if you use wildcards like *.txt) 
in place. Useful for eliminating unnecessary Unicode typography from code.

You may pass wildcards like "*.ps1" to -File.

By default keeps a backup with .bak extension. To skip the Backup
use -Backup "". To change the extension use -Backup "ext".

.OUTPUTS
Produces a psCustomObject for each evaluated file:
  File        = The file path
  Changed     = True/False
  EncodingStr = Human readable encoding.
  EncodingObj = The output of Get-TextFileEncoding
  Details     = Human readable outcome. E.g.:
                "Changes made"
                "Pattern(s) not found"
                "Skipped too big file ..."
                "Ignored empty file"
                "No files matched pattern"

.PARAMETER MaxFileSize
Files larger than these many bytes are ignored.

.PARAMETER PreferISOEncodings
When set, ISO encodings are selected when multiple encodings represent
the text equivalently; otherwise, Windows encodings are selected.

.NOTES
Why we have to do the changes in three batches instead of all together:
By default, PowerShell hashtables (@{} and [ordered]@{}) use culture-sensitive 
linguistic comparison.
Because 0x200B, 0x200C, and 0x200D are invisible formatting characters, 
the linguistic comparer gives them a sorting weight of zero. Therefore, 
PowerShell evaluates them as the exact same string and throws a "Duplicate keys" 
error when building the hashtable.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$File,

        [Parameter()]
        [string]$Backup="bak",

        [Parameter()]
        [long]$MaxFileSize=1001001,
    
        [Parameter()]
        [switch]$PreferISOEncodings
    )

    begin {
        # Define batches once in the begin block for performance
        $batch1 = [ordered]@{
            "$([char]0x201C)" = '"'   # Left Double Quotation Mark
            "$([char]0x201D)" = '"'   # Right Double Quotation Mark
            "$([char]0x2018)" = "'"   # Left Single Quotation Mark
            "$([char]0x2019)" = "'"   # Right Single Quotation Mark
            "$([char]0x2014)" = '-'   # Em Dash
            "$([char]0x2013)" = '-'   # En Dash
            "$([char]0x2212)" = '-'   # Minus Sign
            "$([char]0x2026)" = '...' # Horizontal Ellipsis
            "$([char]0x00A0)" = ' '   # NBSP
            "$([char]0x202F)" = ' '   # NNBSP
            "$([char]0x200B)" = ''    # ZWSP
            "$([char]0x2022)" = '*'   # Bullet
            "$([char]0x00B7)" = '.'   # Middle Dot
            "$([char]0x00D7)" = '*'   # Multiplication Sign
            "$([char]0x00F7)" = '/'   # Division Sign
            "$([char]0x2260)" = '!='  # Not Equal To
            "$([char]0x2248)" = '~='  # Almost Equal To
            "$([char]0x2264)" = '<='  # Less-Than or Equal To
            "$([char]0x2265)" = '>='  # Greater-Than or Equal To
            "$([char]0x2192)" = '->'  # Rightwards Arrow
            "$([char]0x2190)" = '<-'  # Leftwards Arrow
            "$([char]0x21D2)" = '=>'  # Rightwards Double Arrow
            "$([char]0x21D0)" = '<='  # Leftwards Double Arrow
            "$([char]0xFF1A)" = ':'   # Fullwidth Colon
            "$([char]0xFF0C)" = ','   # Fullwidth Comma
        }
        $batch2 = [ordered]@{ "$([char]0x200C)" = '' } # ZWNJ
        $batch3 = [ordered]@{ "$([char]0x200D)" = '' } # ZWJ
    }

    process {
        foreach ($currentPath in $File) {
            $hasWildcards = [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($currentPath)
            $targets = @()

            # Resolve the file paths identically to Edit-TextFile
            if ($hasWildcards) {
                $targets = @(Get-ChildItem -Path $currentPath -File -ErrorAction Stop | Select-Object -ExpandProperty FullName)
                if ($targets.Count -eq 0) {
                    Write-Output [pscustomobject]@{ File=$currentPath; Changed=$false; EncodingStr=$null; EncodingObj=$null; Details="No files matched pattern" }
                    continue
                }
            } else {
                $resolved = (Resolve-Path -LiteralPath $currentPath -ErrorAction Stop).ProviderPath
                $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
                if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolved" }
                $targets = @($resolved)
            }

            $results = foreach ($target in $targets) {
                # Keep track of the backup state PER FILE
                $activeBackup = $Backup

                $res1 = Edit-TextFile -File $target -ReplaceMap $batch1 `
					-Literal -Backup $activeBackup -MaxFileSize $MaxFileSize `
					-PreferISOEncodings $PreferISOEncodings
                if ($res1.Changed) { $activeBackup = "" } 

                $res2 = Edit-TextFile -File $target -ReplaceMap $batch2 `
					-Literal -Backup $activeBackup -MaxFileSize $MaxFileSize `
					-PreferISOEncodings $PreferISOEncodings
                if ($res2.Changed) { $activeBackup = "" } 

                $res3 = Edit-TextFile -File $target -ReplaceMap $batch3 `
					-Literal -Backup $activeBackup -MaxFileSize $MaxFileSize `
					-PreferISOEncodings $PreferISOEncodings

                $anyChanged = ($res1.Changed -or $res2.Changed -or $res3.Changed)
                $details = if ($anyChanged) { "Changes made across typography batches" } else { "Pattern(s) not found" }

                [pscustomobject]@{
                    File     = $res1.File
                    Changed  = $anyChanged
                    EncodingStr = $res1.EncodingStr
                    EncodingObj  = $res1.EncodingObj
                    Details  = $details
                }
            }

            # Return arrays for wildcards, single objects for literal paths
            if ($hasWildcards) { Write-Output $results }
            else { Write-Output ($results | Select-Object -First 1) }
        }
    }
}