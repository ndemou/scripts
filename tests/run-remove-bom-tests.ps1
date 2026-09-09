<#
.SYNOPSIS
Tests BOM removal for exact byte preservation, input selection, and safe writes.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\helpers-text-files.ps1')

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if(-not $Condition){ throw $Message }
}
function Assert-Equal {
  param($Actual, $Expected, [string]$Message)
  if($Actual -cne $Expected){ throw "$Message Expected: $Expected; actual: $Actual" }
}
function Assert-Bytes {
  param([string]$Path, [AllowEmptyCollection()][byte[]]$Expected)
  Assert-Equal ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))) `
    ([Convert]::ToBase64String($Expected)) "Byte mismatch at $Path."
}
function Get-TestFileId {
  param([string]$Path)
  $output = @(& fsutil.exe file queryfileid $Path 2>&1)
  if($LASTEXITCODE -ne 0){ throw "File ID query failed: $output" }
  $output -join "`n"
}
function New-Fixture {
  param([AllowEmptyCollection()][byte[]]$Bytes, [string]$Name='original.txt')
  $directory = Join-Path $tempRoot ([guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $directory | Out-Null
  $file = Join-Path $directory $Name
  [IO.File]::WriteAllBytes($file, $Bytes)
  [pscustomobject]@{ File=$file; Directory=$directory; Original=$Bytes; Id=(Get-TestFileId $file) }
}
function Assert-NoTemporaryFiles {
  param($Fixture)
  Assert-Equal @(Get-ChildItem -LiteralPath $Fixture.Directory -Force -Filter '.sed_*').Count 0 'Temporary files leaked.'
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('remove-bom-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$tests = [Collections.Generic.List[object]]::new()
$encodings = @(
  @{ Label='UTF-8'; Encoding=[Text.UTF8Encoding]::new($true) },
  @{ Label='UTF-16LE'; Encoding=[Text.UnicodeEncoding]::new($false, $true) },
  @{ Label='UTF-16BE'; Encoding=[Text.UnicodeEncoding]::new($true, $true) },
  @{ Label='UTF-32LE'; Encoding=[Text.UTF32Encoding]::new($false, $true) },
  @{ Label='UTF-32BE'; Encoding=[Text.UTF32Encoding]::new($true, $true) }
)
foreach($encoding in $encodings){
  foreach($empty in @($false, $true)){
    $tests.Add(@{ Name="$($encoding.Label), empty body=$empty"; Data=@{ Spec=$encoding; Empty=$empty }; Body={
      param($case)
      $spec = $case.Spec
      $text = if($case.Empty){ '' } else { "start $([char]0x03B1)$([char]0xFEFF)`r`nnext`nlast`r" }
      [byte[]]$body = $spec.Encoding.GetBytes($text)
      [byte[]]$original = @($spec.Encoding.GetPreamble()) + @($body)
      $fixture = New-Fixture $original
      $results = @(Remove-BomFromTextFile $fixture.File)
      Assert-Equal $results.Count 1 'Expected one result.'
      $result = $results[0]
      Assert-True $result.Changed $result.Details
      Assert-Equal $result.BytesRemoved $spec.Encoding.GetPreamble().Length 'Wrong number of removed bytes.'
      Assert-Equal $result.EncodingStr "$($spec.Label) (No BOM)" 'Wrong output encoding.'
      Assert-Bytes $fixture.File $body
      Assert-Bytes ($fixture.File + '.bak') $original
      Assert-True ((Get-TestFileId $fixture.File) -cne $fixture.Id) 'Ordinary file did not use replacement.'
      Assert-NoTemporaryFiles $fixture
      $secondResult = Remove-BomFromTextFile $fixture.File
      Assert-True (-not $secondResult.Changed) 'Second invocation modified a BOM-free file.'
      Assert-Bytes ($fixture.File + '.bak') $original
    } })
  }
}

$noBomCases = @(
  @{ Name='empty'; Bytes=[byte[]]@() },
  @{ Name='plain ASCII'; Bytes=[Text.Encoding]::ASCII.GetBytes("plain`r`ntext") },
  @{ Name='BOM in middle'; Bytes=[byte[]]@(65, 239, 187, 191, 66) },
  @{ Name='partial UTF8 prefix'; Bytes=[byte[]]@(239, 187) },
  @{ Name='partial UTF16 prefix'; Bytes=[byte[]]@(255) },
  @{ Name='partial UTF32 BE prefix'; Bytes=[byte[]]@(0, 0, 254) },
  @{ Name='unrecognized signature'; Bytes=[byte[]]@(43, 47, 118, 56) }
)
foreach($case in $noBomCases){
  $tests.Add(@{ Name="unchanged: $($case.Name)"; Data=$case; Body={
    param($case)
    $fixture = New-Fixture $case.Bytes
    $timestamp = [IO.File]::GetLastWriteTimeUtc($fixture.File)
    $result = Remove-BomFromTextFile $fixture.File
    Assert-True (-not $result.Changed) 'File without a supported BOM was changed.'
    Assert-Equal $result.Details 'No BOM found' 'Unexpected no-op result.'
    Assert-Equal $result.BytesRemoved 0 'No-op claims removed bytes.'
    Assert-Bytes $fixture.File $case.Bytes
    Assert-Equal (Get-TestFileId $fixture.File) $fixture.Id 'No-op replaced the file record.'
    Assert-Equal ([IO.File]::GetLastWriteTimeUtc($fixture.File)) $timestamp 'No-op changed the timestamp.'
    Assert-Equal @(Get-ChildItem -LiteralPath $fixture.Directory -Force).Count 1 'No-op created a backup or temporary file.'
  } })
}

$tests.Add(@{ Name='removes exactly one BOM, even for duplicate input paths'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,239,187,191,65))
  $results = @(Remove-BomFromTextFile -File @($fixture.File, $fixture.File))
  Assert-Equal $results.Count 2 'Expected one result per input.'
  Assert-Equal @($results | Where-Object Changed).Count 1 'Duplicate input was edited twice.'
  Assert-Bytes $fixture.File ([byte[]]@(239,187,191,65))
  Assert-Bytes ($fixture.File + '.bak') $fixture.Original
} })

$tests.Add(@{ Name='wildcard hardlink aliases keep file IDs and remove the BOM once'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,239,187,191,65))
  $link = Join-Path $fixture.Directory 'sibling.txt'
  New-Item -ItemType HardLink -Path $link -Target $fixture.File | Out-Null
  $results = @(Remove-BomFromTextFile (Join-Path $fixture.Directory '*.txt') -Backup '')
  Assert-Equal $results.Count 2 'Expected both wildcard matches.'
  Assert-Equal @($results | Where-Object Changed).Count 1 'Hardlinked record was modified twice.'
  foreach($path in @($fixture.File, $link)){
    Assert-Bytes $path ([byte[]]@(239,187,191,65))
    Assert-Equal (Get-TestFileId $path) $fixture.Id 'Hardlink relationship was broken.'
  }
  Assert-Equal @(Get-ChildItem -LiteralPath $fixture.Directory -Force).Count 2 'Backup-disabled write left files behind.'
} })

$tests.Add(@{ Name='FileInfo pipeline resolves full paths and retains distinct backups'; Body={
  $a = New-Fixture ([byte[]]@(239,187,191,65))
  $b = New-Fixture ([byte[]]@(239,187,191,66))
  $results = @(@((Get-Item -LiteralPath $a.File), (Get-Item -LiteralPath $b.File)) | Remove-BomFromTextFile -Backup orig)
  Assert-Equal @($results | Where-Object Changed).Count 2 'FileInfo pipeline did not process both files.'
  Assert-Bytes $a.File ([byte[]]@(65))
  Assert-Bytes $b.File ([byte[]]@(66))
  Assert-Bytes ($a.File + '.orig') $a.Original
  Assert-Bytes ($b.File + '.orig') $b.Original
} })

$tests.Add(@{ Name='literal brackets and hidden attributes work'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,65)) -Name 'file [1].txt'
  [IO.File]::SetAttributes($fixture.File, [IO.FileAttributes]::Hidden)
  try {
    $result = Remove-BomFromTextFile $fixture.File
    Assert-True $result.Changed $result.Details
    Assert-Bytes $fixture.File ([byte[]]@(65))
    Assert-NoTemporaryFiles $fixture
  } finally { [IO.File]::SetAttributes($fixture.File, [IO.FileAttributes]::Normal) }
} })

$tests.Add(@{ Name='WhatIf creates no backup and preserves every byte'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,65))
  $result = Remove-BomFromTextFile $fixture.File -WhatIf
  Assert-True (-not $result.Changed) 'WhatIf reported a change.'
  Assert-Equal $result.BytesRemoved 0 'WhatIf reported removed bytes.'
  Assert-Bytes $fixture.File $fixture.Original
  Assert-Equal (Get-TestFileId $fixture.File) $fixture.Id 'WhatIf replaced the file.'
  Assert-Equal @(Get-ChildItem -LiteralPath $fixture.Directory -Force).Count 1 'WhatIf created files.'
} })

$tests.Add(@{ Name='size limit skips large files and allows the exact boundary'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,65))
  $result = Remove-BomFromTextFile $fixture.File -MaxFileSize 3
  Assert-True (-not $result.Changed) 'Oversized file was changed.'
  Assert-Bytes $fixture.File $fixture.Original
  $result = Remove-BomFromTextFile $fixture.File -MaxFileSize 4
  Assert-True $result.Changed $result.Details
  Assert-Bytes $fixture.File ([byte[]]@(65))
} })

$tests.Add(@{ Name='no wildcard matches reports a no-op'; Body={
  $results = @(Remove-BomFromTextFile (Join-Path $tempRoot '*.missing'))
  Assert-Equal $results.Count 1 'Expected one no-match result.'
  Assert-Equal $results[0].Details 'No files matched pattern' 'Incorrect no-match message.'
  Assert-True (-not $results[0].Changed) 'Unmatched wildcard claims a change.'
} })

$tests.Add(@{ Name='directories and missing literal paths are rejected'; Body={
  foreach($path in @($tempRoot, (Join-Path $tempRoot 'missing.txt'))){
    $caught = $false
    try { Remove-BomFromTextFile $path -ErrorAction Stop | Out-Null } catch { $caught = $true }
    Assert-True $caught 'Expected invalid input to fail.'
  }
} })

$tests.Add(@{ Name='malformed encoded body is preserved without decoding'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,255,0,192,13,10))
  $result = Remove-BomFromTextFile $fixture.File -Backup ''
  Assert-True $result.Changed $result.Details
  Assert-Bytes $fixture.File ([byte[]]@(255,0,192,13,10))
} })

$tests.Add(@{ Name='backup alias failure preserves all links and reports no change'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,65))
  $backup = $fixture.File + '.bak'
  New-Item -ItemType HardLink -Path $backup -Target $fixture.File | Out-Null
  $result = Remove-BomFromTextFile $fixture.File
  Assert-True (-not $result.Changed) 'Backup alias was accepted.'
  Assert-True ($result.Details -like '*failed:*hardlink*') 'Commit error details are missing.'
  Assert-Equal $result.BytesRemoved 0 'Failed commit reports removed bytes.'
  foreach($path in @($fixture.File, $backup)){
    Assert-Bytes $path $fixture.Original
    Assert-Equal (Get-TestFileId $path) $fixture.Id 'Backup rejection detached a link.'
  }
  Assert-NoTemporaryFiles $fixture
} })

$tests.Add(@{ Name='partial write rolls back and returns a failure result'; Body={
  $fixture = New-Fixture ([byte[]]@(239,187,191,65))
  $link = Join-Path $fixture.Directory 'sibling.txt'
  New-Item -ItemType HardLink -Path $link -Target $fixture.File | Out-Null
  $writer = ${function:_Etf_WriteBytesInPlace}
  $fault = @{ Calls=0 }
  function _Etf_WriteBytesInPlace {
    param($ResolvedPath, [AllowEmptyCollection()][byte[]]$Bytes)
    $fault.Calls++
    if($fault.Calls -eq 1){ [IO.File]::WriteAllBytes($ResolvedPath, [byte[]]@(120)); throw 'Injected write failure' }
    & $writer -ResolvedPath $ResolvedPath -Bytes $Bytes
  }
  $result = Remove-BomFromTextFile $fixture.File
  Assert-True (-not $result.Changed) 'Failed write was reported as successful.'
  Assert-True ($result.Details -like '*Injected write failure*') 'Write failure details were lost.'
  foreach($path in @($fixture.File, $link)){
    Assert-Bytes $path $fixture.Original
    Assert-Equal (Get-TestFileId $path) $fixture.Id 'Rollback broke a hardlink.'
  }
  Assert-Bytes ($fixture.File + '.bak') $fixture.Original
  Assert-NoTemporaryFiles $fixture
} })

$passed = 0
try {
  foreach($test in $tests){
    $data = if($test.ContainsKey('Data')){ $test.Data } else { $null }
    & $test.Body $data
    Write-Host "PASS $($test.Name)" -ForegroundColor Green
    $passed++
  }
  Write-Host "All $passed BOM removal tests passed." -ForegroundColor Green
} finally {
  $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
  $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
  if(-not $resolvedTemp.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($resolvedTemp) -notlike 'remove-bom-tests-*'){ throw "Unsafe cleanup target: $resolvedTemp" }
  Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
}
