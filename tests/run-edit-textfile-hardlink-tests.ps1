<#
.SYNOPSIS
Exercises hardlink-preserving edits, byte fidelity, and failed-commit recovery on Windows.

.DESCRIPTION
Uses real NTFS hardlinks and file IDs, plus injected failures at the commit
boundaries. All fixtures live in one disposable directory. No external test
framework or elevation is required.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\helpers-text-files.ps1')

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw $Message }
}

function Assert-Equal {
  param([AllowNull()]$Actual, [AllowNull()]$Expected, [string]$Message)
  if ($Actual -cne $Expected) { throw "$Message`nExpected: $Expected`nActual: $Actual" }
}

function Assert-Bytes {
  param([string]$Path, [AllowEmptyCollection()][byte[]]$Expected)
  $actual = [IO.File]::ReadAllBytes($Path)
  Assert-Equal ([Convert]::ToBase64String($actual)) ([Convert]::ToBase64String($Expected)) "Byte mismatch at $Path"
}

function Get-FileId {
  param([string]$Path)
  $output = @(& fsutil.exe file queryfileid $Path 2>&1)
  if ($LASTEXITCODE -ne 0) { throw "File ID query failed: $output" }
  return ($output -join "`n")
}

function New-Fixture {
  param([string]$Text = 'before', [Text.Encoding]$Encoding = [Text.UTF8Encoding]::new($false), [int]$LinkCount = 2)
  $directory = Join-Path $tempRoot ([guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $directory | Out-Null
  $file = Join-Path $directory 'original.txt'
  [IO.File]::WriteAllText($file, $Text, $Encoding)
  $links = @($file)
  for ($i = 1; $i -lt $LinkCount; $i++) {
    $link = Join-Path $directory "sibling-$i.txt"
    New-Item -ItemType HardLink -Path $link -Target $file | Out-Null
    $links += $link
  }
  [pscustomobject]@{
    Directory = $directory
    File = $file
    Links = $links
    Id = Get-FileId $file
    Original = [IO.File]::ReadAllBytes($file)
    Tmp = Join-Path $directory 'commit.tmp'
    Bak = "$file.bak"
  }
}

function Assert-Links {
  param($Fixture, [AllowEmptyCollection()][byte[]]$Bytes)
  foreach ($link in $Fixture.Links) {
    Assert-True (Test-Path -LiteralPath $link) "Hardlink disappeared: $link"
    Assert-Equal (Get-FileId $link) $Fixture.Id "File ID changed: $link"
    Assert-Bytes $link $Bytes
  }
}

function Assert-NoStagingFiles {
  param($Fixture)
  $leftovers = @(Get-ChildItem -LiteralPath $Fixture.Directory -Force |
    Where-Object { $_.Name -like '.sed_*' -or $_.Name -eq 'commit.tmp' })
  Assert-Equal $leftovers.Count 0 "Temporary files remain: $(($leftovers | ForEach-Object Name) -join ', ')"
}

function Invoke-Commit {
  param($Fixture, [AllowEmptyCollection()][byte[]]$Bytes = [Text.Encoding]::UTF8.GetBytes('after'),
    [bool]$KeepBackup = $true, [switch]$StrictAtomic)
  Replace-FileBytesSafely -ResolvedPath $Fixture.File -TmpPath $Fixture.Tmp -BakPath $Fixture.Bak `
    -Bytes $Bytes -UserBackup $KeepBackup -StrictAtomic:$StrictAtomic -Retries 0 -ErrorAction Stop
}

function Assert-Throws {
  param([scriptblock]$Action, [string]$Pattern)
  $caught = $null
  try { & $Action | Out-Null } catch { $caught = $_ }
  Assert-True ($null -ne $caught) 'Expected a terminating error.'
  Assert-True ($caught.Exception.Message -like $Pattern) "Unexpected error: $($caught.Exception.Message)"
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('edit-hardlink-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$tests = [Collections.Generic.List[object]]::new()

# The same exact-byte assertions cover changes in length, BOMs, newline styles,
# and non-ASCII input. New directories keep every case independent.
$unicode = [string][char]0x03B1 + [char]0x03B2 + [char]0x03B3 + [char]0x03B4
$cases = @(
  @{ Name = 'shorter text'; Text = 'before and a long suffix'; Pattern = 'before and a long suffix'; Replacement = 'x' },
  @{ Name = 'longer text'; Text = 'before'; Pattern = 'before'; Replacement = ('longer-' * 4096) },
  @{ Name = 'same length'; Text = 'before'; Pattern = 'before'; Replacement = 'AFTERS' },
  @{ Name = 'empty replacement'; Text = 'before'; Pattern = 'before'; Replacement = '' },
  @{ Name = 'one-byte replacement'; Text = 'before'; Pattern = 'before'; Replacement = 'x' },
  @{ Name = 'CRLF retained'; Text = "before`r`nnext`r`n"; Pattern = 'before'; Replacement = 'after' },
  @{ Name = 'LF retained'; Text = "before`nnext`n"; Pattern = 'before'; Replacement = 'after' },
  @{ Name = 'CR retained'; Text = "before`rnext`r"; Pattern = 'before'; Replacement = 'after' },
  @{ Name = 'mixed newlines retained'; Text = "before`r`nx`ny`r"; Pattern = 'before'; Replacement = 'after' },
  @{ Name = 'UTF8 Unicode replacement'; Text = 'before'; Pattern = 'before'; Replacement = $unicode },
  @{ Name = 'UTF8 Unicode input'; Text = "$unicode before"; Pattern = 'before'; Replacement = 'after' },
  @{ Name = 'UTF8 BOM'; Text = "$unicode before"; Pattern = 'before'; Replacement = 'after'; Encoding = [Text.UTF8Encoding]::new($true) },
  @{ Name = 'UTF16 LE BOM'; Text = "$unicode before"; Pattern = 'before'; Replacement = 'after'; Encoding = [Text.UnicodeEncoding]::new($false, $true) },
  @{ Name = 'UTF16 BE BOM'; Text = "$unicode before"; Pattern = 'before'; Replacement = 'after'; Encoding = [Text.UnicodeEncoding]::new($true, $true) },
  @{ Name = 'UTF32 LE BOM'; Text = "$unicode before"; Pattern = 'before'; Replacement = 'after'; Encoding = [Text.UTF32Encoding]::new($false, $true) },
  @{ Name = 'UTF32 BE BOM'; Text = "$unicode before"; Pattern = 'before'; Replacement = 'after'; Encoding = [Text.UTF32Encoding]::new($true, $true) },
  @{ Name = 'UTF8 BOM-only output'; Text = 'before'; Pattern = 'before'; Replacement = ''; Encoding = [Text.UTF8Encoding]::new($true) },
  @{ Name = 'UTF16 BOM-only output'; Text = 'before'; Pattern = 'before'; Replacement = ''; Encoding = [Text.UnicodeEncoding]::new($false, $true) },
  @{ Name = 'regex capture groups'; Text = 'before 123'; Pattern = '(before) (123)'; Replacement = '$2 $1' }
)
foreach ($case in $cases) {
  $tests.Add(@{ Name = $case.Name; Data = $case; Body = {
    param($case)
    $encoding = if ($case.ContainsKey('Encoding')) { $case.Encoding } else { [Text.UTF8Encoding]::new($false) }
    $fixture = New-Fixture -Text $case.Text -Encoding $encoding -LinkCount 3
    $expectedText = [regex]::Replace($case.Text, $case.Pattern, $case.Replacement)
    [byte[]]$expected = @($encoding.GetPreamble()) + @($encoding.GetBytes($expectedText))
    $result = Edit-TextFile $fixture.File -Pattern $case.Pattern -Replacement $case.Replacement
    Assert-True $result.Changed $result.Details
    Assert-Links $fixture $expected
    Assert-Bytes $fixture.Bak $fixture.Original
    Assert-True ((Get-FileId $fixture.Bak) -cne $fixture.Id) 'Backup shares the target file record.'
    Assert-NoStagingFiles $fixture
  } })
}

foreach ($backup in @('', '   ', 'save', '.orig', '  restore  ')) {
  $tests.Add(@{ Name = "backup suffix '$backup'"; Data = $backup; Body = {
    param($backup)
    $fixture = New-Fixture
    $result = Edit-TextFile $fixture.File -Pattern before -Replacement after -Backup $backup
    Assert-True $result.Changed $result.Details
    Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
    $suffix = if ([string]::IsNullOrWhiteSpace($backup)) { '' } else { '.' + $backup.Trim().TrimStart('.') }
    if ($suffix) { Assert-Bytes ($fixture.File + $suffix) $fixture.Original }
    Assert-Equal @(Get-ChildItem -LiteralPath $fixture.Directory -Force).Count (2 + [int][bool]$suffix) 'Unexpected files after backup cleanup.'
    Assert-NoStagingFiles $fixture
  } })
}

$tests.Add(@{ Name = 'edit through a sibling link in a different directory'; Body = {
  $fixture = New-Fixture -LinkCount 3
  $subdirectory = Join-Path $fixture.Directory 'space and apostrophe''s directory'
  New-Item -ItemType Directory -Path $subdirectory | Out-Null
  $link = Join-Path $subdirectory ('link ' + [char]0x03B1 + '.txt')
  New-Item -ItemType HardLink -Path $link -Target $fixture.File | Out-Null
  $fixture.Links += $link
  $result = Edit-TextFile $link -Pattern before -Replacement after
  Assert-True $result.Changed $result.Details
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
  Assert-Bytes "$link.bak" $fixture.Original
} })

$tests.Add(@{ Name = 'sequential replacement map and literal metacharacters'; Body = {
  $fixture = New-Fixture -Text 'before? + before?'
  $result = Edit-TextFile $fixture.File -Literal -ReplaceMap ([ordered]@{ 'before?' = 'middle'; 'middle' = 'after' })
  Assert-True $result.Changed $result.Details
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after + after'))
  Assert-Bytes $fixture.Bak $fixture.Original
} })

foreach ($mode in @('missing pattern', 'identical replacement', 'empty map', 'oversized', 'empty file', 'invalid regex')) {
  $tests.Add(@{ Name = "no writes for $mode"; Data = $mode; Body = {
    param($mode)
    $fixture = New-Fixture -Text $(if ($mode -eq 'empty file') { '' } else { 'before' })
    [IO.File]::WriteAllText($fixture.Bak, 'previous backup')
    $parameters = @{ File = $fixture.File; Pattern = 'before'; Replacement = 'after' }
    switch ($mode) {
      'missing pattern' { $parameters.Pattern = 'missing' }
      'identical replacement' { $parameters.Replacement = 'before' }
      'empty map' { $parameters.Remove('Pattern'); $parameters.Remove('Replacement'); $parameters.ReplaceMap = [ordered]@{} }
      'oversized' { $parameters.MaxFileSize = 1 }
      'invalid regex' { $parameters.Pattern = '[' }
    }
    if ($mode -eq 'invalid regex') { Assert-Throws { Edit-TextFile @parameters } '*Invalid regex*' }
    else { $result = Edit-TextFile @parameters; Assert-True (-not $result.Changed) 'No-op reported a write.' }
    Assert-Links $fixture $fixture.Original
    Assert-Equal ([IO.File]::ReadAllText($fixture.Bak)) 'previous backup' 'No-op replaced the old backup.'
    Assert-NoStagingFiles $fixture
  } })
}

$tests.Add(@{ Name = 'repeated edits refresh backup without detaching links'; Body = {
  $fixture = New-Fixture
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement middle
  Assert-True $result.Changed $result.Details
  $result = Edit-TextFile $fixture.File -Pattern middle -Replacement after
  Assert-True $result.Changed $result.Details
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
  Assert-Bytes $fixture.Bak ([Text.Encoding]::UTF8.GetBytes('middle'))
  Assert-NoStagingFiles $fixture
} })

$tests.Add(@{ Name = 'existing backup hardlinked to a separate file stays independent'; Body = {
  $fixture = New-Fixture
  $oldBackupLink = Join-Path $fixture.Directory 'old-backup.txt'
  [IO.File]::WriteAllText($oldBackupLink, 'old backup')
  New-Item -ItemType HardLink -Path $fixture.Bak -Target $oldBackupLink | Out-Null
  $oldBackupId = Get-FileId $oldBackupLink
  Invoke-Commit $fixture
  Assert-Equal ([IO.File]::ReadAllText($oldBackupLink)) 'old backup' 'Overwriting backup changed an unrelated hardlink.'
  Assert-Equal (Get-FileId $oldBackupLink) $oldBackupId 'Unrelated backup record changed.'
  Assert-Bytes $fixture.Bak $fixture.Original
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
} })

foreach ($linked in @($true, $false)) {
  $tests.Add(@{ Name = "StrictAtomic with hardlinks=$linked"; Data = $linked; Body = {
    param($linked)
    $fixture = New-Fixture -LinkCount $(if ($linked) { 2 } else { 1 })
    if ($linked) {
      [IO.File]::WriteAllText($fixture.Bak, 'previous backup')
      Assert-Throws { Invoke-Commit $fixture -StrictAtomic } '*StrictAtomic*'
      Assert-Links $fixture $fixture.Original
      Assert-Equal ([IO.File]::ReadAllText($fixture.Bak)) 'previous backup' 'StrictAtomic rejection modified the backup.'
    } else {
      Invoke-Commit $fixture -StrictAtomic
      Assert-True ((Get-FileId $fixture.File) -cne $fixture.Id) 'Ordinary file did not use replacement.'
      Assert-Bytes $fixture.File ([Text.Encoding]::UTF8.GetBytes('after'))
    }
    Assert-NoStagingFiles $fixture
  } })
  $tests.Add(@{ Name = "direct empty-byte commit with hardlinks=$linked"; Data = $linked; Body = {
    param($linked)
    $fixture = New-Fixture -LinkCount $(if ($linked) { 2 } else { 1 })
    Invoke-Commit $fixture -Bytes ([byte[]]@())
    if ($linked) { Assert-Links $fixture ([byte[]]@()) } else { Assert-Bytes $fixture.File ([byte[]]@()) }
    Assert-Bytes $fixture.Bak $fixture.Original
    Assert-NoStagingFiles $fixture
  } })
}

$tests.Add(@{ Name = 'last remaining link returns to ordinary atomic replacement'; Body = {
  $fixture = New-Fixture
  Remove-Item -LiteralPath $fixture.Links[1]
  Invoke-Commit $fixture -StrictAtomic
  Assert-True ((Get-FileId $fixture.File) -cne $fixture.Id) 'Single remaining name was treated as multiply hardlinked.'
  Assert-Bytes $fixture.File ([Text.Encoding]::UTF8.GetBytes('after'))
} })

$tests.Add(@{ Name = 'alternate data stream and ACL survive in-place edits'; Body = {
  $fixture = New-Fixture
  Set-Content -LiteralPath $fixture.File -Stream 'test-metadata' -Value 'stream contents' -NoNewline
  $acl = (Get-Acl -LiteralPath $fixture.File).Sddl
  Invoke-Commit $fixture
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
  foreach ($link in $fixture.Links) {
    Assert-Equal (Get-Content -LiteralPath $link -Stream 'test-metadata' -Raw) 'stream contents' 'Alternate data stream was lost.'
    Assert-Equal (Get-Acl -LiteralPath $link).Sddl $acl 'Security descriptor changed.'
  }
} })

foreach ($mode in @('read-only target', 'reader denies writes', 'writer holds file', 'locked backup', 'backup copy failure', 'staging failure', 'detection failure', 'missing LinkType')) {
  $tests.Add(@{ Name = "safe rejection: $mode"; Data = $mode; Body = {
    param($mode)
    $fixture = New-Fixture
    $lock = $null
    try {
      switch ($mode) {
        'read-only target' { (Get-Item -LiteralPath $fixture.File).IsReadOnly = $true }
        'reader denies writes' { $lock = [IO.File]::Open($fixture.Links[1], 'Open', 'Read', 'Read') }
        'writer holds file' { $lock = [IO.File]::Open($fixture.Links[1], 'Open', 'Write', 'ReadWrite') }
        'locked backup' {
          [IO.File]::WriteAllText($fixture.Bak, 'previous backup')
          $lock = [IO.File]::Open($fixture.Bak, 'Open', 'Read', 'Read')
        }
        'backup copy failure' { function Copy-Item { throw 'Injected backup failure' } }
        'staging failure' { $fixture.Tmp = Join-Path $fixture.Directory 'missing\commit.tmp' }
        'detection failure' { function _Etf_TestHasMultipleHardLinks { throw 'Injected detection failure' } }
        'missing LinkType' { function Get-Item { [pscustomobject]@{ Name = 'without provider metadata' } } }
      }
      Assert-Throws { Invoke-Commit $fixture } '*'
    } finally {
      if ($null -ne $lock) { $lock.Dispose() }
      [IO.File]::SetAttributes($fixture.File, [IO.FileAttributes]::Normal)
    }
    Assert-Links $fixture $fixture.Original
    if ($mode -eq 'locked backup') { Assert-Equal ([IO.File]::ReadAllText($fixture.Bak)) 'previous backup' 'Locked backup changed.' }
    Assert-NoStagingFiles $fixture
  } })
}

$tests.Add(@{ Name = 'already-open reader sees new bytes on the same file record'; Body = {
  $fixture = New-Fixture
  $reader = [IO.File]::Open($fixture.Links[1], 'Open', 'Read', 'ReadWrite')
  try {
    Invoke-Commit $fixture
    $buffer = New-Object byte[] 5
    Assert-Equal ($reader.Read($buffer, 0, $buffer.Length)) 5 'Existing reader got wrong length.'
    Assert-Equal ([Text.Encoding]::UTF8.GetString($buffer)) 'after' 'Existing handle did not see updated bytes.'
    Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
  } finally { $reader.Dispose() }
} })

foreach ($mode in @('truncate then fail', 'partial write then fail', 'restore fails')) {
  foreach ($keepBackup in @($true, $false)) {
    $tests.Add(@{ Name = "$mode; keep backup=$keepBackup"; Data = @{ Mode = $mode; Keep = $keepBackup }; Body = {
      param($case)
      $fixture = New-Fixture
      $writer = ${function:_Etf_WriteBytesInPlace}
      $fault = @{ Calls = 0; Mode = $case.Mode }
      function _Etf_WriteBytesInPlace {
        param($ResolvedPath, [AllowEmptyCollection()][byte[]]$Bytes)
        $fault.Calls++
        if ($fault.Calls -eq 1) {
          if ($fault.Mode -eq 'truncate then fail') { [IO.File]::WriteAllBytes($ResolvedPath, [byte[]]@()) }
          else { [IO.File]::WriteAllBytes($ResolvedPath, [byte[]]@(120)) }
          throw 'Injected write failure'
        }
        if ($fault.Mode -eq 'restore fails') { throw 'Injected restore failure' }
        & $writer -ResolvedPath $ResolvedPath -Bytes $Bytes
      }
      Assert-Throws { Invoke-Commit $fixture -KeepBackup $case.Keep } '*Injected write failure*'
      Assert-Equal $fault.Calls 2 'Expected exactly one write and one restore attempt.'
      if ($case.Mode -eq 'restore fails') {
        Assert-Links $fixture ([byte[]]@(120))
        Assert-Bytes $fixture.Bak $fixture.Original
      } else {
        Assert-Links $fixture $fixture.Original
        if ($case.Keep) { Assert-Bytes $fixture.Bak $fixture.Original }
        else { Assert-True (-not (Test-Path -LiteralPath $fixture.Bak)) 'Successful rollback left transient backup.' }
      }
      Assert-NoStagingFiles $fixture
    } })
  }
}

$tests.Add(@{ Name = 'failed write restores an originally empty file'; Body = {
  $fixture = New-Fixture -Text ''
  $writer = ${function:_Etf_WriteBytesInPlace}
  $fault = @{ Calls = 0 }
  function _Etf_WriteBytesInPlace {
    param($ResolvedPath, [AllowEmptyCollection()][byte[]]$Bytes)
    $fault.Calls++
    if ($fault.Calls -eq 1) { [IO.File]::WriteAllBytes($ResolvedPath, [byte[]]@(120)); throw 'Injected write failure' }
    & $writer -ResolvedPath $ResolvedPath -Bytes $Bytes
  }
  Assert-Throws { Invoke-Commit $fixture } '*Injected write failure*'
  Assert-Links $fixture ([byte[]]@())
  Assert-Bytes $fixture.Bak ([byte[]]@())
} })

$tests.Add(@{ Name = 'public edit reports failed commit after restoring every link'; Body = {
  $fixture = New-Fixture
  $writer = ${function:_Etf_WriteBytesInPlace}
  $fault = @{ Calls = 0 }
  function _Etf_WriteBytesInPlace {
    param($ResolvedPath, [AllowEmptyCollection()][byte[]]$Bytes)
    $fault.Calls++
    if ($fault.Calls -eq 1) { [IO.File]::WriteAllBytes($ResolvedPath, [byte[]]@(120)); throw 'Injected failure' }
    & $writer -ResolvedPath $ResolvedPath -Bytes $Bytes
  }
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement after
  Assert-True (-not $result.Changed) 'Failed commit reported Changed=true.'
  Assert-True ($result.Details -like '*Write/commit failed:*Injected failure*') 'Failure details were lost.'
  Assert-Links $fixture $fixture.Original
  Assert-NoStagingFiles $fixture
} })

$tests.Add(@{ Name = 'wildcard edits each shared file record only once'; Body = {
  $fixture = New-Fixture -Text 'a' -LinkCount 3
  $results = @(Edit-TextFile (Join-Path $fixture.Directory '*.txt') -Pattern a -Replacement aa)
  Assert-Equal $results.Count 3 'Expected a result for each matching name.'
  Assert-Equal @($results | Where-Object Changed).Count 1 'A hardlinked record was edited repeatedly.'
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('aa'))
  $backups = @(Get-ChildItem -LiteralPath $fixture.Directory -Filter '*.bak')
  Assert-Equal $backups.Count 1 'Multiple backups were made for one logical edit.'
  Assert-Bytes $backups[0].FullName $fixture.Original
} })

$tests.Add(@{ Name = 'wildcard handles a mixture of linked and independent files'; Body = {
  $fixture = New-Fixture -Text 'a'
  $independent = Join-Path $fixture.Directory 'separate.txt'
  [IO.File]::WriteAllText($independent, 'a')
  $independentId = Get-FileId $independent
  $results = @(Edit-TextFile (Join-Path $fixture.Directory '*.txt') -Pattern a -Replacement aa -Backup '')
  Assert-Equal $results.Count 3 'Expected all three names in the results.'
  Assert-Equal @($results | Where-Object Changed).Count 2 'Expected two distinct files to change.'
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('aa'))
  Assert-Bytes $independent ([Text.Encoding]::UTF8.GetBytes('aa'))
  Assert-True ((Get-FileId $independent) -cne $independentId) 'Ordinary wildcard target lost replacement behavior.'
} })

$tests.Add(@{ Name = 'backup path hardlinked to target is rejected without unlinking it'; Body = {
  $fixture = New-Fixture
  New-Item -ItemType HardLink -Path $fixture.Bak -Target $fixture.File | Out-Null
  $fixture.Links += $fixture.Bak
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement after
  Assert-True (-not $result.Changed) 'Aliased backup was accepted.'
  Assert-Links $fixture $fixture.Original
  Assert-NoStagingFiles $fixture
} })

foreach ($mode in @('temporary equals target', 'backup equals target', 'temporary equals backup', 'normalized target alias', 'temporary hardlinked to target', 'temporary hardlinked to backup', 'preexisting temporary', 'backup directory')) {
  $tests.Add(@{ Name = "reject unsafe paths: $mode"; Data = $mode; Body = {
    param($mode)
    $fixture = New-Fixture
    [IO.File]::WriteAllText($fixture.Bak, 'previous backup')
    $originalBackup = $fixture.Bak
    $verifyTemporary = $false
    switch ($mode) {
      'temporary equals target' { $fixture.Tmp = $fixture.File }
      'backup equals target' { $fixture.Bak = $fixture.File }
      'temporary equals backup' { $fixture.Tmp = $fixture.Bak }
      'normalized target alias' { $fixture.Tmp = Join-Path $fixture.Directory '.\ORIGINAL.txt' }
      'temporary hardlinked to target' { New-Item -ItemType HardLink -Path $fixture.Tmp -Target $fixture.File | Out-Null; $fixture.Links += $fixture.Tmp }
      'temporary hardlinked to backup' { New-Item -ItemType HardLink -Path $fixture.Tmp -Target $fixture.Bak | Out-Null; $verifyTemporary = $true }
      'preexisting temporary' { [IO.File]::WriteAllText($fixture.Tmp, 'previous backup'); $verifyTemporary = $true }
      'backup directory' { $fixture.Bak = Join-Path $fixture.Directory 'backup-directory'; New-Item -ItemType Directory -Path $fixture.Bak | Out-Null }
    }
    Assert-Throws { Invoke-Commit $fixture } '*'
    Assert-Links $fixture $fixture.Original
    Assert-Equal ([IO.File]::ReadAllText($originalBackup)) 'previous backup' 'Unsafe commit modified an existing backup.'
    if ($verifyTemporary) { Assert-Equal ([IO.File]::ReadAllText($fixture.Tmp)) 'previous backup' 'Unsafe commit changed or deleted existing temporary path.' }
    if ($mode -eq 'backup directory') { Assert-True (Test-Path -LiteralPath $fixture.Bak -PathType Container) 'Backup directory was removed.' }
  } })
}

$tests.Add(@{ Name = 'forced ASCII upgrades when Unicode is inserted'; Body = {
  $fixture = New-Fixture
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement $unicode -DontPreferUTF8
  Assert-True $result.Changed $result.Details
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes($unicode))
  Assert-True ($result.EncodingStr -like '*UTF*8*') 'Reported encoding did not reflect the upgrade.'
  Assert-Bytes $fixture.Bak $fixture.Original
} })

$tests.Add(@{ Name = 'hidden hardlink can be edited by its literal path'; Body = {
  $fixture = New-Fixture
  [IO.File]::SetAttributes($fixture.File, [IO.FileAttributes]::Hidden)
  try {
    $result = Edit-TextFile $fixture.File -Pattern before -Replacement after
    Assert-True $result.Changed $result.Details
    Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
    Assert-True ([bool]([IO.File]::GetAttributes($fixture.File) -band [IO.FileAttributes]::Hidden)) 'Hidden attribute changed.'
  } finally { [IO.File]::SetAttributes($fixture.File, [IO.FileAttributes]::Normal) }
} })

$tests.Add(@{ Name = 'public empty replacement also works for an ordinary file'; Body = {
  $fixture = New-Fixture -LinkCount 1
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement ''
  Assert-True $result.Changed $result.Details
  Assert-Bytes $fixture.File ([byte[]]@())
  Assert-True ((Get-FileId $fixture.File) -cne $fixture.Id) 'Empty output lost atomic replacement behavior.'
  Assert-Bytes $fixture.Bak $fixture.Original
} })

foreach ($mode in @('wildcard', 'backup')) {
  $tests.Add(@{ Name = "file identity failure stops $mode edits safely"; Data = $mode; Body = {
    param($mode)
    $fixture = New-Fixture
    function _Etf_GetFileIdentity { throw 'Injected file identity failure' }
    if ($mode -eq 'wildcard') {
      $results = @(Edit-TextFile (Join-Path $fixture.Directory '*.txt') -Pattern before -Replacement after)
      Assert-Equal @($results | Where-Object Changed).Count 0 'Identity failure permitted wildcard edits.'
      Assert-Equal @($results | Where-Object { $_.Details -like '*Injected file identity failure*' }).Count 2 'Identity error was not reported for both names.'
    } else {
      [IO.File]::WriteAllText($fixture.Bak, 'previous backup')
      Assert-Throws { Invoke-Commit $fixture } '*Injected file identity failure*'
      Assert-Equal ([IO.File]::ReadAllText($fixture.Bak)) 'previous backup' 'Failed identity query changed the backup.'
    }
    Assert-Links $fixture $fixture.Original
    Assert-NoStagingFiles $fixture
  } })
}

$tests.Add(@{ Name = 'relative commit paths use the PowerShell location'; Body = {
  $fixture = New-Fixture
  Push-Location -LiteralPath $fixture.Directory
  try {
    Replace-FileBytesSafely -ResolvedPath '.\original.txt' -TmpPath '.\commit.tmp' -BakPath '.\original.txt.bak' `
      -Bytes ([Text.Encoding]::UTF8.GetBytes('after')) -UserBackup $true
  } finally { Pop-Location }
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
  Assert-Bytes $fixture.Bak $fixture.Original
  Assert-NoStagingFiles $fixture
} })

$tests.Add(@{ Name = 'exact file-size limit still permits editing'; Body = {
  $fixture = New-Fixture
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement after -MaxFileSize $fixture.Original.Length
  Assert-True $result.Changed $result.Details
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes('after'))
} })

$tests.Add(@{ Name = 'large hardlink update preserves data outside the encoding sample'; Body = {
  $original = ('a' * 600000) + 'before' + ('z' * 400000)
  $fixture = New-Fixture -Text $original
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement after
  Assert-True $result.Changed $result.Details
  Assert-Links $fixture ([Text.Encoding]::UTF8.GetBytes($original.Replace('before', 'after')))
  Assert-Bytes $fixture.Bak $fixture.Original
} })

$tests.Add(@{ Name = 'forced ASCII stays ASCII for representable text'; Body = {
  $fixture = New-Fixture
  $result = Edit-TextFile $fixture.File -Pattern before -Replacement after -DontPreferUTF8
  Assert-True $result.Changed $result.Details
  Assert-Equal $result.EncodingObj.DotNetEncodingObj.CodePage 20127 'Unnecessary ASCII encoding change.'
  Assert-Links $fixture ([Text.Encoding]::ASCII.GetBytes('after'))
} })

$tests.Add(@{ Name = 'null byte input is rejected before touching any file'; Body = {
  $fixture = New-Fixture
  Assert-Throws { Replace-FileBytesSafely -ResolvedPath $fixture.File -TmpPath $fixture.Tmp -BakPath $fixture.Bak -Bytes $null -UserBackup $true } '*Bytes*null*'
  Assert-Links $fixture $fixture.Original
  Assert-NoStagingFiles $fixture
} })

$tests.Add(@{ Name = 'restoration error reports both failures and the retained backup path'; Body = {
  $fixture = New-Fixture
  $fault = @{ Calls = 0 }
  function _Etf_WriteBytesInPlace {
    $fault.Calls++
    if ($fault.Calls -eq 1) { throw 'first-write-error' }
    throw 'second-restore-error'
  }
  Assert-Throws { Invoke-Commit $fixture -KeepBackup $false } "*first-write-error*second-restore-error*Backup remains at '$($fixture.Bak)'*"
  Assert-Bytes $fixture.Bak $fixture.Original
  Assert-Links $fixture $fixture.Original
} })

$passed = 0
$failures = [Collections.Generic.List[string]]::new()
try {
  foreach ($test in $tests) {
    try {
      $data = if ($test.ContainsKey('Data')) { $test.Data } else { $null }
      & $test.Body $data
      Write-Host "PASS $($test.Name)" -ForegroundColor Green
      $passed++
    } catch {
      $failures.Add("$($test.Name): $($_.Exception.Message)`n$($_.ScriptStackTrace)")
      Write-Host "FAIL $($test.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
  }
  Write-Host "`n$passed / $($tests.Count) hardlink tests passed."
  if ($failures.Count -gt 0) { throw ($failures -join "`n`n") }
} finally {
  $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
  $systemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
  if (-not $resolvedTemp.StartsWith($systemTemp, [StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetFileName($resolvedTemp) -notlike 'edit-hardlink-tests-*') { throw "Unsafe cleanup target: $resolvedTemp" }
  Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
}
