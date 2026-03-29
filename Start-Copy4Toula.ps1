<#
.SYNOPSIS
Minimize copy-pasting and typing while using an LLM like Toula-the-fixer to troubleshoot issues.

.DESCRIPTION
HOW TO USE
----------
Begin by opening a terminal and dot-sourcing this script. E.g.:
    
    $p="C:\IT\bin";$f="Start-Copy4Toula.ps1";mkdir $p -force >$null;iwr -useb https://ndemou.github.io/scripts/$f -out $p\$f; . $p\$f

Then repeat these steps:
  1. Copy code from the LLM
  2. Run `q` in the terminal
  3. Go back to the LLM and click to paste the clipboard.

Every time you run `q` it:
  - Reads code from the clipboard.
  - Executes it.
  - Automatically copies the output back to the clipboard.

    It will copy up to 3000 lines by default. Change like this: 
       $global:SctMaxLinesToCopy = 4000

If you run commands directly (without `q`) use `ccc` to copy all output 
since the last time you run either `q` or `ccc`.

UNDER THE HOOD
--------------
The script maintains two transcript files per PowerShell process:
  1. `$env:TEMP\Toula-the-fixer-$PID.txt`
     Stores the most recent chunk of output.
  2. `$env:TEMP\Toula-the-fixer-$PID.full.txt`
     Stores the cumulative raw history for the current session.

.EXAMPLE
. .\Start-Copy4Toula.ps1
q
...
q
...
#>

if (-not $global:SctMaxLinesToCopy) {
    $global:SctMaxLinesToCopy = 3000
}

function Write-SctConsoleDirect {
    [CmdletBinding()]
    param(
        [string]$Message,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::Gray
    )

    $prevColor = [Console]::ForegroundColor
    try {
        [Console]::ForegroundColor = $Color
        [Console]::WriteLine($Message)
    } finally {
        [Console]::ForegroundColor = $prevColor
    }
}

function Get-SctTranscriptPath {
    "$env:TEMP\Toula-the-fixer-$PID.txt"
}

function Get-SctFullTranscriptPath {
    "$env:TEMP\Toula-the-fixer-$PID.full.txt"
}

function Strip-SctTranscriptBlocks {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines = @()
    )

    $totalLines = $Lines.Count
    if ($totalLines -eq 0) { return @() }

    $startIndex = 0
    $asteriskCount = 0
    for ($i = 0; $i -lt $totalLines; $i++) {
        if ($Lines[$i] -match '\*{20,}') {
            $asteriskCount++
            if ($asteriskCount -eq 2) {
                $startIndex = $i + 1
                break
            }
        }
        if ($i -gt 30) { break }
    }

    $endIndex = $totalLines
    for ($i = $totalLines - 1; $i -ge $startIndex; $i--) {
        if ($Lines[$i] -match 'Windows PowerShell transcript end') {
            if ($i -gt 0 -and $Lines[$i - 1] -match '\*{20,}') {
                $endIndex = $i - 1
            } else {
                $endIndex = $i
            }
            break
        }
    }

    if ($endIndex -le $startIndex) { return @() }
    return $Lines[$startIndex..($endIndex - 1)]
}

function Get-SctCleanedUpText {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines = @()
    )

    if ($Lines.Count -eq 0) { return @() }

    $processedLines = New-Object System.Collections.Generic.List[string]
    $promptRegex = '^\s*(?:(?:\[.*?\]\s*)?(?:PS\s*)?(?:[a-zA-Z]:[\\/][^>]*|\\\\[^>]+)>|PS>)'

    $i = 0
    while ($i -lt $Lines.Count) {
        $line = $Lines[$i].TrimEnd()

        if ($line -match "$promptRegex\s*(.*)$") {
            $cmd = $matches[1]

            if ($cmd.Trim() -eq '') {
                $i++
                continue
            }

            $line = "PS prompt>$cmd"

            if (($i + 2) -lt $Lines.Count) {
                $errLine = $Lines[$i + 1].TrimEnd()
                $emptyLine = $Lines[$i + 2].TrimEnd()

                $isPhantomError = ($errLine -match "^Missing closing '.*' in statement block") -or
                                  ($errLine -match "^The string is missing the terminator") -or
                                  ($errLine -match "^Missing expression after") -or
                                  ($errLine -match "^Incomplete string token")

                if ($isPhantomError -and $emptyLine -eq '') {
                    $i += 3
                    continue
                }
            }
        }

        if ($line -match '^(\s*)[\*\-\=#]{4,}$') {
            $line = "$($matches[1])---"
        }

        $processedLines.Add($line)
        $i++
    }

    $dedupedPrompts = New-Object System.Collections.Generic.List[string]
    $lastPromptLine = $null

    foreach ($line in $processedLines) {
        if ($line -match '^PS prompt>') {
            if ($line -eq $lastPromptLine) { continue }
            $lastPromptLine = $line
        } else {
            $lastPromptLine = $null
        }
        $dedupedPrompts.Add($line)
    }

    $finalLines = New-Object System.Collections.Generic.List[string]
    $emptyCount = 0

    foreach ($line in $dedupedPrompts) {
        if ($line -eq '') {
            $emptyCount++
            if ($emptyCount -le 1 -and $finalLines.Count -gt 0) {
                $finalLines.Add($line)
            }
        } else {
            $emptyCount = 0
            $finalLines.Add($line)
        }
    }

    while ($finalLines.Count -gt 0 -and $finalLines[$finalLines.Count - 1] -eq '') {
        $finalLines.RemoveAt($finalLines.Count - 1)
    }

    # Remove helper invocation commands themselves
    while ($finalLines.Count -gt 0) {
        $lastLine = $finalLines[$finalLines.Count - 1]
        if ($lastLine -match '^PS prompt>(?:ccc|q|Invoke-CommandFromClipboard)\s*$') {
            $finalLines.RemoveAt($finalLines.Count - 1)
            while ($finalLines.Count -gt 0 -and $finalLines[$finalLines.Count - 1] -eq '') {
                $finalLines.RemoveAt($finalLines.Count - 1)
            }
            continue
        }
        break
    }

    return $finalLines.ToArray()
}

function Start-SctTranscriptIfNeeded {
    [CmdletBinding()]
    param()

    $transcriptPath = Get-SctTranscriptPath

    if (-not $global:SctTranscriptActive) {
        Start-Transcript -Path $transcriptPath -Append -Force | Out-Null
        $global:SctTranscriptActive = $true
    }
}

function Restart-SctTranscriptChunk {
    [CmdletBinding()]
    param()

    $transcriptPath = Get-SctTranscriptPath

    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

    $retryCount = 0
    while ((Test-Path $transcriptPath) -and $retryCount -lt 2) {
        try {
            Remove-Item $transcriptPath -Force -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 100
            $retryCount++
        }
    }

    if (Test-Path $transcriptPath) {
        Remove-Item $transcriptPath -Force -ErrorAction SilentlyContinue
    }

    Start-Transcript -Path $transcriptPath -Append -Force | Out-Null
    $global:SctTranscriptActive = $true
}

function Save-SctTranscriptChunk {
    [CmdletBinding()]
    param(
        [switch]$CopyToClipboard,
        [switch]$Quiet
    )

    $transcriptPath = Get-SctTranscriptPath
    $fullPath = Get-SctFullTranscriptPath

    if (-not (Test-Path $transcriptPath)) {
        if (-not $Quiet) {
            Write-SctConsoleDirect -Message "Transcript file not found. Is the session being recorded?" -Color Yellow
        }
        return [pscustomobject]@{
            RawLineCount = 0
            CleanLineCount = 0
            CopiedLineCount = 0
            Copied = $false
            HadData = $false
        }
    }

    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    $rawLines = [System.IO.File]::ReadAllLines($transcriptPath)

    $retryCount = 0
    while ((Test-Path $transcriptPath) -and $retryCount -lt 2) {
        try {
            Remove-Item $transcriptPath -Force -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 100
            $retryCount++
        }
    }

    if (Test-Path $transcriptPath) {
        Remove-Item $transcriptPath -Force -ErrorAction SilentlyContinue
    }

    Start-Transcript -Path $transcriptPath -Append -Force | Out-Null
    $global:SctTranscriptActive = $true

    if ($null -eq $rawLines -or $rawLines.Count -eq 0 -or ($rawLines.Count -eq 1 -and $rawLines[0].Trim() -eq '')) {
        if (-not $Quiet) {
            Write-SctConsoleDirect -Message "No new lines to process." -Color Gray
        }
        return [pscustomobject]@{
            RawLineCount = 0
            CleanLineCount = 0
            CopiedLineCount = 0
            Copied = $false
            HadData = $false
        }
    }

    $strippedLines = Strip-SctTranscriptBlocks -Lines $rawLines

    if ($strippedLines.Count -le 0) {
        if (-not $Quiet) {
            Write-SctConsoleDirect -Message "No new lines to process." -Color Gray
        }
        return [pscustomobject]@{
            RawLineCount = $rawLines.Count
            CleanLineCount = 0
            CopiedLineCount = 0
            Copied = $false
            HadData = $false
        }
    }

    $textToAppend = ($strippedLines -join [Environment]::NewLine) + [Environment]::NewLine
    [System.IO.File]::AppendAllText($fullPath, $textToAppend, [System.Text.Encoding]::Default)

    $cleanedLines = Get-SctCleanedUpText -Lines $strippedLines
    $linesToProcess = $cleanedLines.Count
    $copiedLines = $linesToProcess

    if ($linesToProcess -le 0) {
        if (-not $Quiet) {
            Write-SctConsoleDirect -Message "No new lines to copy." -Color Gray
        }
        return [pscustomobject]@{
            RawLineCount = $rawLines.Count
            CleanLineCount = 0
            CopiedLineCount = 0
            Copied = $false
            HadData = $false
        }
    }

    if ($linesToProcess -gt $global:SctMaxLinesToCopy) {
        if (-not $Quiet) {
            Write-SctConsoleDirect -Message ("*" * 80) -Color Red
            Write-SctConsoleDirect -Message "WARNING: There are $linesToProcess useful lines to copy; only the last $global:SctMaxLinesToCopy will be copied." -Color Red
            Write-SctConsoleDirect -Message "" -Color Red
            Write-SctConsoleDirect -Message "You may wish to copy manually from the .full.txt transcript." -Color Red
            Write-SctConsoleDirect -Message ("*" * 80) -Color Red
        }

        $startIndex = $linesToProcess - $global:SctMaxLinesToCopy
        $cleanedLines = $cleanedLines[$startIndex..($linesToProcess - 1)]
        $copiedLines = $global:SctMaxLinesToCopy
    }

    if ($CopyToClipboard) {
        $textToCopy = $cleanedLines -join [Environment]::NewLine

        if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
            $textToCopy | Set-Clipboard
        } else {
            $tempClip = "$env:TEMP\Toula-clip-$PID.txt"
            [System.IO.File]::WriteAllText($tempClip, $textToCopy, [System.Text.Encoding]::Default)
            cmd.exe /c "clip.exe < `"$tempClip`""
            Remove-Item $tempClip -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $Quiet) {
        if ($CopyToClipboard) {
            Write-SctConsoleDirect -Message "Appended history to .full.txt and copied $copiedLines cleaned line(s) to clipboard." -Color Green
        } else {
            Write-SctConsoleDirect -Message "Appended history to .full.txt and reset the current transcript chunk." -Color Green
        }
    }

    return [pscustomobject]@{
        RawLineCount = $rawLines.Count
        CleanLineCount = $linesToProcess
        CopiedLineCount = $copiedLines
        Copied = [bool]$CopyToClipboard
        HadData = $true
    }
}

function ccc {
    [CmdletBinding()]
    param()

    Save-SctTranscriptChunk -CopyToClipboard
}

function Show-ClipboardParseErrors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][object[]]$ParseErrors
    )

    $lines = $Code -split "`r`n|`n|`r"

    foreach ($errItem in $ParseErrors) {
        $extent = $errItem.Extent
        $lineNumber = $extent.StartLineNumber
        $columnNumber = $extent.StartColumnNumber
        $endColumnNumber = $extent.EndColumnNumber

        if (-not $lineNumber -or $lineNumber -lt 1) { $lineNumber = 1 }
        if (-not $columnNumber -or $columnNumber -lt 1) { $columnNumber = 1 }
        if (-not $endColumnNumber -or $endColumnNumber -lt $columnNumber) { $endColumnNumber = $columnNumber }

        $startLineToShow = [Math]::Max(1, $lineNumber - 2)
        $endLineToShow = [Math]::Min($lines.Count, [Math]::Max($lineNumber, $extent.EndLineNumber))

        Write-Host ("-" * 80) -ForegroundColor DarkGray
        Write-Host ("Line $($lineNumber), Col $($columnNumber): $($errItem.Message)") -ForegroundColor Red

        if ($extent.Text) {
            Write-Host ("Token/Text: " + $extent.Text) -ForegroundColor DarkYellow
        }

        for ($i = $startLineToShow; $i -le $endLineToShow; $i++) {
            $prefix = "{0,5} | " -f $i
            $lineText = $lines[$i - 1]
            Write-Host ($prefix + $lineText) -ForegroundColor Cyan

            if ($i -eq $lineNumber) {
                $caretPad = (' ' * $prefix.Length) + (' ' * ([Math]::Max(0, $columnNumber - 1)))
                $caretLen = [Math]::Max(1, $endColumnNumber - $columnNumber)
                $caret = '^' * $caretLen
                Write-Host ($caretPad + $caret) -ForegroundColor Yellow
            }
        }

        Write-Host
    }

    Write-Host ("-" * 80) -ForegroundColor DarkGray
    Write-Host "Execution skipped because the clipboard contains PowerShell syntax errors." -ForegroundColor Yellow
}

function Invoke-CommandFromClipboard {
<#
.SYNOPSIS
Reads PowerShell code from the clipboard, validates it, executes it, and copies its output.

.DESCRIPTION
Reads the clipboard as raw text. If the clipboard is empty, reports that no code is available.
Before execution, the clipboard text is parsed as PowerShell code. If syntax errors are found,
execution is skipped and detailed parser diagnostics are shown, including the error line,
the two lines before it, and a caret marking the reported position.

If parsing succeeds, the function previews up to the first 4 lines of the clipboard content,
showing "..." only when more lines exist, executes the code, and then automatically copies
the cleaned transcript of that execution to the clipboard.

The amount copied is limited by $global:SctMaxLinesToCopy.

.NOTES
Requires this script to have been dot-sourced so transcript support is active.
#>
    [CmdletBinding()]
    param()

    Write-Host ("_" * 80) -ForegroundColor Cyan

    $clip = Get-Clipboard -Raw
    if ([string]::IsNullOrWhiteSpace($clip)) {
        Write-Host "You haven't copied any code" -ForegroundColor Yellow
        return
    }

    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($clip, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors.Count -gt 0) {
        Write-Host "Clipboard does not contain valid PowerShell code." -ForegroundColor Yellow
        Write-Host
        Show-ClipboardParseErrors -Code $clip -ParseErrors $parseErrors
        Write-Host ("_" * 80) -ForegroundColor Cyan
        return
    }

    $clipLines = $clip -split "`r`n|`n|`r"
    $previewCount = [Math]::Min(4, $clipLines.Count)

    $clipLines | Select-Object -First $previewCount | ForEach-Object {
        Write-Host $_ -ForegroundColor Cyan
    }

    if ($clipLines.Count -gt 4) {
        Write-Host "..." -ForegroundColor Cyan
    }

    Write-Host ("_" * 80) -ForegroundColor Cyan

    Start-SctTranscriptIfNeeded | Out-Null
    Save-SctTranscriptChunk -Quiet | Out-Null

    try {
        Invoke-Expression $clip
    } finally {
        $saveResult = Save-SctTranscriptChunk -CopyToClipboard -Quiet
        if ($saveResult.HadData -and $saveResult.Copied) {
            Write-SctConsoleDirect -Message "Copied $($saveResult.CopiedLineCount) cleaned line(s) of command output to clipboard." -Color Green
            Write-SctConsoleDirect -Message "Full transcript: $(Get-SctFullTranscriptPath)" -Color DarkGray
        } elseif (-not $saveResult.HadData) {
            Write-SctConsoleDirect -Message "The command produced no transcripted output to copy." -Color Gray
        }
    }
}

$transcriptPath = Get-SctTranscriptPath
$fullPath = Get-SctFullTranscriptPath
$isDotSourced = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.InvocationName -eq 'source'

if ($isDotSourced) {
    Set-Alias -Name q -Value Invoke-CommandFromClipboard -Scope Global
    Start-SctTranscriptIfNeeded

    if (-not $global:SctHelpersLoaded) {
        $global:SctHelpersLoaded = $true

        Write-SctConsoleDirect -Message "DETAILS:" -Color DarkGray
        Write-SctConsoleDirect -Message "All output since now will be recorded at: $fullPath" -Color DarkGray
        Write-SctConsoleDirect -Message "The current chunk since last capture/reset will be recorded at: $transcriptPath" -Color DarkGray
        Write-SctConsoleDirect -Message "Will copy at most $($global:SctMaxLinesToCopy) lines of output. Set `$global:SctMaxLinesToCopy to change this limit." -Color DarkGray
        Write-SctConsoleDirect -Message ""
        Write-SctConsoleDirect -Message "HOW TO USE ME:" -Color Green
        Write-SctConsoleDirect -Message "1. Copy PowerShell code to the clipboard." -Color Green
        Write-SctConsoleDirect -Message "2. Run q" -Color Green
        Write-SctConsoleDirect -Message "3. The command output will also be copied to the clipboard." -Color Green
        Write-SctConsoleDirect -Message "You can also run ccc manually to copy the current transcript chunk." -Color Green
        Write-SctConsoleDirect -Message "NOTE: Some rare legacy tools may bypass the transcript." -Color Green
    } else {
        Write-SctConsoleDirect -Message "Helpers are already loaded. Alias 'q' points to Invoke-CommandFromClipboard." -Color Yellow
        Write-SctConsoleDirect -Message "Current chunk transcript: $transcriptPath" -Color DarkGray
        Write-SctConsoleDirect -Message "Full transcript: $fullPath" -Color DarkGray
    }
} else {
    $oldFiles = Get-ChildItem -Path $env:TEMP -Filter "Toula-the-fixer-*.txt*" -ErrorAction SilentlyContinue
    $cleanedCount = 0

    foreach ($file in $oldFiles) {
        if ($file.Name -match 'Toula-the-fixer-(\d+)(?:\.full)?\.txt') {
            $filePid = $matches[1]
            if (-not (Get-Process -Id $filePid -ErrorAction SilentlyContinue)) {
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                $cleanedCount++
            }
        }
    }

    $scriptPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { ".\Toula-ClipboardRunner.ps1" }

    Write-Host "To use this tool, dot-source the script:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ". $scriptPath" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host ""
    Write-Host "Then use:" -ForegroundColor Yellow
    Write-Host "q" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host ""
    Write-Host "That will validate and execute PowerShell code from the clipboard, then copy its output to the clipboard."

    if ($cleanedCount -gt 0) {
        Write-Host "(Cleaned up $cleanedCount orphaned transcript files from previous sessions.)" -ForegroundColor DarkGray
    }
}