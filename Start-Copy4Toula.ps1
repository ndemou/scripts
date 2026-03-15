<#
.SYNOPSIS
  Initializes a session transcript and provides a command to quickly copy recent output.

.DESCRIPTION
  When dot-sourced, this script starts a PowerShell transcript tied to the current 
  process ID (PID) and injects a global function called 'ccc'. 
  Running 'ccc' reads the current transcript file, appends it to a '.full.txt' log, 
  cleans it for readability, copies the clean text to your clipboard and restarts 
  the transcript. So every time you run ccc you get the transcript since last time 
  you called ccc.
  
  *** IMPORTANT: THIS IS NOT THE SAME THING AS COPYING FROM YOUR TERMINAL ***
  Because this tool relies on PowerShell's Start-Transcript engine, it captures 
  data streams rather than screen rendering. This causes a few notable differences:
  
  * Native Executables: Some legacy or external CLI tools (e.g. RUNAS) write directly
    to the console screen buffer, completely bypassing the transcript data stream.
  * Phantom Errors: The engine captures raw parsing hiccups (like the split-second
    before you finish a multiline command), though 'ccc' attempts to sanitize these.
  * Interactive UI: Dynamic elements like progress bars (Write-Progress),
    choice menus, or Read-Host inputs either do not log or log as messy text.
#>

$global:SctMaxLinesToCopy = 3000

function Write-SctConsoleDirect {
    <#
    .SYNOPSIS
        Helper function to write colored console output skipping the transcript file.
    #>
    param (
        [string]$Message,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::Gray
    )
    $prevColor = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    [Console]::WriteLine($Message)
    [Console]::ForegroundColor = $prevColor
}

function Strip-SctTranscriptBlocks {
    param (
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines = @()
    )

    $totalLines = $Lines.Count
    if ($totalLines -eq 0) { return @() }

    # --- A. Remove Transcript Preamble ---
    $startIndex = 0
    $asteriskCount = 0
    for ($i = 0; $i -lt $totalLines; $i++) {
        # Using -match ignores invisible BOM characters at the start of the string
        if ($Lines[$i] -match '\*{20,}') {
            $asteriskCount++
            if ($asteriskCount -eq 2) {
                $startIndex = $i + 1 
                break
            }
        }
        if ($i -gt 30) { break }
    }

    # --- B. Remove Transcript Footer ---
    $endIndex = $totalLines
    for ($i = $totalLines - 1; $i -ge $startIndex; $i--) {
        # Using -match here as well for consistency and safety
        if ($Lines[$i] -match "Windows PowerShell transcript end") {
            if ($i -gt 0 -and $Lines[$i-1] -match '\*{20,}') {
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
    param (
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Lines = @()
    )

    if ($Lines.Count -eq 0) { return @() }

    $processedLines = New-Object System.Collections.Generic.List[string]
    
    # Matches: "PS>", "PS C:\Path>", "[PS] C:\Path>", "\\Server\Share>"
    $promptRegex = '^\s*(?:(?:\[.*?\]\s*)?(?:PS\s*)?(?:[a-zA-Z]:[\\/][^>]*|\\\\[^>]+)>|PS>)'

    # Apply Line-by-Line Formatting Rules
    $i = 0
    while ($i -lt $Lines.Count) {
        $line = $Lines[$i].TrimEnd() 

        # 1. Standardize Prompts and filter empty ones
        if ($line -match "$promptRegex\s*(.*)$") {
            $cmd = $matches[1]
            
            # If the line is just a path prompt with no command, drop it entirely
            if ($cmd.Trim() -eq '') {
                $i++
                continue
            }
            
            # Standardize the prompt format
            $line = "PS prompt>$cmd"

            # 2. Catch and Remove PSReadLine phantom multiline syntax errors
            if (($i + 2) -lt $Lines.Count) {
                $errLine = $Lines[$i+1].TrimEnd()
                $emptyLine = $Lines[$i+2].TrimEnd()
                
                $isPhantomError = ($errLine -match "^Missing closing '.*' in statement block") -or
                                  ($errLine -match "^The string is missing the terminator") -or
                                  ($errLine -match "^Missing expression after") -or
                                  ($errLine -match "^Incomplete string token")
                
                if ($isPhantomError -and $emptyLine -eq '') {
                    # Skip the standardized prompt, the error, and the blank line
                    $i += 3
                    continue
                }
            }
        }

        # 3. Replace structural dividers with "---" preserving leading spaces
        if ($line -match '^(\s*)[\*\-\=#]{4,}$') {
            $line = "$($matches[1])---"
        }

        $processedLines.Add($line)
        $i++
    }

    # Collapse consecutive duplicate PS prompts
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

    # Collapse multiple empty lines and trim starting empty lines
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

    # Trim trailing empty lines
    while ($finalLines.Count -gt 0 -and $finalLines[$finalLines.Count - 1] -eq '') {
        $finalLines.RemoveAt($finalLines.Count - 1)
    }

    # Remove the 'ccc' invocation command itself
    if ($finalLines.Count -gt 0 -and $finalLines[$finalLines.Count - 1] -match '^PS prompt>ccc\s*$') {
        $finalLines.RemoveAt($finalLines.Count - 1)
        
        while ($finalLines.Count -gt 0 -and $finalLines[$finalLines.Count - 1] -eq '') {
            $finalLines.RemoveAt($finalLines.Count - 1)
        }
    }

    return $finalLines.ToArray()
}

function ccc {
    $transcriptPath = "$env:TEMP\Toula-the-fixer-$PID.txt"
    $fullPath       = "$env:TEMP\Toula-the-fixer-$PID.full.txt"

    if (-not (Test-Path $transcriptPath)) {
        Write-SctConsoleDirect -Message "Transcript file not found. Is the session being recorded?" -Color Yellow
        return
    }

    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    $rawLines = [System.IO.File]::ReadAllLines($transcriptPath)

    # Retry logic for file deletion to avoid race conditions with AV/File locks
    $retryCount = 0
    while ((Test-Path $transcriptPath) -and $retryCount -lt 2) {
        try {
            Remove-Item $transcriptPath -Force -ErrorAction Stop
        } catch {
            Start-Sleep -Milliseconds 100
            $retryCount++
        }
    }
    # Fallback cleanup
    if (Test-Path $transcriptPath) { Remove-Item $transcriptPath -Force -ErrorAction SilentlyContinue }

    Start-Transcript -Path $transcriptPath -Append -Force | Out-Null

    if ($null -eq $rawLines -or $rawLines.Count -eq 0 -or ($rawLines.Count -eq 1 -and $rawLines[0].Trim() -eq '')) {
        Write-SctConsoleDirect -Message "No new lines to process." -Color Gray
        return
    }

    $strippedLines = Strip-SctTranscriptBlocks -Lines $rawLines

    if ($strippedLines.Count -le 0) {
        Write-SctConsoleDirect -Message "No new lines to process." -Color Gray
        return
    }

    # Append original output to full history log
    $textToAppend = ($strippedLines -join [Environment]::NewLine) + [Environment]::NewLine
    [System.IO.File]::AppendAllText($fullPath, $textToAppend, [System.Text.Encoding]::Default)

    $cleandLines = Get-SctCleanedUpText -Lines $strippedLines
    $linesToProcess = $cleandLines.Count

    if ($linesToProcess -le 0) {
        Write-SctConsoleDirect -Message "No new lines to copy." -Color Gray
        return
    }

    if ($linesToProcess -gt $global:SctMaxLinesToCopy) {
        Write-SctConsoleDirect -Message ("*" * 80) -Color Red
        Write-SctConsoleDirect -Message "WARNING: There are $linesToProcess useful lines of output to copy; I will only copy the last $global:SctMaxLinesToCopy." -Color Red
        Write-SctConsoleDirect -Message "" -Color Red
        Write-SctConsoleDirect -Message "You may wish to copy manually." -Color Red
        Write-SctConsoleDirect -Message ("*" * 80) -Color Red
        
        $startIndex = $linesToProcess - $global:SctMaxLinesToCopy
        $cleandLines = $cleandLines[$startIndex..($linesToProcess - 1)]
        $linesToProcess = $global:SctMaxLinesToCopy
    }

    $textToCopy = $cleandLines -join [Environment]::NewLine

    if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
        $textToCopy | Set-Clipboard
    } else {
        $tempClip = "$env:TEMP\Toula-clip-$PID.txt"
        [System.IO.File]::WriteAllText($tempClip, $textToCopy, [System.Text.Encoding]::Default)
        cmd.exe /c "clip.exe < `"$tempClip`""
        Remove-Item $tempClip -ErrorAction SilentlyContinue
    }

    Write-SctConsoleDirect -Message "Appended history to .full.txt and copied $linesToProcess cleaned line(s) to clipboard." -Color Green
}

# Main Logic Initialization

$transcriptPath = "$env:TEMP\Toula-the-fixer-$PID.txt"
$isDotSourced = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.InvocationName -eq 'source'

if ($isDotSourced) {
    if (-not $global:SctTranscriptActive) {
        try {
            Start-Transcript -Path $transcriptPath -Append -Force | Out-Null
            $global:SctTranscriptActive = $true
            
            Write-SctConsoleDirect -Message "DETAILS:" -Color DarkGray
            Write-SctConsoleDirect -Message "All output since now will be recorded at: $env:TEMP\Toula-the-fixer-$PID.full.txt" -Color DarkGray
            Write-SctConsoleDirect -Message "The output since last 'ccc' will be recorded at: $transcriptPath" -Color DarkGray
            Write-SctConsoleDirect -Message "Will copy at most $($global:SctMaxLinesToCopy) lines of output. Set `$global:SctMaxLinesToCopy if you want to change this limit" -Color DarkGray
            Write-SctConsoleDirect -Message ""
            Write-SctConsoleDirect -Message "HOW TO USE ME:" -Color Green
            Write-SctConsoleDirect -Message "Run a few commands, then run ccc to copy their output. Repeat." -Color Green
            Write-SctConsoleDirect -Message "CAUTION: The output of some very rare legacy tools like RUNAS will not be copied." -Color Yellow
        } catch {
            Write-Error "Failed to start transcript!"
        }
    } else {
        Write-SctConsoleDirect -Message "'ccc' has already been activated" -Color Yellow
        Write-SctConsoleDirect -Message "DETAILS:" -Color DarkGray
        Write-SctConsoleDirect -Message "All output since activation is being recorded at: $env:TEMP\Toula-the-fixer-$PID.full.txt" -Color DarkGray
        Write-SctConsoleDirect -Message "The output since last 'ccc' is being recorded at: $transcriptPath" -Color DarkGray
        Write-SctConsoleDirect -Message "Will copy at most $($global:SctMaxLinesToCopy) lines of output. Set `$global:SctMaxLinesToCopy if you want to change this limit" -Color DarkGray
    }
} else {
    # Cleanup Routine for Orphaned Sessions
    $oldFiles = Get-ChildItem -Path $env:TEMP -Filter "Toula-the-fixer-*.txt*"
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

    $scriptPath = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { ".\Start-ToulaTranscript.ps1" }

    Write-Host "To use this tool, you must dot-source the script to load the 'ccc' function:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ". $scriptPath" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host ""
    Write-Host "Once dot-sourced, use the 'ccc' command to copy new transcript output to your clipboard."
    
    if ($cleanedCount -gt 0) {
        Write-Host "(Cleaned up $cleanedCount orphaned transcript files from previous sessions.)" -ForegroundColor DarkGray
    }
}