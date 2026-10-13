<#
Public functions
#>

function Write-Host-RED($msg) { Write-Host -ForegroundColor Red $msg }

function Write-Host-YELLOW($msg) { Write-Host -ForegroundColor Yellow $msg }

function Right($text, $length) {
    $startchar = [math]::min($text.length - $Length,$text.length)
    $startchar = [math]::max(0, $startchar)
    $text.SubString($startchar, [math]::min($text.length, $Length))
}

function text_after($text, $start) {
    if ($start -ge $text.length) { "" } else { $text.SubString($start, $text.length - $start) }
}

function CountWordOccurances($word, $file) {
    (Get-Content $file | Select-String "\b$word\b" | Measure-Object -line).lines
}

function SudoRmdir($dirpath) {
    if (-not $dirpath) { throw "Error. SudoRmdir requires a path" }
    $temp_empty_dir = "$Env:TEMP\$(Get-Random).tmp"
    mkdir $temp_empty_dir > $null
    robocopy /MIR $temp_empty_dir $dirpath /NFL /NDL /NJH /NJS /nc /ns /np > $null 2> $null
    $error.clear()
    Remove-Item -recurse -force $dirpath > $null 2> $null
    $error | ForEach-Object { Write-Host -ForegroundColor Red $_.ToString() }
    Remove-Item -recurse -force $temp_empty_dir > $null
}

function RunningWithElevatedRights(){
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WinVer() {
    $RegistryCurrentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if ([int]($RegistryCurrentVersion.CurrentBuildNumber) -ge 22000) { $major_ver = 'Win11' } else { $major_ver = 'Win10' }
    $minor_ver = $RegistryCurrentVersion.DisplayVersion
    if (-not $minor_ver) { $minor_ver = 'r' + $RegistryCurrentVersion.ReleaseId }
    "$major_ver/$minor_ver"
}

function GetBiosSN() { (Get-CimInstance win32_bios).serialnumber }

function GetNameOfLoggedInUser() {
    $output = query user
    $line_with_user = ($output | Select-String '^>')
    if (-not $line_with_user) { $line_with_user = ($output | Select-String 'console') }
    if (-not $line_with_user) { $line_with_user = ($output | Select-String 'rdp-tcp') }
    ($line_with_user -replace '^ *>*','' -replace ' .*','')
}

function GetAnyDeskId() {

    # Case 1: "C:\ProgramData\AnyDesk\system.conf"
    $path = "C:\ProgramData\AnyDesk\system.conf"
    if (Test-Path $path) {
        $match = Select-String '^ad\.anynet\.id=' $path
        if ($match) { return ($match -replace '^.*=','') }
    }

    # Case 3: "C:\Users\$user\AppData\Roaming\AnyDesk\system.conf"
    $user = GetNameOfLoggedInUser
    if ($user) {
        $path = "C:\Users\$user\AppData\Roaming\AnyDesk\system.conf"
        if (Test-Path $path) {
            $match = Select-String '^ad\.anynet\.id=' $path
            if ($match) { return ($match -replace '^.*=','') }
        }
    }

    # Case 3: AppData\Roaming\AnyDesk\system.conf
    Get-ChildItem C:\Users -Directory | ForEach-Object {
        $path = Join-Path $_.FullName 'AppData\Roaming\AnyDesk\system.conf'
        if (Test-Path $path) {
            $match = Select-String '^ad\.anynet\.id=' $path
            if ($match) { return ($match -replace '^.*=','') }
        }
    }

    # Case 4: anydesk.exe --get-id
    $candidates = @(
        'C:\Program Files (x86)\AnyDesk\AnyDesk.exe',
        'C:\Program Files\AnyDesk\AnyDesk.exe'
    )
    foreach ($exe in $candidates) {
        if (Test-Path $exe) {
            $out = & $exe --get-id 2>$null
            if ($out) {
                $id = ($out | Select-String '\d').Line | ForEach-Object {
                    ($_ -replace '[^\d ]','').Trim()
                } | Where-Object { $_ }

                if ($id) { return ($id | Select-Object -First 1) }
            }
        }
    }
}

function Delete-EmptyDirs($SomeDir) {
    foreach ($childDirectory in Get-ChildItem -Force -LiteralPath $SomeDir -Directory) {
        & Delete-EmptyDirs $childDirectory.FullName
    }
    $currentChildren = Get-ChildItem -Force -LiteralPath $SomeDir
    $isEmpty = $currentChildren -eq $null
    if ($SomeDir -and $isEmpty) { Remove-Item -Force -LiteralPath $SomeDir }
}

function Delete-OldFiles($SomeDir, $days) {
    $KillDate = ((Get-Date).AddDays(-$days))
    Get-ChildItem -File -Recurse -ErrorAction SilentlyContinue -Path $SomeDir |
        Where-Object { $_.LastWriteTime -lt $KillDate } |
        Remove-Item -Force -ErrorAction SilentlyContinue
    if ($SomeDir) { Delete-EmptyDirs $SomeDir }
}

function Cleanup-TempDirs($OlderThanDays=5){
    $dirs = @()
    $dirs += (dir "c:\users\*\Appdata\Local\Temp\").fullname
    $dirs += 'C:\Windows\Temp'
    $dirs += 'C:\Windows\Prefetch'
    $dirs | ForEach-Object { Delete-OldFiles $_ $OlderThanDays }
}

function Cleanup-Trash { Clear-RecycleBin -Force }

function Change-AnyDeskSystemSettings {
    $file = "C:\ProgramData\AnyDesk\system.conf"
    $key = "ad.security.interactive_access"
    if (Test-Path $file) {
        if (Select-String -Path $file -Pattern $key) {
            if (Select-String -Path $file -Pattern "$key=0") {
                (Get-Content -Path $file) -Replace "$key=0", "$key=1" | Set-Content -Path $file
                Write-Output "AnyDesk Security Settings adjusted, please restart AnyDesk or PC afterwards"
            } else {
                Write-Host "Custom Security Settings found, not touching"
            }
        } else {
            Add-Content -Path $file -Value "$key=1"
            Write-Output "AnyDesk Security Settings adjusted, please restart AnyDesk or PC afterwards"
        }
    } else {
        Write-Host "$file not found, is AnyDesk installed?"
    }
}

function StopIfNotAnAdmin(){
    if (-not (RunningWithElevatedRights)) {
        Write-Host -ForegroundColor Yellow "Re-run me with administrator privileges"
        WaitForAnyKey "Press any key to close this window"
        exit
    }
}

function StartTranscript($terse_line) {
    Start-Transcript -Append -Path c:\it\log\prepare-laptop.verbose.log > $null
    $ts = (Get-Date -format yyyy-MM-dd` HH:mm:ss)
    $username = GetNameOfLoggedInUser
    $bios_sn = GetBiosSN
    Write-Output "$ts $($env:computername) $bios_sn $username $terse_line" >> c:\it\log\prepare-laptop.short.log
}

function EmptyPcDescr {
    $OSCIM = Get-CimInstance -class Win32_OperatingSystem
    $tmp = $OSCIM.Description
    if ($OSCIM.Description -ne "") {
        $OSCIM.Description = ""
        try { $OSCIM.put() > $null 2>$null } catch {
            Write-Host-YELLOW "I failed to empty the PC description (it is currently set to '$tmp')"
        }
    }
}

function DeleteLocalUserAndData {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName
    )

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'

    try {
        # Use an exact comparison because Get-LocalUser -Name accepts wildcards.
        $users = @(
            Get-LocalUser -ErrorAction Stop |
                Where-Object { $_.Name -ieq $UserName }
        )

        if ($users.Count -ne 1) {
            throw "Expected exactly one local user named '$UserName'; found $($users.Count)."
        }

        $user = $users[0]
        $sidObject = $user.SID
        $sid = $sidObject.Value

        Write-Host "Local user: $($user.Name)"
        Write-Host "SID:        $sid"

        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

        if ($currentSid -eq $sid) {
            throw "Refusing to delete local user '$($user.Name)' because the function is running under that account."
        }

        $profiles = @(
            Get-CimInstance -ClassName Win32_UserProfile |
                Where-Object { $_.SID -eq $sid }
        )

        if ($profiles.Count -gt 1) {
            throw "More than one Win32_UserProfile object was found for SID $sid."
        }

        if ($profiles.Count -eq 1) {
            $profile = $profiles[0]
            $profilePath = $profile.LocalPath

            Write-Host "Profile path: $profilePath"

            if ($profile.Special) {
                throw "Refusing to delete the special system profile for SID $sid."
            }

            if ($profile.Loaded) {
                throw "The profile for '$($user.Name)' is currently loaded. It will not be removed."
            }

            Write-Host "Removing Windows profile registration and profile data..."
            $profile | Remove-CimInstance -ErrorAction Stop

            $remainingProfiles = @(
                Get-CimInstance -ClassName Win32_UserProfile |
                    Where-Object { $_.SID -eq $sid }
            )

            if ($remainingProfiles.Count -ne 0) {
                throw "Profile removal did not complete. SID $sid is still registered."
            }

            if ($profilePath -and (Test-Path -LiteralPath $profilePath)) {
                throw "The profile registration was removed, but data remains at '$profilePath'. The local user account was not deleted."
            }

            Write-Host "Windows profile removed successfully."
        } else {
            Write-Host "No Windows profile is registered for SID $sid."
        }

        # Delete by the SID captured during the initial lookup, preventing
        # deletion of a different account if the name changes or is reused.
        Write-Host "Removing local user account: $($user.Name)"
        Remove-LocalUser -SID $sidObject -Confirm:$false -ErrorAction Stop

        Write-Host "Successfully removed local user '$($user.Name)' and its registered profile."
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
}

function EraseLastScreenLine{
    $pos = $host.UI.RawUI.CursorPosition
    $host.UI.RawUI.CursorPosition = @{x=0; y=$pos.y}
    Write-Host -NoNewline (" "*($host.UI.RawUI.WindowSize.Width))
    $host.UI.RawUI.CursorPosition = @{x=0; y=$pos.y}
}

function EraseLastScreenCharacter{
    $pos = $host.UI.RawUI.CursorPosition
    if ($pos.x -ge 1) {
        $host.UI.RawUI.CursorPosition = @{x=$pos.x-1; y=$pos.y}
        Write-Host -NoNewline " "
        $host.UI.RawUI.CursorPosition = @{x=$pos.x-1; y=$pos.y}
    }
}

function WaitForAnyKey($prompt) {
    if ($prompt) { Write-Host -ForegroundColor White -NoNewline $prompt }
    Write-Host -ForegroundColor Cyan -NoNewline " $([char]9658)"
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    EraseLastScreenCharacter
    Write-Host ""
}

function _PrintPrompt($prompt, $choices_txt, $highlighted) {
    if ($choices_txt) {
        if ($highlighted) {
            Write-Host -ForegroundColor Cyan -NoNewline "$prompt "
            $parts = ($choices_txt -split '~')
            Write-Host -ForegroundColor White -NoNewline $parts[0]
            if ($parts.Length -gt 1) {
                $parts[1..99] | ForEach-Object{
                    if ($_) {
                        Write-Host -BackgroundColor Blue -ForegroundColor White -NoNewline "$($_[0])"
                        Write-Host -ForegroundColor White -NoNewline (text_after $_ 1)
                    }
                }
            }
        } else {
            $padding = (($choices_txt -replace '~(.)','$1') -replace '.',' ')
            Write-Host -ForegroundColor Gray -NoNewline "$prompt $padding"
        }
    } else {
        if ($highlighted) { Write-Host -ForegroundColor Cyan -NoNewline $prompt } else { Write-Host -ForegroundColor Gray -NoNewline $prompt }
    }
}

function ReadUntilItMatches($prompt, $default='', $pattern='', $choices=@()) {
    $choices_txt = ""
    if ($choices) {
        $pattern = "^["
        $choice_chars = @()
        $choices | ForEach-Object{
            $char = $_ -replace '^.*~(.).*$','$1'
            $pattern += $char
            $choice_chars += @($char)
        }
        $pattern += ']$'
        $choices_txt = "($($choices -join ', '))"
        $choice_chars = $choice_chars -join ' '
    }

    $in = $null
    while (($null -eq $in) -or ($in -notmatch $pattern)) {
        $pos = $host.UI.RawUI.CursorPosition
        _PrintPrompt $prompt $choices_txt $true
        Write-Host -ForegroundColor Cyan -NoNewline " $([char]9658) "
        if ($default) {
            Write-Host -ForegroundColor Cyan -NoNewline "$default"
            while (-not [console]::KeyAvailable) { Start-Sleep 0.1 }
            EraseLastScreenCharacter
        }
        $in = Read-Host
        if (($in -eq "") -and $default) {
            Write-Host -ForegroundColor Cyan -NoNewline "$default"
            $in = $default
        }

        $host.UI.RawUI.CursorPosition = @{x=0; y=$pos.y}
        if ($in -match $pattern) {
            _PrintPrompt $prompt $choices_txt $false
            Write-Host -ForegroundColor Gray -NoNewline "  $($in -replace '.',' ') "
            $host.UI.RawUI.CursorPosition = @{x=0; y=$pos.y}
            Write-Host -ForegroundColor Gray -NoNewline $prompt
            Write-Host -ForegroundColor White -NoNewline " $([char]9658) "
            if ($choices) {
                $choices | Where-Object { $_ -like "*~$in*" } | Select-Object -First 1 | ForEach-Object {
                    Write-Host -ForegroundColor Cyan ("$_" -replace '~','')
                }
            } else {
                Write-Host -ForegroundColor Cyan "$in"
            }
        } else {
            _PrintPrompt $prompt $choices_txt $false
            Write-Host -ForegroundColor Gray -NoNewline " $([char]9658) "
            Write-Host -ForegroundColor Gray "$in" -NoNewline
            if ($choices) { Write-Host -ForegroundColor Yellow " (Valid choices are: $choice_chars)" } else { Write-Host -ForegroundColor Yellow " (invalid input)" }
        }
    }
    $in
}

function YesNoQuestion($question, $default='N') { ReadUntilItMatches $question -default $default -choices @("~Yes", "~No") }

function PromptForLocalAccountPassword {
    Write-Host ""
    Write-Host "Please enter the temporary password for the new local account." -ForegroundColor Gray
    ReadUntilItMatches "Temporary password"
}

function AskIfTestPasses($descr, $notes) {
    if ($notes) {
        Write-Host ""
        Write-Host -ForegroundColor Gray "($notes)"
    }
    $failed = ((YesNoQuestion $descr) -eq "n")
    if ($failed) {
        Write-Host -NoNewline -BackgroundColor Red -ForegroundColor White "FAIL"
        Write-Host -ForegroundColor Red " $descr"
    }
}

function TestAndDisplayResult($Title, $Test, $FailureCmnt) {
    if ($Test) {
        Write-Host -NoNewline -ForegroundColor Green "PASS "
        Write-Host "$Title" -ForegroundColor Gray
    } else {
        Write-Host -NoNewline -BackgroundColor Red -ForegroundColor White "FAIL"
        Write-Host -ForegroundColor Red " $Title"
        if ($FailureCmnt) { Write-Host -ForegroundColor Yellow "     $FailureCmnt" }
    }
}

function PromptForMazarsOfficeLocation {
    $locations = @(Get-Config 'OfficeLocations')
    $choices = @()
    foreach ($item in $locations) { $choices += "~$item" }

    $site = ''
    while (-not $site) {
        $key = ReadUntilItMatches "Where will the laptop be stored?" -choices $choices
        foreach ($location in $locations) {
            if ($key -ieq $location.Substring(0,1)) {
                $site = $location
                break
            }
        }
    }
    $site
}

function PromptForStickerNr {
    ReadUntilItMatches "Enter the number you see on the asset sticker (e.g. 123)" -pattern "^[0-9][0-9][0-9][0-9]*$"
}

function PromptToRecordIssueEntry($msg){
    Write-Host "Please record the following under the appropriate issue:" -ForegroundColor Gray
    if ($msg -is [string]) {
        Write-Host "   $msg" -ForegroundColor Magenta
    } elseif ($msg -is [System.Collections.IEnumerable]) {
        $msg | ForEach-Object { Write-Host "   $_" -ForegroundColor Magenta }
    } else {
        throw "PromptToRecordIssueEntry: msg must be either string or array/Enumerable"
    }
    Write-Host ""
}

function DisplayBitlockRecKeyLastDigits {
    Get-BitLockerVolume | ForEach-Object {
        $MountPoint = $_.MountPoint
        $RecoveryKey = [string]($_.KeyProtector).RecoveryPassword
        if ($RecoveryKey.Length -gt 5) {
            $last_digits = $RecoveryKey.Substring(42)
            Write-Output ("    Drive $MountPoint, last digits of BitLocker recovery key ...$last_digits.")
        }
    }
}

function GetNameOfLoggedInUser_with_UI() {
    $username = GetNameOfLoggedInUser
    if (-not ($username -match "[a-z]")) {
        Write-Host ""
        Write-Host "(If the user is logged in then notify the maintainer that auto-detection failed and continue)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please enter the name (LATIN letters) of the user"
        $username = (ReadUntilItMatches "Name" -pattern "^[a-zA-Z]")
    }
    $username
}


function BiosSnToSafeShortStr($text) { Right ($text -replace "[^a-zA-Z0-9]","") 8 }

function UpdateMobosTxt() {
    $assetNameRegex = Get-Config 'AssetComputerNameRegex'
    if (-not ($env:computername -match $assetNameRegex)) { return }

    if (-not (Test-Path -Path "C:\it\logs\mobos_*" -PathType Leaf)) {
        $null = New-Item -ItemType File -Path "C:\it\logs\mobos_.txt" -Force -ErrorAction Stop
    }

    $Mobos=(Get-Item "C:\it\logs\mobos_*.txt" | Select-Object -last 1)
    $Current_SN = (BiosSnToSafeShortStr (GetBiosSN))
    $Last_SN = ($Mobos.BaseName -split "_")[-1]
    if ($Last_SN -ne $Current_SN) {
        if ($Last_SN) {
            Write-Host "Detected a new motherboard ($(GetBiosSN)), updating c:\it\logs\mobos_...txt" -ForegroundColor Cyan
        } else {
            Write-Host "This is the first time this code runs on this motherboard. Recording S/N $(GetBiosSN) to c:\it\logs\mobos_...txt" -ForegroundColor Cyan
        }
        $newname = ("$($Mobos.BaseName)_$Current_SN.txt")
        Rename-Item $Mobos -NewName $newname
        $ts = (Get-Date -format yyyy-MM-dd` HH:mm:ss)
        $username = GetNameOfLoggedInUser
        $bios_sn = GetBiosSN
        Write-Output "                    I detected a new motherboard. I'm noting some basic information below" >> "c:\it\logs\$newname"
        Write-Output "$ts PCNAME=$($env:computername) BIOS_SN=$bios_sn WINDOWS_USER=$username" >> "c:\it\logs\$newname"
    }
}

function Invoke-MinimumSetup {
    $FLAG_FILE = "c:\it\data\flag_prepare_laptop_initial_setup_done"
    if (Test-Path $FLAG_FILE) {
        Write-Host "One-time installations already performed - skipping" -ForegroundColor DarkGray
    } else {
        Write-Host "Performing one-time installations (NuGet & PSWindowsUpdateI don't see the file: $FLAG_FILE)" -ForegroundColor DarkGray
        mkdir -force c:\it > $null
        mkdir -force c:\it\data > $null
        mkdir -force c:\it\logs > $null
        mkdir -force c:\it\temp > $null
        mkdir -force c:\it\bin > $null
        mkdir -force c:\it\config > $null
        try {
            Write-Host "Installing NuGet & PSWindowsUpdate" -ForegroundColor DarkGray
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            Install-Module PSWindowsUpdate -Confirm:$False -Force
            echo "" > $FLAG_FILE
        } catch {
            Write-Host "Failed to install NuGet & PSWindowsUpdate -- please investigate" -ForegroundColor Red
        }
    }

    
}

function Test-OnMainsPower {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus -eq 'Online'
}

function Wait-UntilMainsPowerRemoved {
    [CmdletBinding()]
    param(
        [int]$PollSeconds = 1
    )

    if ($PollSeconds -lt 1) {
        throw "PollSeconds must be >= 1"
    }

    Write-Host "Waiting until mains power is removed. Press A to abort..." -NoNewline

    while (Test-OnMainsPower) {
        $deadline = [DateTime]::UtcNow.AddSeconds($PollSeconds)

        while ([DateTime]::UtcNow -lt $deadline) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)

                if ($key.Key -eq [ConsoleKey]::A) {
                    Write-Host ""
                    Write-Host "Waiting aborted by user."
                    return
                }
            }

            Start-Sleep -Milliseconds 100
        }

        Write-Host "." -NoNewline
    }

    Write-Host ""
    Write-Host "Mains power removed."
}

#------------------------------------------
# functions exposed to the IT technicians
#
function enlCleanupTrash {
    StopIfNotAnAdmin
    write-host "Cleaning up Recycle bin"
    Cleanup-Trash
}


function enlCleanupTempDirs {
    StopIfNotAnAdmin
    write-host "Cleaning up TEMP dirs from files older than 2 days"
    Cleanup-TempDirs 2
}


#TODO use the uninstall script that Kvan wrote
function enlUninstallAnydeskIfPresent {
    if (Test-Path "C:\Program Files (x86)\AnyDesk\AnyDesk.exe") {
        & "C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --uninstall
        Remove-Item C:\Users\*\AppData\Roaming\AnyDesk\*.conf -Force
    }
    if (Test-Path "C:\Program Files\AnyDesk\AnyDesk.exe") {
        & "C:\Program Files\AnyDesk\AnyDesk.exe" --uninstall
        Remove-Item C:\Users\*\AppData\Roaming\AnyDesk\*.conf -Force
    }
}


function enlKeepRestorePoint {
    $restoreRegPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $frequencyName = 'SystemRestorePointCreationFrequency'
    $systemDrive = "$env:SystemDrive\"

    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This function must be run from an elevated PowerShell session.'
    }

    if (-not (Test-Path -LiteralPath $restoreRegPath)) {
        throw "System Restore registry path not found: $restoreRegPath"
    }

    $oldProps = Get-ItemProperty -LiteralPath $restoreRegPath -ErrorAction Stop
    $oldFrequencyProp = $oldProps.PSObject.Properties |
        Where-Object { $_.Name -eq $frequencyName }

    $hadFrequencyValue = $null -ne $oldFrequencyProp
    $oldFrequencyValue = $null

    if ($hadFrequencyValue) {
        $oldFrequencyValue = $oldFrequencyProp.Value
    }

    try {
        Enable-ComputerRestore -Drive $systemDrive

        New-ItemProperty `
            -LiteralPath $restoreRegPath `
            -Name $frequencyName `
            -PropertyType DWord `
            -Value 0 `
            -Force |
            Out-Null

        Checkpoint-Computer `
            -Description "Manual Restore Point" `
            -RestorePointType "MODIFY_SETTINGS"

        Write-Output "Restore point requested for $systemDrive"
    }
    finally {
        if ($hadFrequencyValue) {
            New-ItemProperty `
                -LiteralPath $restoreRegPath `
                -Name $frequencyName `
                -PropertyType DWord `
                -Value $oldFrequencyValue `
                -Force |
                Out-Null

            Write-Output "Restored $frequencyName to previous value: $oldFrequencyValue"
        }
        else {
            Remove-ItemProperty `
                -LiteralPath $restoreRegPath `
                -Name $frequencyName `
                -ErrorAction SilentlyContinue

            Write-Output "Removed $frequencyName to restore Windows default behavior"
        }
    }
}


function enlShowBitlockerCmds {
    $encrypted = (Get-BitLockerVolume | ForEach-Object {
        $MountPoint = $_.MountPoint
        ($_.KeyProtector) | Where-Object{ $_.KeyProtectorType -eq 'RecoveryPassword' }})
    if ($null -eq $encrypted) {
        write-host "-------------------------------------------------------------------------------" -ForegroundColor red
        write-host "Found no encrypted disks -- either you forgot to encrypt or you need to RESTART" -ForegroundColor red
        write-host "-------------------------------------------------------------------------------" -ForegroundColor red
    }
}


#TODO Use windows update helper script
function enlWindowsUpdates($dont_reboot){
    StopIfNotAnAdmin
    Write-Output ""
    Write-host "C:\Personal: setting ACLs" -foregroundcolor gray
    enlCreateAndSetAclForC_Personal
    Write-Output ""
    WaitForAnyKey "I will open chrome (and firefox if installed). LEAVE THEM OPEN in order to get updated.`nPress any key to continue"  -ForegroundColor cyan
    try {Start-Process firefox} catch {}
    Start-Process chrome
    Write-Output ""
    Write-host "Installing Windows updates if found..." -foregroundcolor gray
    if ($dont_reboot) {
        Get-WindowsUpdate -AutoSelectOnWebSites -AcceptAll -Install -verbose             | Out-File "c:\it\log\$(get-date -f yyyy-MM-dd_HH.mm)-WinUpdate.log" -force
    } else {
        Get-WindowsUpdate -AutoSelectOnWebSites -AcceptAll -Install -verbose -AutoReboot | Out-File "c:\it\log\$(get-date -f yyyy-MM-dd_HH.mm)-WinUpdate.log" -force
    }
    Write-Output ""
}



function enlInstallVendorUpdater() {
    $manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
    if ($manufacturer -match '\bLenovo\b') {
        write-host "Installing Lenovo Commercial Vantage using winget (if already installed I'll also install upgrades if any are available)"
        winget install -e --id 9NR5B8GVVM13 --source msstore --accept-source-agreements --accept-package-agreements --silent 
    } else {
        Write-Host-RED "Please install the updater for this manufacturer manualy.`n(I don't know how to install the updater of: $manufacturer)"
    }
}



function enlBrandTests($brand='') {
    StopIfNotAnAdmin
    StartTranscript "enlBrandTests"
    # you can call enlBrandTests "dell" (or "Lenovo") to skip autodetect
    if ($brand) {
        $manufacturer = (Get-CimInstance Win32_BIOS).Manufacturer
        $dell_match = $manufacturer -match "\bdell\b"
        $lenovo_match = $manufacturer -match "\blenovo\b"
        $test = (`
            ($brand -eq "dell" -and ($dell_match -and !$lenovo_match)) `
                -or `
            ($brand -eq "lenovo" -and (!$dell_match -and $lenovo_match))`
            )
        TestAndDisplayResult "Is BIOS reporting brand $($brand)?" `
            -Test $test `
            -FailureCmnt "(Get-CimInstance Win32_BIOS).Manufacturer = $manufacturer"
    } else {
        if (((Get-CimInstance Win32_BIOS).Manufacturer -match '\bLenovo\b') -or ((Get-CimInstance Win32_BIOS).Manufacturer -match '\bLenovo\b')) {
            $brand = "Lenovo"
            write-host -foregroundcolor darkgray "     This PC is a Lenovo"
        } elseif (((Get-CimInstance Win32_BIOS).Manufacturer -match '\bDell\b') -or ((Get-CimInstance Win32_BIOS).Manufacturer -match '\bDell\b')) {
            $brand = "Dell"
            write-host -foregroundcolor darkgray "     This PC is a Dell"
        } else {
            $brand = "Dell"
            write-host -foregroundcolor yellow "*** Not sure what is the Manufacturer -- GUESSING is Dell ***"
        }
    }

    # Check install SW for reference to brands
    $inst_sw_file = New-TemporaryFile
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
    | Out-String > $inst_sw_file
    $dell_lines = CountWordOccurances "dell" $inst_sw_file
    $lenovo_lines = CountWordOccurances "lenovo" $inst_sw_file
    Remove-Item $inst_sw_file

    $test = ("dell" -match $brand -and ($dell_lines -gt 0 -and $lenovo_lines -eq 0)) `
        -or `
    ("lenovo" -match $brand -and ($dell_lines -eq 0 -and $lenovo_lines -gt 0))
    TestAndDisplayResult "Is SW for $brand installed and is other brand's SW not?" `
        -Test $test `
        -FailureCmnt "Found $dell_lines references for Dell SW and $lenovo_lines for Lenovo"
    Stop-Transcript > $null
}


function enlDeleteOldEnlogicUsers {
    StopIfNotAnAdmin

    write-output "Cleaning up home dirs of IT stuf that has left enLogic"
    $LIST_OF_OLD_ENLOGIC_STUF | ForEach-Object{
        $enlogic_user = $_
        if (Test-Path -Path C:\Users\$enlogic_user -PathType Container) {
            write-output "Found C:\Users\$enlogic_user, deleting contents"
            SudoRmdir C:\Users\$enlogic_user
        }
    }
}


function enlScanForVirus {
    StopIfNotAnAdmin
    StartTranscript "enlScanForVirus"
    Write-Host   "`n`nDownloading Run-DismSfc.ps1" -ForegroundColor cyan
    $dir="C:\IT\bin";$f="Run-DismSfc.ps1";iwr -useb https://ndemou.github.io/scripts/$f -out $dir\$f
    Write-Host   "`nRunning Run-DismSfc.ps1" -ForegroundColor cyan
    & "c:\it\bin\Run-DismSfc.ps1"
    Write-Host   "Updating AV signatures" -ForegroundColor cyan
    Update-MpSignature
    Write-Host   "Scanning for virus (FULL system scan)" -ForegroundColor cyan
    Start-MpScan -ScanType FullScan
    Stop-Transcript > $null
}


function enlSdeleteC {
    StopIfNotAnAdmin
    write-output "Running sdelete"
    StartTranscript "enlSdeleteC"
    # securely erase any trace of deleted data from disk c:
    #---------------------------------------------------------
    C:
    Set-Location c:\it\bin
    if (!(Test-Path -Path sdelete64.exe)) {
        Invoke-WebRequest -Uri https://download.sysinternals.com/files/SDelete.zip -OutFile sdelete.zip
        Expand-Archive sdelete.zip -DestinationPath .
        # "accept" the sysinternals EULA -- https://hahndorf.eu/blog/post/2010/03/07/WorkAroundSysinternalsLicensePopups
        reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
        reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
    }
    Write-Host "Really clearing the bytes from disk using sdelete. This will take a LOT of time..."
    .\sdelete64.exe -nobanner -c C:
    Stop-Transcript > $null
}

function Add-WifiProfile {
<#
.SYNOPSIS
    Provisions a WPA/WPA2-Personal Wi-Fi after prompting for the pre-shared key.
    The password is never stored anywhere.

.DESCRIPTION
    Recreates this "Basic" Wi-Fi template:
        Connect automatically when in range ........ Yes
        Connect to more preferred network .......... No
        Connect even when not broadcasting SSID .... No
        Wireless security type ..................... WPA/WPA2-Personal (WPA2PSK + AES)
        Metered connection limit ................... Unrestricted (Windows default)
        FIPS / proxy ............................... off / none (defaults)
    The key is held as a SecureString and passed straight to WlanSetProfile in memory;
    Windows then stores it DPAPI-encrypted. The network need not be in range.
    Must be run elevated (all-user profile). PowerShell 5.1 compatible.

.PARAMETER Ssid
    The Wi-Fi network name. 

.EXAMPLE
    Add-WifiProfile "SomeSSID"
#>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string] $Ssid
    )


    # -------------------------------------------------------------------------------------
    #  Thin wrapper over the native Wi-Fi API (wlanapi.dll). Unlike `netsh`, WlanSetProfile
    #  takes the profile XML as an in-memory string, so the password never hits the disk.
    # -------------------------------------------------------------------------------------
    if (-not ('Native.WlanProfileInstaller' -as [type])) {
        Add-Type -Namespace Native -Name WlanProfileInstaller -MemberDefinition @'
    [DllImport("wlanapi.dll")]
    static extern uint WlanOpenHandle(uint v, IntPtr r, out uint negotiated, out IntPtr handle);
    [DllImport("wlanapi.dll")]
    static extern uint WlanCloseHandle(IntPtr handle, IntPtr r);
    [DllImport("wlanapi.dll")]
    static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr r, out IntPtr list);
    [DllImport("wlanapi.dll")]
    static extern void WlanFreeMemory(IntPtr p);
    [DllImport("wlanapi.dll", CharSet = CharSet.Unicode)]
    static extern uint WlanSetProfile(IntPtr handle, ref Guid iface, uint flags,
        string xml, string security, bool overwrite, IntPtr r, out uint reason);

    // Returns how many Wi-Fi interfaces exist (0 on a desktop / Ethernet-only box).
    // Lets the caller bail out cleanly *before* prompting for a password.
    public static int GetInterfaceCount()
    {
        IntPtr handle; uint negotiated;
        uint res = WlanOpenHandle(2, IntPtr.Zero, out negotiated, out handle);
        if (res != 0) throw new Exception("WlanOpenHandle failed (" + res +
            "). Is the WLAN AutoConfig (Wlansvc) service running?");
        IntPtr list = IntPtr.Zero;
        try
        {
            res = WlanEnumInterfaces(handle, IntPtr.Zero, out list);
            if (res != 0) throw new Exception("WlanEnumInterfaces failed: " + res);
            return Marshal.ReadInt32(list, 0);   // first DWORD of the list = item count
        }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    // Installs an all-user Wi-Fi profile from an in-memory XML string. Requires elevation.
    public static void Install(string profileXml)
    {
        IntPtr handle; uint negotiated;
        uint res = WlanOpenHandle(2, IntPtr.Zero, out negotiated, out handle);
        if (res != 0) throw new Exception("WlanOpenHandle failed (" + res +
            "). Is the WLAN AutoConfig service running?");

        IntPtr list = IntPtr.Zero;
        try
        {
            res = WlanEnumInterfaces(handle, IntPtr.Zero, out list);
            if (res != 0) throw new Exception("WlanEnumInterfaces failed: " + res);

            // WLAN_INTERFACE_INFO_LIST = dwNumberOfItems(4) + dwIndex(4) + array,
            // so the first interface's GUID (its first field) sits at byte offset 8.
            if (Marshal.ReadInt32(list, 0) < 1) throw new Exception("No Wi-Fi adapter found.");
            Guid iface = (Guid)Marshal.PtrToStructure(
                new IntPtr(list.ToInt64() + 8), typeof(Guid));

            uint reason;
            // flags = 0 -> all-user profile; overwrite = true so re-running updates it.
            res = WlanSetProfile(handle, ref iface, 0, profileXml, null, true,
                                 IntPtr.Zero, out reason);
            if (res != 0)
                throw new Exception("WlanSetProfile failed: " + res + " (reason " + reason + ")");
        }
        finally
        {
            if (list != IntPtr.Zero) WlanFreeMemory(list);
            WlanCloseHandle(handle, IntPtr.Zero);
        }
    }
'@
    }

    # All-user profile installation requires admin; stop cleanly if we're not elevated.
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "Run this from an elevated PowerShell session (all-user Wi-Fi profile needs admin). Aborted."
        return
    }

    # Pre-flight: confirm a Wi-Fi adapter exists BEFORE asking for a password, so a desktop
    # or Ethernet-only box exits gracefully instead of prompting and then failing.
    try {
        $wifiCount = [Native.WlanProfileInstaller]::GetInterfaceCount()
    }
    catch {
        Write-Warning "Could not query Wi-Fi: $($_.Exception.Message)"
        return
    }
    if ($wifiCount -lt 1) {
        Write-Warning "No Wi-Fi adapter found - profile not installed. (Normal on a desktop / Ethernet-only PC.)"
        return
    }

    # Prompt for the key. -AsSecureString keeps it out of the console and command history.
    $secure = Read-Host "Pre-shared key for '$Ssid'" -AsSecureString

    # --- Briefly decrypt the SecureString into a usable string ---------------------------
    # The API needs the key as text. SecureStringToBSTR copies it into unmanaged memory;
    # PtrToStringBSTR reads it back. ZeroFreeBSTR in 'finally' wipes that unmanaged copy.
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

        # WPA2-PSK passphrases must be 8-63 characters; reject bad input before the API call.
        if ($plain.Length -lt 8 -or $plain.Length -gt 63) {
            Write-Warning "Pre-shared key must be 8-63 characters (got $($plain.Length)). Aborted."
            return
        }

        # XML-escape both values so an '&', '<', etc. in the SSID or key can't break the XML.
        $ssidXml = [System.Security.SecurityElement]::Escape($Ssid)
        $keyXml  = [System.Security.SecurityElement]::Escape($plain)

        # Profile XML. Each element maps to one toggle on the Intune screen (see comments).
        $xml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$ssidXml</name>
  <SSIDConfig>
    <SSID>
      <name>$ssidXml</name>
    </SSID>
    <!-- "Connect even when not broadcasting its SSID" = No -> false -->
    <nonBroadcast>false</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <!-- "Connect automatically when in range" = Yes -> auto (use 'manual' for No) -->
  <connectionMode>auto</connectionMode>
  <!-- "Connect to a more preferred network if available" = No -> false.
       Only takes effect while connectionMode is 'auto'. -->
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <!-- "WPA/WPA2-Personal": WPA2PSK + AES is the correct, backward-compatible mapping.
             Windows profiles have no combined "WPA+WPA2" token. -->
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <!-- protected=false = "key below is plaintext"; Windows re-encrypts it with DPAPI
             the moment it stores the profile. -->
        <protected>false</protected>
        <keyMaterial>$keyXml</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"@
        # Metered=Unrestricted, FIPS=No, Proxy=None are Windows defaults -> no extra XML.

        # Hand the XML straight to the API - nothing is written to disk.
        try {
            [Native.WlanProfileInstaller]::Install($xml)
            Write-Host "Installed Wi-Fi profile '$Ssid'." -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not install profile '$Ssid': $($_.Exception.Message)"
        }
    }
    finally {
        # Wipe the unmanaged plaintext copy and release the SecureString.
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        if ($secure) { $secure.Dispose() }
        $plain = $null
    }
}

function Get-HWInfo {
# Returns basic HW info
    $Computer = Get-CimInstance Win32_ComputerSystem
    $CPU = Get-CimInstance Win32_Processor | Select-Object -First 1
    $BIOS = Get-CimInstance Win32_BIOS
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"

    [PSCustomObject]@{
        CPU          = $CPU.Name
        DiskCSizeGB  = [math]::Round($Disk.Size / 1e9, 0)
        RAMGB        = [math]::Ceiling($Computer.TotalPhysicalMemory / 1GB)
        Model        = $Computer.Model
        Vendor       = $Computer.Manufacturer
        SerialNumber = $BIOS.SerialNumber
    }
}

function Get-RecentUsers {
# Returns a comma separated list of the usernames of the most recently logged in users
    param (
        [int]$RecentUserCount = 4
    )
    
    $Users = Get-CimInstance Win32_UserProfile |
        Where-Object {
            -not $_.Special -and
            $_.LocalPath -notmatch '\\(Default|Public|defaultuser0)$'
        } |
        Sort-Object LastUseTime -Descending |
        Select-Object -First $RecentUserCount

    $RecentUsers = ($Users | ForEach-Object {
        Split-Path $_.LocalPath -Leaf
    }) -join ", "
    
    $RecentUsers
}

function Get-HwAndUsersDescription {
# Returns a line of text whith the basic HW and Owner facts about a PC:
#   HW: LENOVO; 20T8000SGM; SN PF12345; AMD Ryzen 7 4700U; 953GB; 23GB; Recent Users: NickDemou, anastasis, CodexSandboxOffline
    $pcInfo = Get-HWInfo 
    $RecentUsers = Get-RecentUsers
    $hwDescription = "HW: $($pcInfo.Vendor); $($pcInfo.Model); SN $($pcInfo.SerialNumber); $($pcInfo.CPU -replace '\(R\)' -replace '\(TM\)' -replace ' with [a-z0-9 ]+'); $($pcInfo.DiskCSizeGB)GB; $($pcInfo.RAMGB)GB; Recent Users: $RecentUsers"
    $hwDescription
}

function Test-DomainControllerAccess {
<#
.SYNOPSIS
    Quickly checks TCP connectivity to an automatically discovered domain controller.
.DESCRIPTION
    Detects the computer's joined AD domain, discovers one controller through DNS,
    and tests TCP port 389 with a 500 ms connection timeout. Domain detection and
    DNS discovery may take additional time. Does not verify authentication or trust.
.OUTPUTS
    PSCustomObject with Domain, DomainController, Port, TcpTestSucceeded, and Detail.
    TcpTestSucceeded is True when the TCP connection succeeds; otherwise False,
    with the timeout or error explained in Detail. Discovery errors terminate the test.
.EXAMPLE
    Test-DomainControllerAccess
#>
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if (-not $computer.PartOfDomain) {
        throw 'This computer is not joined to an Active Directory domain.'
    }

    $domain = $computer.Domain
    $dcName = Resolve-DnsName "_ldap._tcp.dc._msdcs.$domain" `
        -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop |
        Where-Object Type -eq 'SRV' |
        Sort-Object Priority |
        Select-Object -First 1 -ExpandProperty NameTarget

    if ([string]::IsNullOrWhiteSpace($dcName)) {
        throw "No domain controller was found in DNS for $domain."
    }
    $dcName = $dcName.TrimEnd('.')

    $client = New-Object System.Net.Sockets.TcpClient
    $connected = $false
    try {
        $connected = $client.ConnectAsync($dcName, 389).Wait(500)
        $detail = if ($connected) {
            'TCP connection succeeded.'
        } else {
            'No connection completed within 500 ms.'
        }
    }
    catch {
        $detail = $_.Exception.GetBaseException().Message
    }
    finally {
        $client.Close()
    }

    [pscustomobject]@{
        Domain           = $domain
        DomainController = $dcName
        Port             = 389
        TcpTestSucceeded = $connected
        Detail           = $detail
    }
}