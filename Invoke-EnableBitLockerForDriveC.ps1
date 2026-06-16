#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enable or maintain BitLocker on operating-system volume C: and
    escrow its recovery key to AD DS and Microsoft Entra ID.

.DESCRIPTION
    Run this script locally and elevated on a Windows 11 laptop to
    bring drive C: into a protected BitLocker state. It targets C:
    only and is safe to run repeatedly.

    Elevation is required. A Domain Admin account is not required and
    is not recommended; a local administrator or Windows LAPS
    administrator account is sufficient.

    The script ensures a recovery-password protector exists, submits
    every recovery-password protector to on-premises AD DS and to
    Microsoft Entra ID, then enables or maintains encryption on C:
    using an existing or newly added startup protector.

    The run succeeds only when all of the following hold: C: is
    encrypted, encrypting, or validly pending the startup hardware
    test; a recovery-password protector exists; at least one
    recovery-password submission was accepted by AD DS or by Microsoft
    Entra ID; and the final local BitLocker state passes validation.
    If neither directory accepts a recovery key, the script throws.

    The script may create a recovery protector, add a TPM startup
    protector, start encryption, and resume encryption or protection.
    Existing protectors are always retained and never weakened. A
    restart may be required before encryption begins.

    Successful completion of a backup command is treated as an
    accepted submission. The script does not independently read the
    recovery key back from AD DS or Microsoft Entra ID; read-back
    verification needs separate directory permissions and tooling.

    The script performs no destructive cleanup. A terminating error
    may leave partial external state in place, such as a new recovery
    protector, a recovery record already submitted to one directory,
    encryption already started, or protection already resumed. That
    state is intentionally left untouched.

.OUTPUTS
    On success, a single PSCustomObject is returned with fields:

        Succeeded                   Always True on success.
        MountPoint                  The target volume, C:.
        VolumeStatus                Final local conversion state.
        ProtectionStatus            Final local protection state.
        EncryptionPercentage        Final local percentage.
        EncryptionMethod            Final local encryption method.
        RecoveryProtectorIds        Recovery-password protector IDs.
        EscrowedToActiveDirectory   True if an AD DS submission
                                    succeeded during this run.
        EscrowedToMicrosoftEntraId  True if an Entra submission
                                    succeeded during this run.
        RebootRequired              True only when a restart is needed
                                    for the requested hardware test.

    The 48-digit recovery password is never printed or returned.

.PARAMETER EncryptionMethod
    Requested method: Aes128, Aes256, XtsAes128, or XtsAes256.
    Defaults to XtsAes256. If an operating-system drive encryption
    policy requires a different method, the policy method is used and
    reported instead of the requested method.

.PARAMETER UsedSpaceOnly
    Encrypt only used space during the initial conversion. Free space
    that may hold remnants of deleted data is not covered until it is
    reused. When omitted, full-volume encryption is requested.

.PARAMETER SkipHardwareTest
    Skip the BitLocker startup hardware test so encryption begins
    immediately, bypassing preboot validation. When omitted, the
    hardware test is requested and C: may stay decrypted until the
    next restart.

.EXAMPLE
    $r = .\Invoke-EnableBitLockerForDriveC.ps1
    if ($r.RebootRequired) { Restart-Computer }

    Configure C:, then restart only when a restart is required for the
    pending hardware test.
#>

[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')]
    [string]$EncryptionMethod = 'XtsAes256',

    [switch]$UsedSpaceOnly,

    [switch]$SkipHardwareTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -DisableNameChecking suppresses only the module's unapproved-verb
# warning (for example BackupToAAD-BitLockerKeyProtector); it does not
# suppress unrelated warnings.
Import-Module BitLocker -DisableNameChecking -ErrorAction Stop

# --------------------------------------------------------------------
# Presentation helpers (Write-Host only; never the success stream)
# --------------------------------------------------------------------

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('  ' + $Title) -ForegroundColor White
    Write-Host ('  ' + ('-' * 64)) -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Field {
    param(
        [string]$Label,
        [string]$Value
    )
    $padded = ($Label + ':').PadRight(26)
    Write-Host ('  ' + $padded) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor Gray
}

function Write-Tag {
    param(
        [ValidateSet('info', 'run', 'ok', 'next')]
        [string]$Level,
        [string]$Message
    )
    $tag = ''
    $color = 'Gray'
    switch ($Level) {
        'info' { $tag = '[info]'; $color = 'DarkCyan' }
        'run'  { $tag = '[run]';  $color = 'Cyan' }
        'ok'   { $tag = '[ok]';   $color = 'Green' }
        'next' { $tag = '[next]'; $color = 'Yellow' }
    }
    Write-Host ('  ' + $tag + ' ') -ForegroundColor $color -NoNewline
    Write-Host $Message -ForegroundColor Gray
}

function Write-SuccessPanel {
    param([string]$Message)
    Write-Host ''
    Write-Host ('  ' + ('━' * 64)) -ForegroundColor DarkGray
    Write-Host '  ' -NoNewline
    Write-Host 'SUCCESS  ' -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor White
    Write-Host ('  ' + ('━' * 64)) -ForegroundColor DarkGray
    Write-Host ''
}

# --------------------------------------------------------------------
# Diagnostic / state helpers
# --------------------------------------------------------------------

function Get-ExceptionDescription {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    if ($null -eq $ErrorRecord) {
        return 'Unknown error (no error record).'
    }
    $message = 'Unknown error.'
    if ($null -ne $ErrorRecord.Exception) {
        $message = $ErrorRecord.Exception.Message
    }
    $id = $ErrorRecord.FullyQualifiedErrorId
    if ([string]::IsNullOrWhiteSpace($id)) {
        return $message
    }
    return ($message + ' [' + $id + ']')
}

function Get-OsBitLockerVolume {
    param([string]$MountPoint = 'C:')
    $volume = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
    return $volume
}

function Get-RecoveryProtectors {
    param($Volume)
    return @($Volume.KeyProtector |
        Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
}

function Get-BootProtectors {
    param($Volume)
    $bootTypes = @(
        'Tpm', 'TpmPin', 'TpmStartupKey', 'TpmPinStartupKey',
        'ExternalKey', 'StartupKey'
    )
    return @($Volume.KeyProtector |
        Where-Object { $bootTypes -contains $_.KeyProtectorType })
}

function Get-TpmReadiness {
    $info = [pscustomobject]@{
        Determined = $false
        Present    = $false
        Ready      = $false
        LockedOut  = $false
    }
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $info.Determined = $true
        $info.Present = [bool]$tpm.TpmPresent
        $info.Ready = [bool]$tpm.TpmReady
        if ($tpm.PSObject.Properties.Name -contains 'LockedOut') {
            $info.LockedOut = [bool]$tpm.LockedOut
        }
    }
    catch {
        Write-Warning ('Unable to query TPM state: ' +
            (Get-ExceptionDescription $_))
    }
    return $info
}

function Get-JoinState {
    $state = [pscustomobject]@{
        DomainJoined    = 'Unknown'
        DomainName      = ''
        AzureAdJoined   = 'Unknown'
        WorkplaceJoined = 'Unknown'
        EntraTenant     = ''
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            $state.DomainJoined = 'YES'
            $state.DomainName = [string]$cs.Domain
        }
        else {
            $state.DomainJoined = 'NO'
        }
    }
    catch {
        Write-Warning ('Could not determine AD domain join state: ' +
            (Get-ExceptionDescription $_))
    }

    try {
        $out = & dsregcmd.exe /status 2>$null
        if ($null -ne $out) {
            foreach ($line in $out) {
                if ($line -match 'AzureAdJoined\s*:\s*(\S+)') {
                    $state.AzureAdJoined = $Matches[1].ToUpper()
                }
                elseif ($line -match 'WorkplaceJoined\s*:\s*(\S+)') {
                    $state.WorkplaceJoined = $Matches[1].ToUpper()
                }
                elseif ($line -match 'TenantName\s*:\s*(.+)') {
                    $state.EntraTenant = $Matches[1].Trim()
                }
                elseif ($state.DomainJoined -eq 'Unknown' -and
                    $line -match 'DomainJoined\s*:\s*(\S+)') {
                    $state.DomainJoined = $Matches[1].ToUpper()
                }
            }
        }
    }
    catch {
        Write-Warning ('Could not determine Microsoft Entra join state: ' +
            (Get-ExceptionDescription $_))
    }

    return $state
}

function Get-SecureBootState {
    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($enabled) {
            return 'Enabled'
        }
        return 'Disabled'
    }
    catch {
        # Thrown on legacy BIOS or when the platform cannot report it.
        return 'Unknown'
    }
}

function Get-PolicyEncryptionMethod {
    # Reads the OS-drive policy value EncryptionMethodWithXtsOs under
    # HKLM\SOFTWARE\Policies\Microsoft\FVE and maps it to the parameter
    # set used by Enable-BitLocker. Returns $null when no policy applies.
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    if (-not (Test-Path -Path $path)) {
        return $null
    }
    try {
        $item = Get-ItemProperty -Path $path -ErrorAction Stop
    }
    catch {
        return $null
    }
    if ($item.PSObject.Properties.Name -notcontains 'EncryptionMethodWithXtsOs') {
        return $null
    }
    $value = $item.EncryptionMethodWithXtsOs
    if ($null -eq $value) {
        return $null
    }
    switch ([int]$value) {
        3 { return 'Aes128' }
        4 { return 'Aes256' }
        6 { return 'XtsAes128' }
        7 { return 'XtsAes256' }
        default { return $null }
    }
}

function Invoke-RecoveryEscrow {
    # Submits each recovery-password protector to AD DS and to Microsoft
    # Entra ID. A successful backup cmdlet result is treated as an
    # accepted submission. Read-back verification is intentionally NOT
    # performed; that requires separate directory permissions/tooling.
    param(
        [string]$MountPoint,
        [string[]]$ProtectorIds
    )

    $result = [pscustomobject]@{
        AdSuccess  = $false
        AadSuccess = $false
        Failures   = @()
    }

    $adCmd = Get-Command -Name 'Backup-BitLockerKeyProtector' `
        -ErrorAction SilentlyContinue
    $aadCmd = Get-Command -Name 'BackupToAAD-BitLockerKeyProtector' `
        -ErrorAction SilentlyContinue

    if ($null -eq $adCmd) {
        Write-Warning ('Backup-BitLockerKeyProtector is unavailable; ' +
            'cannot escrow to AD DS.')
        $result.Failures += 'AD DS: backup command unavailable.'
    }
    if ($null -eq $aadCmd) {
        Write-Warning ('BackupToAAD-BitLockerKeyProtector is unavailable; ' +
            'cannot escrow to Microsoft Entra ID.')
        $result.Failures += 'Entra ID: backup command unavailable.'
    }

    foreach ($id in $ProtectorIds) {
        if ($null -ne $adCmd) {
            Write-Tag run ('Backing up protector ' + $id + ' to AD DS')
            try {
                $null = Backup-BitLockerKeyProtector -MountPoint $MountPoint `
                    -KeyProtectorId $id -ErrorAction Stop
                $result.AdSuccess = $true
                Write-Tag ok 'Recovery protector submitted to AD DS'
            }
            catch {
                $detail = Get-ExceptionDescription $_
                Write-Warning ('AD DS backup failed for ' + $id + ': ' + $detail)
                $result.Failures += ('AD DS (' + $id + '): ' + $detail)
            }
        }

        if ($null -ne $aadCmd) {
            Write-Tag run ('Backing up protector ' + $id +
                ' to Microsoft Entra ID')
            try {
                $null = BackupToAAD-BitLockerKeyProtector -MountPoint $MountPoint `
                    -KeyProtectorId $id -ErrorAction Stop
                $result.AadSuccess = $true
                Write-Tag ok 'Recovery protector submitted to Microsoft Entra ID'
            }
            catch {
                $detail = Get-ExceptionDescription $_
                Write-Warning ('Entra ID backup failed for ' + $id + ': ' +
                    $detail)
                $result.Failures += ('Entra ID (' + $id + '): ' + $detail)
            }
        }
    }

    return $result
}

function Start-OsEncryption {
    param(
        [string]$MountPoint,
        [string]$EncryptionMethod,
        [bool]$UsedSpaceOnly,
        [bool]$SkipHardwareTest,
        $BootProtectors
    )

    $splat = @{
        MountPoint       = $MountPoint
        EncryptionMethod = $EncryptionMethod
        ErrorAction      = 'Stop'
    }
    if ($UsedSpaceOnly) {
        $splat['UsedSpaceOnly'] = $true
        Write-Warning ('UsedSpaceOnly requested: free space that may contain ' +
            'remnants of previously deleted data is NOT encrypted during the ' +
            'initial conversion.')
    }
    if ($SkipHardwareTest) {
        $splat['SkipHardwareTest'] = $true
        Write-Warning ('SkipHardwareTest requested: BitLocker preboot ' +
            'validation is bypassed and encryption begins immediately.')
    }

    $tpmFamily = @($BootProtectors | Where-Object {
            @('Tpm', 'TpmPin', 'TpmStartupKey', 'TpmPinStartupKey') `
                -contains $_.KeyProtectorType
        })
    $external = @($BootProtectors | Where-Object {
            @('ExternalKey', 'StartupKey') -contains $_.KeyProtectorType
        })

    if ($tpmFamily.Count -eq 0 -and $external.Count -eq 0) {
        Write-Tag run 'No boot protector present; validating TPM for startup'
        $tpm = Get-TpmReadiness
        if (-not $tpm.Determined) {
            throw ('Cannot enable BitLocker: TPM state could not be ' +
                'determined and no existing boot protector is present.')
        }
        if (-not $tpm.Present) {
            throw ('Cannot enable BitLocker: no TPM is present and no ' +
                'existing boot protector is available for unattended startup.')
        }
        if ($tpm.LockedOut) {
            Write-Warning ('The TPM reports a lockout condition; BitLocker ' +
                'enablement may fail until the lockout clears.')
        }
        if (-not $tpm.Ready) {
            throw ('Cannot enable BitLocker: the TPM is present but not ' +
                'ready. Initialize the TPM through the TPM management console ' +
                'first. This script will not clear, reset, or take ownership ' +
                'of the TPM automatically.')
        }
        $splat['TpmProtector'] = $true
        Write-Tag run 'Enabling BitLocker with a TPM startup protector'
        $null = Enable-BitLocker @splat
        Write-Tag ok 'BitLocker enablement requested'
    }
    else {
        # A decrypted volume that already carries a startup protector is
        # not expected (decryption removes protectors). Rather than
        # weaken the configuration (for example by adding a TPM-only
        # protector beside a TPM+PIN one) or duplicate it, refuse to
        # start encryption automatically and tell the operator.
        Write-Tag info 'Existing boot protector detected on a decrypted volume'
        throw ('C: is fully decrypted but already carries a startup ' +
            '(boot) protector. To avoid weakening or duplicating the ' +
            'existing startup configuration, this script will not start ' +
            'encryption automatically in this state. Start encryption ' +
            'manually so the existing protector is reused (for example: ' +
            'manage-bde -on C:), then re-run this script to confirm ' +
            'recovery-key escrow and protection.')
    }
}

function Test-FinalState {
    param(
        $Volume,
        [bool]$ActivationRequested,
        [bool]$SkipHwTest
    )
    switch ($Volume.VolumeStatus) {
        'FullyEncrypted' {
            if ($Volume.ProtectionStatus -ne 'On') {
                throw ('Final verification failed: C: is fully encrypted but ' +
                    'protection is ' + $Volume.ProtectionStatus +
                    ' (expected On).')
            }
        }
        'EncryptionInProgress' {
            # Acceptable; do not wait for completion.
        }
        'FullyDecrypted' {
            if (-not ($ActivationRequested -and -not $SkipHwTest)) {
                throw ('Final verification failed: C: is fully decrypted and ' +
                    'no valid pending hardware test explains it.')
            }
        }
        default {
            throw ('Final verification failed: unexpected BitLocker volume ' +
                'status ' + $Volume.VolumeStatus + '.')
        }
    }
}

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------

try {
    Write-Section 'Checking administrative privileges'
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = $principal.IsInRole($adminRole)
    Write-Field 'Identity' $identity.Name
    Write-Field 'Elevated' ($isAdmin.ToString())
    if (-not $isAdmin) {
        throw 'This script must run elevated (Run as Administrator).'
    }
    Write-Tag info 'A Domain Admin account is neither required nor recommended'

    Write-Section 'Join-state assessment'
    $join = Get-JoinState
    Write-Field 'AD domain joined' $join.DomainJoined
    if (-not [string]::IsNullOrWhiteSpace($join.DomainName)) {
        Write-Field 'Domain' $join.DomainName
    }
    Write-Field 'Entra ID joined' $join.AzureAdJoined
    Write-Field 'Workplace joined' $join.WorkplaceJoined
    if (-not [string]::IsNullOrWhiteSpace($join.EntraTenant)) {
        Write-Field 'Entra tenant' $join.EntraTenant
    }
    if ($join.DomainJoined -eq 'Unknown') {
        Write-Warning ('AD domain join state could not be determined; AD DS ' +
            'escrow will still be attempted.')
    }
    if ($join.AzureAdJoined -eq 'Unknown') {
        Write-Warning ('Microsoft Entra join state could not be determined; ' +
            'Entra escrow will still be attempted.')
    }
    if ($join.AzureAdJoined -ne 'YES' -and $join.WorkplaceJoined -eq 'YES') {
        Write-Warning ('A work or school account appears connected, but this ' +
            'device is not Entra (Azure AD) joined; Entra escrow may not ' +
            'be available.')
    }

    Write-Section 'Secure Boot status'
    $secureBoot = Get-SecureBootState
    Write-Field 'Secure Boot' $secureBoot
    if ($secureBoot -eq 'Disabled') {
        Write-Warning ('Secure Boot is disabled. BitLocker can still be ' +
            'enabled, but enabling Secure Boot is recommended for stronger ' +
            'preboot integrity.')
    }
    if ($secureBoot -eq 'Unknown') {
        Write-Warning 'Secure Boot state could not be determined; continuing.'
    }

    Write-Section 'BitLocker volume state'
    $vol = Get-OsBitLockerVolume -MountPoint 'C:'
    if ($vol.VolumeType -ne 'OperatingSystem') {
        throw ('C: is not reported as the operating-system volume ' +
            '(VolumeType = ' + $vol.VolumeType + '); aborting.')
    }
    if ($vol.LockStatus -ne 'Unlocked') {
        throw ('C: is not unlocked (LockStatus = ' + $vol.LockStatus +
            '); aborting.')
    }
    Write-Field 'Mount point' ([string]$vol.MountPoint)
    Write-Field 'Volume type' ([string]$vol.VolumeType)
    Write-Field 'Volume status' ([string]$vol.VolumeStatus)
    Write-Field 'Protection' ([string]$vol.ProtectionStatus)
    Write-Field 'Lock status' ([string]$vol.LockStatus)
    Write-Field 'Encryption %' ([string]$vol.EncryptionPercentage)
    Write-Field 'Method (current)' ([string]$vol.EncryptionMethod)

    if ($vol.VolumeStatus -eq 'DecryptionInProgress') {
        throw ('C: decryption is currently in progress. This script will not ' +
            'automatically reverse an active decryption. Let decryption ' +
            'complete (or stop it deliberately), then re-run this script.')
    }
    if ($vol.VolumeStatus -eq 'DecryptionPaused') {
        throw ('C: decryption is paused. This script will not automatically ' +
            'reverse a paused decryption. Resolve the decryption state ' +
            'deliberately, then re-run this script.')
    }

    # Resolve the effective encryption method against policy.
    $effectiveMethod = $EncryptionMethod
    $policyMethod = Get-PolicyEncryptionMethod
    if ($null -ne $policyMethod -and $policyMethod -ne $EncryptionMethod) {
        Write-Warning ('An OS-drive encryption policy requires ' +
            $policyMethod + '; using it instead of the requested ' +
            $EncryptionMethod + '.')
        $effectiveMethod = $policyMethod
    }

    Write-Section 'Recovery-password protector'
    $recovery = @(Get-RecoveryProtectors $vol)
    if ($recovery.Count -eq 0) {
        Write-Tag run 'No recovery-password protector found; creating one'
        $null = Add-BitLockerKeyProtector -MountPoint 'C:' `
            -RecoveryPasswordProtector -ErrorAction Stop
        $vol = Get-OsBitLockerVolume -MountPoint 'C:'
        $recovery = @(Get-RecoveryProtectors $vol)
        Write-Tag ok 'Recovery-password protector created'
    }
    else {
        Write-Tag info ('Existing recovery-password protector(s): ' +
            $recovery.Count)
        if ($recovery.Count -gt 1) {
            Write-Warning ('Multiple recovery-password protectors exist; all ' +
                'are retained and submitted to both directories.')
        }
    }
    $protectorIds = @($recovery | ForEach-Object { $_.KeyProtectorId })
    foreach ($protectorId in $protectorIds) {
        Write-Field 'Protector ID' ([string]$protectorId)
    }

    Write-Section 'Recovery-key escrow'
    $escrow = Invoke-RecoveryEscrow -MountPoint 'C:' -ProtectorIds $protectorIds
    Write-Host ''
    $adText = 'failed'
    if ($escrow.AdSuccess) { $adText = 'succeeded' }
    $aadText = 'failed'
    if ($escrow.AadSuccess) { $aadText = 'succeeded' }
    Write-Field 'AD DS escrow' $adText
    Write-Field 'Entra ID escrow' $aadText

    if (-not $escrow.AdSuccess -and -not $escrow.AadSuccess) {
        $detail = ($escrow.Failures -join '; ')
        throw ('Recovery-key escrow failed for BOTH AD DS and Microsoft ' +
            'Entra ID. No recovery key was accepted by either directory and ' +
            'encryption was not started. Details: ' + $detail)
    }
    if ($escrow.AdSuccess -and -not $escrow.AadSuccess) {
        Write-Warning ('Recovery key was accepted by AD DS but NOT by ' +
            'Microsoft Entra ID.')
    }
    if ($escrow.AadSuccess -and -not $escrow.AdSuccess) {
        Write-Warning ('Recovery key was accepted by Microsoft Entra ID but ' +
            'NOT by AD DS.')
    }

    Write-Section 'Encryption and protection'
    Write-Field 'Requested method' $EncryptionMethod
    Write-Field 'Effective method' $effectiveMethod
    $activationRequested = $false

    switch ($vol.VolumeStatus) {
        'FullyDecrypted' {
            Write-Warning ('C: is fully decrypted. Confirm that no ' +
                'third-party full-disk encryption product is active before ' +
                'proceeding; this script cannot detect every such product.')
            $boot = @(Get-BootProtectors $vol)
            Start-OsEncryption -MountPoint 'C:' `
                -EncryptionMethod $effectiveMethod `
                -UsedSpaceOnly ([bool]$UsedSpaceOnly) `
                -SkipHardwareTest ([bool]$SkipHardwareTest) `
                -BootProtectors $boot
            $activationRequested = $true
        }
        'EncryptionInProgress' {
            Write-Tag info 'Encryption already in progress; not restarting it'
        }
        'EncryptionPaused' {
            Write-Tag run 'Encryption is paused; resuming'
            $null = Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop
            Write-Tag ok 'Resume requested'
        }
        'FullyEncrypted' {
            if ($vol.ProtectionStatus -ne 'On') {
                Write-Tag run ('Volume encrypted but protection is Off; ' +
                    'resuming protection')
                $null = Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop
                Write-Tag ok 'Protection resume requested'
            }
            else {
                Write-Tag info 'Volume already fully encrypted and protected'
            }
        }
        default {
            throw ('Unexpected BitLocker volume status ' + $vol.VolumeStatus +
                ' for C:; no action taken.')
        }
    }

    Write-Section 'Final verification'
    $final = Get-OsBitLockerVolume -MountPoint 'C:'
    $finalRecovery = @(Get-RecoveryProtectors $final)
    if ($finalRecovery.Count -eq 0) {
        throw ('Final verification failed: no recovery-password protector is ' +
            'present on C:.')
    }

    $rebootRequired = $false
    if ($activationRequested -and -not $SkipHardwareTest -and
        $final.VolumeStatus -eq 'FullyDecrypted') {
        $rebootRequired = $true
    }

    Test-FinalState -Volume $final -ActivationRequested $activationRequested `
        -SkipHwTest ([bool]$SkipHardwareTest)

    Write-Field 'Volume status' ([string]$final.VolumeStatus)
    Write-Field 'Protection' ([string]$final.ProtectionStatus)
    Write-Field 'Encryption %' ([string]$final.EncryptionPercentage)
    Write-Field 'Method' ([string]$final.EncryptionMethod)
    Write-Field 'Reboot required' ($rebootRequired.ToString())

    $result = [pscustomobject]@{
        Succeeded                  = $true
        MountPoint                 = 'C:'
        VolumeStatus               = [string]$final.VolumeStatus
        ProtectionStatus           = [string]$final.ProtectionStatus
        EncryptionPercentage       = $final.EncryptionPercentage
        EncryptionMethod           = [string]$final.EncryptionMethod
        RecoveryProtectorIds       = @($finalRecovery |
            ForEach-Object { [string]$_.KeyProtectorId })
        EscrowedToActiveDirectory  = [bool]$escrow.AdSuccess
        EscrowedToMicrosoftEntraId = [bool]$escrow.AadSuccess
        RebootRequired             = $rebootRequired
    }

    Write-SuccessPanel 'BitLocker configuration completed'
    if ($rebootRequired) {
        Write-Tag next ('Restart the laptop to run the BitLocker hardware ' +
            'test; encryption begins only after a successful test.')
        Write-Host ''
    }

    return $result
}
catch {
    $caught = $_
    Write-Warning ('BITLOCKER CONFIGURATION FAILED: ' +
        (Get-ExceptionDescription $caught))
    # No destructive rollback is attempted. Partial external state (for
    # example a new recovery protector, a record already escrowed to one
    # directory, encryption already started, or protection already
    # resumed) is intentionally left in place. Re-running the script is
    # safe and will reconcile the remaining steps.
    throw $caught
}