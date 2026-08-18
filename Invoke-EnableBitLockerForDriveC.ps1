#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Enables or maintains BitLocker protection for C: and submits each
recovery-password protector to AD DS and Microsoft Entra ID.

.DESCRIPTION
Use this script on a Windows 11 computer when the operating-system
volume must be BitLocker protected and its recovery password must be
stored in at least one of the computer's configured directories.

The script requires an elevated Windows PowerShell 5.1 session. A
Domain Admin account is neither required nor recommended. The script
targets C: only. It attempts recovery-key submission to each eligible
directory (AD DS, Microsoft Entra ID, or both) and treats the operation
as successful only when at least one submission succeeds and the local
BitLocker state passes its final checks.

The script may create a recovery-password protector, add a TPM
protector when no supported boot protector exists, start or resume
encryption, and resume suspended BitLocker protection. Existing
recovery and boot protectors are retained.

By default, a BitLocker hardware test is requested. Encryption may
therefore remain pending until Windows is restarted and the test
succeeds. UsedSpaceOnly and SkipHardwareTest change this behavior as
described below.

A terminating error can leave externally visible state partially
updated. For example, a recovery protector or directory recovery
record may exist even if encryption is not started or later validation
fails. The script does not remove protectors or recovery records that
it created or submitted.

A successful directory submission means Windows accepted the backup
request. The script does not read the recovery password back from AD DS
or Microsoft Entra ID. Verify directory visibility separately when
operational policy requires end-to-end confirmation.

When it creates a recovery-password protector, the script suppresses
the warning stream from Add-BitLockerKeyProtector so the 48-digit
password is not written to the console or a transcript by that cmdlet.
The script never intentionally prints or returns the recovery password.

Do not use this script while C: is being decrypted, or where another
full-disk encryption product is active. Review applicable Group Policy
and Intune BitLocker settings before use because policy can reject or
alter the requested configuration.

On failure, writes warnings as applicable and raises a terminating
error. No success object is produced.

.PARAMETER EncryptionMethod
Specifies the requested BitLocker encryption method. Applied policy may
require a different supported method, which the script reports and
uses.

.PARAMETER UsedSpaceOnly
When set, requests encryption of allocated disk space only; otherwise,
requests encryption of the entire volume. Use this mainly for new or
recently prepared systems where unallocated space has not held
sensitive data.

.PARAMETER SkipHardwareTest
When set, requests encryption without the BitLocker startup hardware
test; otherwise, a restart may be required before encryption begins.
Use only when bypassing the preboot validation is acceptable.
#>

[CmdletBinding()]
param(
    [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')]
    [string]$EncryptionMethod = 'XtsAes256',
    [string]$MountPoint = 'C:',
    [switch]$UsedSpaceOnly,
    [switch]$SkipHardwareTest
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$UiRuleWidth = 64
function Write-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    Write-Host ''
    Write-Host ('  ' + $Message) -ForegroundColor White
    Write-Host ('  ' + ('─' * $UiRuleWidth)) -ForegroundColor DarkGray
}
function Write-Status {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Running', 'Success', 'Action')]
        [string]$Kind,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    switch ($Kind) {
        'Info' {
            $tag = 'info'
            $color = [ConsoleColor]::DarkCyan
        }
        'Running' {
            $tag = 'run'
            $color = [ConsoleColor]::Cyan
        }
        'Success' {
            $tag = 'ok'
            $color = [ConsoleColor]::Green
        }
        'Action' {
            $tag = 'next'
            $color = [ConsoleColor]::Yellow
        }
    }
    Write-Host ('  [' + $tag + ']') -ForegroundColor $color -NoNewline
    Write-Host (' ' + $Message) -ForegroundColor Gray
}
function Write-Field {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [AllowNull()]
        [object]$Value
    )
    Write-Host ('  {0,-23}' -f ($Label + ':')) -ForegroundColor DarkGray -NoNewline
    Write-Host ([string]$Value) -ForegroundColor Gray
}
function Write-SuccessHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    Write-Host ''
    Write-Host ('  ' + ('━' * $UiRuleWidth)) -ForegroundColor Green
    Write-Host '  SUCCESS' -ForegroundColor Green -NoNewline
    Write-Host ('  ' + $Message) -ForegroundColor White
    Write-Host ('  ' + ('━' * $UiRuleWidth)) -ForegroundColor Green
}
function Get-ErrorDescription {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $parts = New-Object System.Collections.Generic.List[string]
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        $parts.Add($ErrorRecord.Exception.Message.Trim())
    }
    if ($ErrorRecord.FullyQualifiedErrorId) {
        $parts.Add('ErrorId=' + $ErrorRecord.FullyQualifiedErrorId)
    }
    if ($ErrorRecord.Exception) {
        try {
            $hresultBytes = [BitConverter]::GetBytes(
                [int32]$ErrorRecord.Exception.HResult
            )
            $unsignedHresult = [BitConverter]::ToUInt32(
                $hresultBytes,
                0
            )
            $parts.Add(
                ('HRESULT=0x{0:X8}' -f $unsignedHresult)
            )
        }
        catch {
        }
    }
    return ($parts -join ' | ')
}
function Get-SystemBitLockerVolume {
    $volume = Get-BitLockerVolume `
        -MountPoint $MountPoint `
        -ErrorAction Stop
    if ($null -eq $volume) {
        throw (
            'Get-BitLockerVolume returned no information for ' +
            $MountPoint +
            '.'
        )
    }
    return $volume
}
function Get-RecoveryPasswordProtectors {
    param(
        [Parameter(Mandatory = $true)]
        $Volume
    )
    return @(
        $Volume.KeyProtector |
            Where-Object {
                [string]$_.KeyProtectorType -eq 'RecoveryPassword'
            }
    )
}
function Get-BootProtectors {
    param(
        [Parameter(Mandatory = $true)]
        $Volume
    )
    $bootProtectorTypes = @(
        'Tpm'
        'TpmPin'
        'TpmStartupKey'
        'TpmPinStartupKey'
        'ExternalKey'
    )
    return @(
        $Volume.KeyProtector |
            Where-Object {
                [string]$_.KeyProtectorType -in $bootProtectorTypes
            }
    )
}
function Assert-TpmReady {
    if (
        -not (
            Get-Command `
                -Name Get-Tpm `
                -ErrorAction SilentlyContinue
        )
    ) {
        throw (
            'Get-Tpm is unavailable. ' +
            'The TrustedPlatformModule PowerShell module is required.'
        )
    }
    $tpm = Get-Tpm -ErrorAction Stop
    if (-not $tpm.TpmPresent) {
        throw (
            'No compatible TPM was detected. ' +
            'A TPM is required for unattended TPM-based OS-drive unlock.'
        )
    }
    if (-not $tpm.TpmReady) {
        throw (
            'The TPM is present but is not ready. ' +
            'Check tpm.msc and the UEFI or BIOS TPM configuration. ' +
            'This script will not clear or reset the TPM automatically.'
        )
    }
    if ($tpm.LockedOut) {
        Write-Warning (
            "`n" + 'The TPM reports that it is locked out. ' +
            'BitLocker activation may fail until the lockout condition ' +
            'is resolved.' + "`n`n"
        )
    }
    return $tpm
}
function Get-EntraJoinState {
    $dsregcmd = Join-Path `
        $env:SystemRoot `
        'System32\dsregcmd.exe'
    if (
        -not (
            Test-Path `
                -LiteralPath $dsregcmd `
                -PathType Leaf
        )
    ) {
        Write-Warning (
            "`n" + 'dsregcmd.exe was not found. ' +
            'Microsoft Entra join state could not be checked.' + "`n`n"
        )
        return $null
    }
    try {
        $output = @(
            & $dsregcmd /status 2>&1
        )
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Write-Warning (
                "`n" + 'dsregcmd.exe /status returned exit code ' +
                $exitCode +
                '. Entra escrow eligibility cannot be established.' +
                "`n`n"
            )
            return $null
        }
        return (
            @(
                $output |
                    Where-Object {
                        [string]$_ -match (
                            '^\s*AzureAdJoined\s*:\s*YES\s*$'
                        )
                    }
            ).Count -gt 0
        )
    }
    catch {
        Write-Warning (
            "`n" + 'Could not check Microsoft Entra join state: ' +
            (
                Get-ErrorDescription `
                    -ErrorRecord $_
            ) + "`n`n"
        )
        return $null
    }
}
function Get-AdComputerPlacement {
    $result = [pscustomobject]@{
        Determined        = $false
        DistinguishedName = ''
        DefaultComputers  = $false
    }
    $root = $null
    $entry = $null
    $searcher = $null
    try {
        $root = [ADSI]'LDAP://RootDSE'
        $baseDn = [string]$root.defaultNamingContext
        if ([string]::IsNullOrWhiteSpace($baseDn)) {
            throw 'RootDSE did not return a default naming context.'
        }
        $entry = New-Object `
            -TypeName System.DirectoryServices.DirectoryEntry `
            -ArgumentList ("LDAP://$baseDn")
        $searcher = New-Object `
            -TypeName System.DirectoryServices.DirectorySearcher `
            -ArgumentList $entry
        $searcher.Filter = (
            '(&(objectCategory=computer)(sAMAccountName=' +
            $env:COMPUTERNAME +
            '$))'
        )
        [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        $found = $searcher.FindOne()
        if ($null -ne $found) {
            $dn = [string]$found.Properties['distinguishedname'][0]
            $result.Determined = $true
            $result.DistinguishedName = $dn
            $result.DefaultComputers = (
                $dn -ieq (
                    'CN=' +
                    $env:COMPUTERNAME +
                    ',CN=Computers,' +
                    $baseDn
                )
            )
        }
    }
    catch {
        Write-Warning (
            "`n" + 'Could not determine AD computer location: ' +
            (Get-ErrorDescription -ErrorRecord $_) +
            "`n`n"
        )
    }
    finally {
        if ($null -ne $searcher) {
            $searcher.Dispose()
        }
        if ($null -ne $entry) {
            $entry.Dispose()
        }
        if ($null -ne $root) {
            $root.Dispose()
        }
    }
    return $result
}
function Get-AdRecoveryEscrowPolicy {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $result = [pscustomobject]@{
        Determined              = $false
        OSRecovery              = $null
        OSActiveDirectoryBackup = $null
        OSRecoveryPassword      = $null
        Eligible                = $false
    }
    try {
        if (-not (Test-Path -LiteralPath $policyPath -PathType Container)) {
            $result.Determined = $true
            return $result
        }
        $policy = Get-ItemProperty `
            -LiteralPath $policyPath `
            -ErrorAction Stop
        foreach ($propertyName in @(
            'OSRecovery'
            'OSActiveDirectoryBackup'
            'OSRecoveryPassword'
        )) {
            $property = $policy.PSObject.Properties[$propertyName]
            if ($null -ne $property) {
                $result.$propertyName = [int]$property.Value
            }
        }
        $result.Determined = $true
        $result.Eligible = (
            $result.OSRecovery -eq 1 -and
            $result.OSActiveDirectoryBackup -eq 1 -and
            $null -ne $result.OSRecoveryPassword -and
            $result.OSRecoveryPassword -ne 0
        )
    }
    catch {
        Write-Warning (
            "`n" + 'Could not read effective AD DS BitLocker recovery ' +
            'policy: ' +
            (Get-ErrorDescription -ErrorRecord $_) +
            "`n`n"
        )
    }
    return $result
}
function Format-PolicyValue {
    param(
        [AllowNull()]
        [object]$Value,
        [Parameter(Mandatory = $true)]
        [scriptblock]$EnabledTest
    )
    if ($null -eq $Value) {
        return 'Not configured'
    }
    if (& $EnabledTest $Value) {
        return ([string]$Value + ' (eligible)')
    }
    return ([string]$Value + ' (not eligible)')
}
function Find-AvailableDomainController {
    $result = [pscustomobject]@{
        Available        = $false
        DomainController = ''
    }
    $domain = $null
    $domainController = $null
    try {
        $domain = (
            [System.DirectoryServices.ActiveDirectory.Domain]::
                GetComputerDomain()
        )
        $domainController = $domain.FindDomainController()
        if (
            $null -ne $domainController -and
            -not [string]::IsNullOrWhiteSpace($domainController.Name)
        ) {
            $result.Available = $true
            $result.DomainController = [string]$domainController.Name
        }
    }
    catch {
        Write-Warning (
            "`n" + 'No AD DS domain controller could be discovered: ' +
            (Get-ErrorDescription -ErrorRecord $_) +
            "`n`n"
        )
    }
    finally {
        if ($null -ne $domainController) {
            $domainController.Dispose()
        }
        if ($null -ne $domain) {
            $domain.Dispose()
        }
    }
    return $result
}
function Get-PolicyEncryptionMethod {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    try {
        $policy = Get-ItemProperty `
            -LiteralPath $policyPath `
            -ErrorAction Stop
        $property = $policy.PSObject.Properties[
            'EncryptionMethodWithXtsOs'
        ]
        if ($null -eq $property) {
            return $null
        }
        switch ([int]$property.Value) {
            3 {
                return 'Aes128'
            }
            4 {
                return 'Aes256'
            }
            6 {
                return 'XtsAes128'
            }
            7 {
                return 'XtsAes256'
            }
            default {
                Write-Warning (
                    "`n" + 'Unsupported OS-drive encryption policy value ' +
                    $property.Value +
                    ' was found in ' +
                    $policyPath +
                    '.' + "`n`n"
                )
                return $null
            }
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $null
    }
    catch {
        Write-Warning (
            "`n" + 'Could not read the configured BitLocker encryption method: ' +
            (
                Get-ErrorDescription `
                    -ErrorRecord $_
            ) + "`n`n"
        )
        return $null
    }
}
function Start-EncryptionUsingExistingProtector {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Aes128', 'Aes256', 'XtsAes128', 'XtsAes256')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [bool]$EncryptUsedSpaceOnly,
        [Parameter(Mandatory = $true)]
        [bool]$BypassHardwareTest
    )
    $methodNumbers = @{
        Aes128    = [uint32]3
        Aes256    = [uint32]4
        XtsAes128 = [uint32]6
        XtsAes256 = [uint32]7
    }
    $encryptionFlags = [uint32]0
    if ($EncryptUsedSpaceOnly) {
        $encryptionFlags = [uint32]1
    }
    $encryptableVolume = Get-CimInstance `
        -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' `
        -ClassName Win32_EncryptableVolume `
        -Filter "DriveLetter = '$MountPoint'" `
        -ErrorAction Stop
    if ($null -eq $encryptableVolume) {
        throw (
            'Win32_EncryptableVolume returned no object for ' +
            $MountPoint +
            '.'
        )
    }
    if ($BypassHardwareTest) {
        $methodName = 'Encrypt'
    }
    else {
        $methodName = 'EncryptAfterHardwareTest'
    }
    $result = Invoke-CimMethod `
        -InputObject $encryptableVolume `
        -MethodName $methodName `
        -Arguments @{
            EncryptionMethod = $methodNumbers[$Method]
            EncryptionFlags  = $encryptionFlags
        } `
        -ErrorAction Stop
    $returnValue = [uint32]$result.ReturnValue
    if ($returnValue -ne 0) {
        $hexValue = '0x{0:X8}' -f $returnValue
        throw (
            $methodName +
            ' failed for ' +
            $MountPoint +
            ' with return value ' +
            $hexValue +
            '.'
        )
    }
}
function Resume-EncryptionConversion {
    $manageBde = Join-Path `
        $env:SystemRoot `
        'System32\manage-bde.exe'
    if (
        -not (
            Test-Path `
                -LiteralPath $manageBde `
                -PathType Leaf
        )
    ) {
        throw (
            'manage-bde.exe was not found, so paused encryption ' +
            'cannot be resumed.'
        )
    }
    $output = @(
        & $manageBde -resume $MountPoint 2>&1
    )
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $text = (
            $output |
                ForEach-Object {
                    [string]$_
                }
        ) -join ' '
        throw (
            'manage-bde.exe could not resume encryption on ' +
            $MountPoint +
            '. ExitCode=' +
            $exitCode +
            '. ' +
            $text
        )
    }
}
function Invoke-RecoveryEscrow {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Protectors,
        [Parameter(Mandatory = $true)]
        [bool]$AttemptAd,
        [Parameter(Mandatory = $true)]
        [bool]$AttemptAad
    )
    $adEscrowedProtectorIds = @()
    $aadEscrowedProtectorIds = @()
    $adFailedProtectorIds = @()
    $aadFailedProtectorIds = @()
    $adFailureDetails = @()
    $aadFailureDetails = @()
    $adCommand = $null
    $aadCommand = $null
    if ($AttemptAd) {
        $adCommand = Get-Command `
            -Name Backup-BitLockerKeyProtector `
            -ErrorAction SilentlyContinue
    }
    if ($AttemptAad) {
        $aadCommand = Get-Command `
            -Name BackupToAAD-BitLockerKeyProtector `
            -ErrorAction SilentlyContinue
    }
    foreach ($protector in $Protectors) {
        $protectorId = [string]$protector.KeyProtectorId
        if ([string]::IsNullOrWhiteSpace($protectorId)) {
            throw (
                'A recovery-password protector has no KeyProtectorId.'
            )
        }
        if ($AttemptAd) {
            if ($null -eq $adCommand) {
                $message = 'Backup-BitLockerKeyProtector is unavailable.'
                $adFailedProtectorIds += $protectorId
                $adFailureDetails += ($protectorId + ': ' + $message)
                Write-Warning ("`n" + $message + "`n`n")
            }
            else {
                try {
                    Write-Status `
                        -Kind Running `
                        -Message (
                            'Backing up protector ' +
                            $protectorId +
                            ' to AD DS'
                        )
                    $null = Backup-BitLockerKeyProtector `
                        -MountPoint $MountPoint `
                        -KeyProtectorId $protectorId `
                        -Confirm:$false `
                        -ErrorAction Stop
                    $adEscrowedProtectorIds += $protectorId
                    Write-Status `
                        -Kind Success `
                        -Message 'Recovery protector submitted to AD DS'
                }
                catch {
                    $message = Get-ErrorDescription -ErrorRecord $_
                    $adFailedProtectorIds += $protectorId
                    $adFailureDetails += ($protectorId + ': ' + $message)
                    Write-Warning (
                        "`n" + 'AD DS escrow failed for protector ' +
                        $protectorId +
                        ': ' +
                        $message + "`n`n"
                    )
                }
            }
        }
        if ($AttemptAad) {
            if ($null -eq $aadCommand) {
                $message = (
                    'BackupToAAD-BitLockerKeyProtector is unavailable.'
                )
                $aadFailedProtectorIds += $protectorId
                $aadFailureDetails += ($protectorId + ': ' + $message)
                Write-Warning ("`n" + $message + "`n`n")
            }
            else {
                try {
                    Write-Status `
                        -Kind Running `
                        -Message (
                            'Backing up protector ' +
                            $protectorId +
                            ' to Microsoft Entra ID'
                        )
                    $null = BackupToAAD-BitLockerKeyProtector `
                        -MountPoint $MountPoint `
                        -KeyProtectorId $protectorId `
                        -Confirm:$false `
                        -ErrorAction Stop
                    $aadEscrowedProtectorIds += $protectorId
                    Write-Status `
                        -Kind Success `
                        -Message (
                            'Recovery protector submitted to ' +
                            'Microsoft Entra ID'
                        )
                }
                catch {
                    $message = Get-ErrorDescription -ErrorRecord $_
                    $aadFailedProtectorIds += $protectorId
                    $aadFailureDetails += ($protectorId + ': ' + $message)
                    Write-Warning (
                        "`n" + 'Microsoft Entra escrow failed for protector ' +
                        $protectorId +
                        ': ' +
                        $message + "`n`n"
                    )
                }
            }
        }
    }
    if (-not $AttemptAd) {
        $adState = 'Not applicable'
    }
    elseif ($adEscrowedProtectorIds.Count -gt 0) {
        $adState = 'Succeeded'
    }
    else {
        $adState = 'Failed'
    }
    if (-not $AttemptAad) {
        $aadState = 'Not applicable'
    }
    elseif ($aadEscrowedProtectorIds.Count -gt 0) {
        $aadState = 'Succeeded'
    }
    else {
        $aadState = 'Failed'
    }
    return [pscustomobject]@{
        AdState                   = $adState
        AadState                  = $aadState
        AdEscrowedProtectorIds    = @($adEscrowedProtectorIds)
        AadEscrowedProtectorIds   = @($aadEscrowedProtectorIds)
        AdFailedProtectorIds      = @($adFailedProtectorIds)
        AadFailedProtectorIds     = @($aadFailedProtectorIds)
        AdFailureDetails          = @($adFailureDetails)
        AadFailureDetails         = @($aadFailureDetails)
        AtLeastOneSaved           = (
            $adEscrowedProtectorIds.Count -gt 0 -or
            $aadEscrowedProtectorIds.Count -gt 0
        )
    }
}
try {
    Write-Step 'Preflight checks (is everything allright to proceed?)'
    $currentIdentity = (
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    $currentPrincipal = New-Object `
        -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $currentIdentity
    $isAdministrator = $currentPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdministrator) {
        throw (
            'Run this script from an elevated Windows PowerShell session.'
        )
    }
    Write-Field `
        -Label 'Identity' `
        -Value $currentIdentity.Name
    #Write-Step 'Loading and checking BitLocker support'
    Import-Module BitLocker `
        -DisableNameChecking `
        -ErrorAction Stop
    $requiredCommands = @(
        'Get-BitLockerVolume'
        'Add-BitLockerKeyProtector'
        'Enable-BitLocker'
        'Resume-BitLocker'
    )
    foreach ($commandName in $requiredCommands) {
        if (
            -not (
                Get-Command `
                    -Name $commandName `
                    -ErrorAction SilentlyContinue
            )
        ) {
            throw (
                "Required BitLocker command '" +
                $commandName +
                "' is unavailable."
            )
        }
    }
    #Write-Step 'Checking domain and Microsoft Entra join state'
    $computerSystem = Get-CimInstance `
        -ClassName Win32_ComputerSystem `
        -ErrorAction Stop
    $domainJoined = [bool]$computerSystem.PartOfDomain
    $adEscrowEligible = $false
    $aadEscrowEligible = $false
    $adPrerequisiteIssues = @()
    $aadPrerequisiteIssues = @()
    if ($domainJoined) {
        Write-Field `
            -Label 'AD DS join' `
            -Value (
                'Yes - ' +
                $computerSystem.Domain
            )
        $placement = Get-AdComputerPlacement
        if ($placement.Determined) {
            Write-Field `
                -Label 'AD computer DN' `
                -Value $placement.DistinguishedName
            if ($placement.DefaultComputers) {
                Write-Warning (
                    "`n" + 'This computer account is in the built-in ' +
                    'CN=Computers container. GPOs cannot be linked directly ' +
                    'to this container. Confirm the required BitLocker ' +
                    'policy is inherited from the domain or move the ' +
                    'computer into the appropriate managed OU.' + "`n`n"
                )
            }
        }
        $adPolicy = Get-AdRecoveryEscrowPolicy
        Write-Field `
            -Label 'OSRecovery' `
            -Value (
                Format-PolicyValue `
                    -Value $adPolicy.OSRecovery `
                    -EnabledTest { param($value) [int]$value -eq 1 }
            )
        Write-Field `
            -Label 'OSActiveDirectoryBackup' `
            -Value (
                Format-PolicyValue `
                    -Value $adPolicy.OSActiveDirectoryBackup `
                    -EnabledTest { param($value) [int]$value -eq 1 }
            )
        Write-Field `
            -Label 'OSRecoveryPassword' `
            -Value (
                Format-PolicyValue `
                    -Value $adPolicy.OSRecoveryPassword `
                    -EnabledTest { param($value) [int]$value -ne 0 }
            )
        if (-not $adPolicy.Determined) {
            $adPrerequisiteIssues += (
                'effective BitLocker recovery policy could not be read'
            )
        }
        elseif (-not $adPolicy.Eligible) {
            $adPrerequisiteIssues += (
                'effective BitLocker policy does not enable AD DS ' +
                'recovery-password storage'
            )
        }
        $domainController = Find-AvailableDomainController
        if ($domainController.Available) {
            Write-Field `
                -Label 'Domain controller' `
                -Value $domainController.DomainController
        }
        else {
            $adPrerequisiteIssues += 'no domain controller is available'
        }
        if (
            -not (
                Get-Command `
                    -Name Backup-BitLockerKeyProtector `
                    -ErrorAction SilentlyContinue
            )
        ) {
            $adPrerequisiteIssues += (
                'Backup-BitLockerKeyProtector is unavailable'
            )
        }
        $adEscrowEligible = ($adPrerequisiteIssues.Count -eq 0)
    }
    else {
        Write-Field -Label 'AD DS join' -Value 'No'
        $adPrerequisiteIssues += 'device is not AD DS domain joined'
        Write-Status `
            -Kind Info `
            -Message 'Device is not domain joined; AD DS escrow is not applicable'
    }
    $entraJoined = Get-EntraJoinState
    if ($entraJoined -eq $true) {
        Write-Field `
            -Label 'Microsoft Entra join' `
            -Value 'Yes'
        if (
            Get-Command `
                -Name BackupToAAD-BitLockerKeyProtector `
                -ErrorAction SilentlyContinue
        ) {
            $aadEscrowEligible = $true
        }
        else {
            $aadPrerequisiteIssues += (
                'BackupToAAD-BitLockerKeyProtector is unavailable'
            )
        }
    }
    elseif ($entraJoined -eq $false) {
        Write-Field -Label 'Microsoft Entra join' -Value 'No'
        $aadPrerequisiteIssues += 'device is not Microsoft Entra joined'
        Write-Status `
            -Kind Info `
            -Message (
                'Device is not Entra joined; Entra escrow is not applicable'
            )
    }
    else {
        Write-Field -Label 'Microsoft Entra join' -Value 'Unknown'
        $aadPrerequisiteIssues += (
            'Microsoft Entra join state could not be determined'
        )
        Write-Status `
            -Kind Info `
            -Message 'Entra escrow is not applicable without a confirmed join'
    }
    if ($adEscrowEligible) {
        Write-Field -Label 'AD DS escrow preflight' -Value 'Eligible'
    }
    else {
        Write-Field `
            -Label 'AD DS escrow preflight' `
            -Value ('Not applicable - ' + ($adPrerequisiteIssues -join '; '))
    }
    if ($aadEscrowEligible) {
        Write-Field -Label 'Entra escrow preflight' -Value 'Eligible'
    }
    else {
        Write-Field `
            -Label 'Entra escrow preflight' `
            -Value ('Not applicable - ' + ($aadPrerequisiteIssues -join '; '))
    }
    if (-not $adEscrowEligible -and -not $aadEscrowEligible) {
        throw (
            'No usable recovery escrow destination is currently available. ' +
            'AD DS: ' +
            ($adPrerequisiteIssues -join '; ') +
            '. Microsoft Entra ID: ' +
            ($aadPrerequisiteIssues -join '; ') +
            '. No recovery-password protector was created.'
        )
    }
    # Write-Step 'Checking Secure Boot'
    if (
        Get-Command `
            -Name Confirm-SecureBootUEFI `
            -ErrorAction SilentlyContinue
    ) {
        try {
            if (
                Confirm-SecureBootUEFI `
                    -ErrorAction Stop
            ) {
                Write-Field `
                    -Label 'Secure Boot' `
                    -Value 'Enabled'
            }
            else {
                Write-Warning (
                    "`n" + 'Secure Boot is disabled. BitLocker can still work, ' +
                    'but platform-integrity protection is weaker.' + "`n`n"
                )
            }
        }
        catch {
            Write-Warning (
                "`n" + 'Secure Boot state could not be determined: ' +
                (
                    Get-ErrorDescription `
                        -ErrorRecord $_
                ) + "`n`n"
            )
        }
    }
    # Write-Step (
    #     'Reading the current BitLocker state of ' +
    #     $MountPoint
    # )
    $volume = Get-SystemBitLockerVolume
    $initialStatus = [string]$volume.VolumeStatus
    if ([string]$volume.VolumeType -ne 'OperatingSystem') {
        throw (
            $MountPoint +
            ' is not reported as the Windows operating-system volume.'
        )
    }
    if ([string]$volume.LockStatus -ne 'Unlocked') {
        throw (
            $MountPoint +
            ' is unexpectedly locked. ' +
            'The running Windows OS drive must be unlocked.'
        )
    }
    Write-Field `
        -Label 'Volume status' `
        -Value $initialStatus
    Write-Field `
        -Label 'Protection status' `
        -Value ([string]$volume.ProtectionStatus)
    Write-Field `
        -Label 'Encryption method' `
        -Value ([string]$volume.EncryptionMethod)
    Write-Field `
        -Label 'Encrypted' `
        -Value (
            [string]$volume.EncryptionPercentage +
            '%'
        )
    switch ($initialStatus) {
        'DecryptionInProgress' {
            throw (
                $MountPoint +
                ' is currently being decrypted. ' +
                'The script will not reverse an active decryption ' +
                'operation automatically.'
            )
        }
        'DecryptionPaused' {
            throw (
                $MountPoint +
                ' has paused decryption. ' +
                'The script will not reverse that operation automatically.'
            )
        }
        'FullyDecrypted' {
            Write-Warning (
                "`n" + 'Confirm that no third-party full-disk encryption product ' +
                'is installed or active. This script cannot reliably detect ' +
                'every such product.' + "`n`n"
            )
        }
    }
    # Write-Step 'Selecting the encryption method'
    $effectiveEncryptionMethod = $EncryptionMethod
    $policyEncryptionMethod = Get-PolicyEncryptionMethod
    if ($policyEncryptionMethod) {
        if ($policyEncryptionMethod -ne $EncryptionMethod) {
            Write-Warning (
                "`n" + 'The requested method ' +
                $EncryptionMethod +
                ' conflicts with local BitLocker policy. ' +
                'The script will use ' +
                $policyEncryptionMethod +
                '.' + "`n`n"
            )
        }
        $effectiveEncryptionMethod = $policyEncryptionMethod
    }
    Write-Field `
        -Label 'Encryption method' `
        -Value $effectiveEncryptionMethod
    if ($UsedSpaceOnly) {
        Write-Warning (
            "`n" + 'Used-space-only encryption was requested. Free space that ' +
            'may contain remnants of deleted data is not covered by the ' +
            'initial conversion.' + "`n`n"
        )
    }
    else {
        Write-Field `
            -Label 'Encryption scope' `
            -Value 'Entire volume'
    }
    if ($SkipHardwareTest) {
        Write-Warning (
            "`n" + 'The BitLocker startup hardware test is being skipped. ' +
            'Encryption will be requested immediately.' + "`n`n"
        )
    }
    else {
        Write-Field `
            -Label 'Hardware test' `
            -Value 'Enabled; restart may be required'
    }
    Write-Step (
        'Ensuring that a recovery-password protector exists'
    )
    $recoveryProtectors = @(
        Get-RecoveryPasswordProtectors `
            -Volume $volume
    )
    if ($recoveryProtectors.Count -eq 0) {
        Write-Status `
            -Kind Running `
            -Message 'Creating a recovery-password protector'
        $null = Add-BitLockerKeyProtector `
            -MountPoint $MountPoint `
            -RecoveryPasswordProtector `
            -Confirm:$false `
            -WarningAction SilentlyContinue `
            -ErrorAction Stop
        $volume = Get-SystemBitLockerVolume
        $recoveryProtectors = @(
            Get-RecoveryPasswordProtectors `
                -Volume $volume
        )
        if ($recoveryProtectors.Count -eq 0) {
            throw (
                'Windows reported success while adding a recovery-password ' +
                'protector, but no recovery-password protector can be found ' +
                'afterward.'
            )
        }
        Write-Status `
            -Kind Success `
            -Message 'Recovery-password protector created'
    }
    else {
        Write-Status `
            -Kind Info `
            -Message (
                'Found ' +
                $recoveryProtectors.Count +
                ' existing recovery-password protector(s)'
            )
    }
    if ($recoveryProtectors.Count -gt 1) {
        Write-Warning (
            "`n" + 'Multiple recovery-password protectors exist. ' +
            'The script will attempt to escrow all of them and will not ' +
            'remove any protector.' + "`n`n"
        )
    }
    foreach ($protector in $recoveryProtectors) {
        Write-Field `
            -Label 'Recovery protector' `
            -Value ([string]$protector.KeyProtectorId)
    }
    Write-Step (
        'Escrowing recovery information to AD DS and Microsoft Entra ID'
    )
    $escrow = Invoke-RecoveryEscrow `
        -Protectors $recoveryProtectors `
        -AttemptAd $adEscrowEligible `
        -AttemptAad $aadEscrowEligible
    Write-Field -Label 'AD DS escrow' -Value $escrow.AdState
    Write-Field -Label 'Entra escrow' -Value $escrow.AadState
    foreach ($protectorId in $escrow.AdEscrowedProtectorIds) {
        Write-Field -Label 'AD escrowed protector' -Value $protectorId
    }
    foreach ($protectorId in $escrow.AadEscrowedProtectorIds) {
        Write-Field -Label 'Entra escrowed protector' -Value $protectorId
    }
    foreach ($protectorId in $escrow.AdFailedProtectorIds) {
        Write-Field -Label 'AD failed protector' -Value $protectorId
    }
    foreach ($protectorId in $escrow.AadFailedProtectorIds) {
        Write-Field -Label 'Entra failed protector' -Value $protectorId
    }
    if (-not $escrow.AtLeastOneSaved) {
        $failureLines = @()
        $failureLines += @($escrow.AdFailureDetails)
        $failureLines += @($escrow.AadFailureDetails)
        $failureText = $failureLines -join (
            [Environment]::NewLine +
            ' - '
        )
        if ($initialStatus -eq 'FullyDecrypted') {
            $stateText = (
                'New BitLocker encryption was not started.'
            )
        }
        else {
            $stateText = (
                'The existing BitLocker state was left intact.'
            )
        }
        throw (
            'No recovery-password protector could be escrowed to either ' +
            'AD DS or Microsoft Entra ID.' +
            [Environment]::NewLine +
            $stateText +
            [Environment]::NewLine +
            'Failures:' +
            [Environment]::NewLine +
            ' - ' +
            $failureText
        )
    }
    if (
        $adEscrowEligible -and
        $escrow.AdEscrowedProtectorIds.Count -eq 0
    ) {
        Write-Warning (
            "`n" + 'No recovery protector was submitted successfully to AD DS. ' +
            'Continuing because Microsoft Entra escrow succeeded.' + "`n`n"
        )
    }
    if (
        $aadEscrowEligible -and
        $escrow.AadEscrowedProtectorIds.Count -eq 0
    ) {
        Write-Warning (
            "`n" + 'No recovery protector was submitted successfully to ' +
            'Microsoft Entra ID. Continuing because AD DS escrow succeeded.' + "`n`n"
        )
    }
    # Write-Step 'Ensuring that BitLocker encryption is active'
    $volume = Get-SystemBitLockerVolume
    $currentStatus = [string]$volume.VolumeStatus
    $activationRequested = $false
    switch ($currentStatus) {
        'FullyDecrypted' {
            $bootProtectors = @(
                Get-BootProtectors `
                    -Volume $volume
            )
            if ($bootProtectors.Count -eq 0) {
                Write-Status `
                    -Kind Running `
                    -Message (
                        'No boot protector found; checking the TPM'
                    )
                $null = Assert-TpmReady
                $enableParameters = @{
                    MountPoint       = $MountPoint
                    EncryptionMethod = $effectiveEncryptionMethod
                    TpmProtector     = $true
                    Confirm          = $false
                    ErrorAction      = 'Stop'
                }
                if ($UsedSpaceOnly) {
                    $enableParameters.UsedSpaceOnly = $true
                }
                if ($SkipHardwareTest) {
                    $enableParameters.SkipHardwareTest = $true
                }
                Write-Status `
                    -Kind Running `
                    -Message (
                        'Enabling BitLocker with a TPM protector'
                    )
                $null = Enable-BitLocker @enableParameters
            }
            else {
                $types = @(
                    $bootProtectors |
                        ForEach-Object {
                            [string]$_.KeyProtectorType
                        }
                ) -join ', '
                Write-Field `
                    -Label 'Boot protector(s)' `
                    -Value $types
                Write-Status `
                    -Kind Info `
                    -Message (
                        'Preserving the existing startup-protector ' +
                        'configuration'
                    )
                Start-EncryptionUsingExistingProtector `
                    -Method $effectiveEncryptionMethod `
                    -EncryptUsedSpaceOnly ([bool]$UsedSpaceOnly) `
                    -BypassHardwareTest ([bool]$SkipHardwareTest)
            }
            $activationRequested = $true
        }
        'EncryptionPaused' {
            Write-Warning (
                "`n" + 'BitLocker encryption is paused. Resuming the conversion.' + "`n`n"
            )
            Resume-EncryptionConversion
        }
        'EncryptionInProgress' {
            Write-Status `
                -Kind Info `
                -Message 'Encryption is already in progress'
        }
        'FullyEncrypted' {
            Write-Status `
                -Kind Success `
                -Message 'The volume is already fully encrypted'
        }
        default {
            throw (
                'Unsupported or unexpected BitLocker volume status: ' +
                $currentStatus
            )
        }
    }
    Start-Sleep -Seconds 2
    $volume = Get-SystemBitLockerVolume
    $currentStatus = [string]$volume.VolumeStatus
    $currentProtection = [string]$volume.ProtectionStatus
    if (
        $currentStatus -ne 'FullyDecrypted' -and
        $currentProtection -eq 'Off'
    ) {
        Write-Warning (
            "`n" + 'BitLocker protection is suspended or disabled. ' +
            'Attempting to resume protection.' + "`n`n"
        )
        $null = Resume-BitLocker `
            -MountPoint $MountPoint `
            -Confirm:$false `
            -ErrorAction Stop
        Start-Sleep -Seconds 1
        $volume = Get-SystemBitLockerVolume
    }
    Write-Step 'Performing final local verification'
    $finalStatus = [string]$volume.VolumeStatus
    $finalProtection = [string]$volume.ProtectionStatus
    $finalRecoveryProtectors = @(
        Get-RecoveryPasswordProtectors `
            -Volume $volume
    )
    if ($finalRecoveryProtectors.Count -eq 0) {
        throw (
            'Final verification failed: ' +
            'no recovery-password protector exists.'
        )
    }
    $rebootRequired = $false
    switch ($finalStatus) {
        'FullyEncrypted' {
            if ($finalProtection -ne 'On') {
                throw (
                    'Final verification failed: the volume is fully ' +
                    'encrypted, but ProtectionStatus is ' +
                    $finalProtection +
                    ' rather than On.'
                )
            }
        }
        'EncryptionInProgress' {
        }
        'FullyDecrypted' {
            if (
                $activationRequested -and
                -not $SkipHardwareTest
            ) {
                $rebootRequired = $true
            }
            else {
                throw (
                    'Final verification failed: the volume remains fully ' +
                    'decrypted and no pending hardware-test activation ' +
                    'is expected.'
                )
            }
        }
        default {
            throw (
                'Final verification failed: unexpected BitLocker status ' +
                $finalStatus +
                '.'
            )
        }
    }
    $escrowDestinations = @()
    if ($escrow.AdEscrowedProtectorIds.Count -gt 0) {
        $escrowDestinations += 'AD DS'
    }
    if ($escrow.AadEscrowedProtectorIds.Count -gt 0) {
        $escrowDestinations += 'Microsoft Entra ID'
    }
    $escrowText = $escrowDestinations -join ' and '
    Write-SuccessHeader `
        -Message 'BitLocker configuration completed'
    Write-Field `
        -Label 'Drive' `
        -Value $MountPoint
    Write-Field `
        -Label 'Volume status' `
        -Value $finalStatus
    Write-Field `
        -Label 'Protection status' `
        -Value $finalProtection
    Write-Field `
        -Label 'Encryption progress' `
        -Value (
            [string]$volume.EncryptionPercentage +
            '%'
        )
    Write-Field `
        -Label 'Encryption method' `
        -Value ([string]$volume.EncryptionMethod)
    Write-Field `
        -Label 'Recovery escrow' `
        -Value $escrowText
    if ($rebootRequired) {
        Write-Status `
            -Kind Action `
            -Message (
                'Restart Windows to run the BitLocker hardware test'
            )
        Write-Warning (
            "`n" + 'BitLocker encryption will begin only after the next restart ' +
            'and a successful startup hardware test.' + "`n`n"
        )
    }
    elseif ($finalStatus -eq 'EncryptionInProgress') {
        Write-Status `
            -Kind Info `
            -Message 'Encryption is continuing in the background'
    }
    else {
        Write-Status `
            -Kind Success `
            -Message (
                'The operating-system volume is fully encrypted ' +
                'and protected'
            )
    }
    Write-Host ''
<#
    [pscustomobject]@{
        Succeeded = $true
        MountPoint = $MountPoint
        VolumeStatus = $finalStatus
        ProtectionStatus = $finalProtection
        EncryptionPercentage = $volume.EncryptionPercentage
        EncryptionMethod = [string]$volume.EncryptionMethod
        RecoveryProtectorIds = @(
            $finalRecoveryProtectors |
                ForEach-Object {
                    [string]$_.KeyProtectorId
                }
        )
        EscrowedToActiveDirectory = (
            $escrow.AdEscrowedProtectorIds.Count -gt 0
        )
        EscrowedToMicrosoftEntraId = (
            $escrow.AadEscrowedProtectorIds.Count -gt 0
        )
        RebootRequired = $rebootRequired
    }
#>
}
catch {
    $message = Get-ErrorDescription `
        -ErrorRecord $_
    Write-Warning (
        "`n" + 'BITLOCKER CONFIGURATION FAILED: ' +
        $message + "`n`n"
    )
    throw
}
