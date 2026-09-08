<#
.SYNOPSIS
    Performs read-only, workstation-side Active Directory connectivity diagnostics.

.DESCRIPTION
    Tests domain membership, required services, DNS and SRV discovery, DC Locator,
    routes, required client-to-DC TCP ports, the Netlogon RPC interface when
    rpcping.exe is available, LDAP RootDSE, SYSVOL access when the current user is
    a domain user, time offset, Kerberos tickets, and secure-channel indicators.

    The script deliberately does not repair or reset the secure channel, restart
    services, flush caches, force DC discovery, or change the machine password.

.PARAMETER DomainName
    DNS name of the Active Directory domain. When omitted, the computer's joined
    domain is used.

.PARAMETER MaxDomainControllers
    Maximum number of discovered domain controllers to test. The default is 8.

.PARAMETER TcpTimeoutMilliseconds
    Timeout for each TCP connection attempt. The default is 1000 milliseconds.

.PARAMETER IncludeOptionalPorts
    Also tests LDAPS 636, Global Catalog 3268/3269, and AD Web Services 9389.
    Failure of an optional port is a warning, not a domain-health failure.

.PARAMETER SkipSecureChannel
    Skips all Test-ComputerSecureChannel checks, both the Windows-selected
    domain controller and each individual domain controller.

.EXAMPLE
    .\Test-WorkstationDomainConnectivity.ps1 -SkipSecureChannel

.EXAMPLE
    .\Test-WorkstationDomainConnectivity.ps1

.EXAMPLE
    .\Test-WorkstationDomainConnectivity.ps1 -IncludeOptionalPorts

.NOTES
    Compatible with Windows PowerShell 5.1. Run elevated for the broadest coverage.
    The script writes only color-coded console messages and returns no objects.
    Passwords, packet contents, and historical event logs are never collected.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$DomainName,

    [ValidateRange(1, 32)]
    [int]$MaxDomainControllers = 8,

    [ValidateRange(250, 30000)]
    [int]$TcpTimeoutMilliseconds = 1000,

    [switch]$IncludeOptionalPorts,

    [switch]$SkipSecureChannel
)

$started = Get-Date
$statusCounts = @{ PASS = 0; WARN = 0; FAIL = 0; INFO = 0; SKIP = 0 }
$recapLines = New-Object 'System.Collections.Generic.List[string]'
$displayState = @{
    CheckOpen  = $false
    Description = ''
    Mode        = 'Command'
    CommandText = ''
    SuppressOutput = $false
}

function ConvertTo-DisplayText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) {
        return $Value.Trim()
    }
    return (($Value | Out-String -Width 4096).Trim())
}

function Write-IndentedText {
    param(
        [AllowNull()]
        [object]$Value,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::DarkGray
    )

    $text = ConvertTo-DisplayText $Value
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    foreach ($line in @($text -split '\r?\n')) {
        Write-Host "    $line" -ForegroundColor $ForegroundColor
    }
}

function Write-CheckResult {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,
        [AllowEmptyString()]
        [string]$Evidence,
        [string]$OutputLabel = 'Got this output:',
        [string]$Reason = '',
        [string]$InfoText = ''
    )

    $statusCounts[$Status]++

    $statusColor = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'SKIP' { 'DarkCyan' }
        'INFO' { 'DarkGray' }
        default { 'DarkGray' }
    }

    if ($displayState.SuppressOutput -and $Status -notin @('WARN', 'FAIL')) {
        $displayState.CheckOpen = $false
        return
    }

    if ($Status -eq 'INFO' -and -not [string]::IsNullOrWhiteSpace($InfoText)) {
        Write-Host $InfoText -ForegroundColor DarkGray
        $displayState.CheckOpen = $false
        return
    }

    if ($Status -eq 'SKIP') {
        Write-Host ''
        Write-Host '[SKIPPED]' -ForegroundColor DarkCyan -NoNewline
        $skipMessageText = if ([string]::IsNullOrWhiteSpace($Evidence)) {
            $displayState.Description -replace '^Checking\s+', ''
        }
        else {
            $Evidence.Trim().TrimEnd('.')
        }
        Write-Host " $skipMessageText." -ForegroundColor DarkCyan
        $displayState.CheckOpen = $false
        return
    }
    # This fallback protects the format if a future test is added without first
    # registering its plain-language description and command or method.
    if (-not $displayState.CheckOpen) {
        $displayState.Description = 'Checking domain connectivity.'
        $displayState.Mode = 'Evaluation'
        $displayState.CommandText = 'Information collected by the script'
    }

    $completedDescription = $displayState.Description.Trim()
    if ($completedDescription -match '^Checking\b') {
        $completedDescription = $completedDescription -replace '^Checking\b', 'Checked'
    }
    elseif ($completedDescription -match '^Comparing\b') {
        $completedDescription = $completedDescription -replace '^Comparing\b', 'Compared'
    }
    elseif ($completedDescription -notmatch '^Checked\b') {
        $completedDescription = "Checked $completedDescription"
    }
    $completedDescription = $completedDescription.TrimEnd()
    if ($completedDescription -notmatch '[.!?]$') {
        $completedDescription += '.'
    }

    $modeLabel = switch ($displayState.Mode) {
        'Method'     { ' Method:' }
        'Evaluation' { ' Evaluating:' }
        default      { ' Run:' }
    }
    $messageColor = if ($Status -in @('PASS', 'INFO', 'SKIP')) { 'DarkGray' } else { 'White' }
    $headline = " $completedDescription$modeLabel"
    if ($Status -in @('WARN', 'FAIL')) {
        [void]$recapLines.Add("[$Status]$headline")
    }

    Write-Host ''
    Write-Host "[$Status]" -ForegroundColor $statusColor -NoNewline
    Write-Host $headline -ForegroundColor $messageColor
    Write-IndentedText -Value $displayState.CommandText -ForegroundColor DarkGray
    if (-not [string]::IsNullOrWhiteSpace($Evidence)) {
        Write-Host $OutputLabel -ForegroundColor DarkGray
        Write-IndentedText -Value $Evidence -ForegroundColor DarkGray
    }
    if ($Status -in @('WARN', 'FAIL')) {
        Write-Host ("Why {0}:" -f $Status) -ForegroundColor $statusColor
        Write-IndentedText -Value $Reason -ForegroundColor White
    }
    $displayState.CheckOpen = $false
}

function Write-CheckCommand {
    param(
        [string]$Description,
        [string]$CommandText,
        [switch]$Evaluation,
        [switch]$Method
    )

    if ($Evaluation) {
        $mode = 'Evaluation'
    }
    elseif ($Method) {
        $mode = 'Method'
    }
    else {
        $mode = 'Command'
    }
    $displayState.Description = $Description
    $displayState.CommandText = $CommandText
    $displayState.Mode = $mode
    $displayState.CheckOpen = $true
}

function Write-SectionHeading {
    param(
        [int]$Number,
        [string]$Title
    )

    Write-Host "`n$Number. $($Title.ToUpperInvariant())" -ForegroundColor White
}

function Write-CheckError {
    param(
        [string]$Status,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Reason = ''
    )

    $errorSummary = $ErrorRecord.Exception.Message
    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.FullyQualifiedErrorId)) {
        $errorSummary += " Error ID: $($ErrorRecord.FullyQualifiedErrorId)."
    }
    Write-CheckResult -Status $Status `
        -Evidence $errorSummary `
        -OutputLabel 'Got this error:' `
        -Reason $Reason
}

function Invoke-NativeCapture {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $nativeOutput = @(& $FilePath @ArgumentList 2>&1)
    $output = ($nativeOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Text     = $output.Trim()
    }
}

function Test-TcpPortWithTimeout {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMilliseconds
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $null
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return [pscustomobject]@{ Open = $false; Detail = "Timed out after $TimeoutMilliseconds ms" }
        }
        $client.EndConnect($asyncResult)
        return [pscustomobject]@{ Open = $true; Detail = 'TCP connection succeeded' }
    }
    catch {
        return [pscustomobject]@{
            Open = $false
            Detail = ConvertTo-DisplayText $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $asyncResult -and $null -ne $asyncResult.AsyncWaitHandle) {
            $asyncResult.AsyncWaitHandle.Close()
        }
        $client.Close()
    }
}

function Test-LdapRootDse {
    param(
        [string]$DomainController,
        [int]$TimeoutMilliseconds
    )

    $connection = $null
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new(
            $DomainController, 389, $false, $false
        )
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $connection.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMilliseconds)
        $connection.SessionOptions.ProtocolVersion = 3
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
            '', '(objectClass=*)',
            [System.DirectoryServices.Protocols.SearchScope]::Base,
            [string[]]@('defaultNamingContext', 'dnsHostName')
        )
        $response = $connection.SendRequest($request)
        $entry = $response.Entries[0]
        $context = [string]$entry.Attributes['defaultNamingContext'][0]
        return [pscustomobject]@{ Succeeded = $true; Detail = "defaultNamingContext=$context" }
    }
    catch {
        return [pscustomobject]@{
            Succeeded = $false
            Detail = ConvertTo-DisplayText $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $connection) { $connection.Dispose() }
    }
}

Write-Host "`nDomain workstation connectivity assessment started at $($started.ToString('yyyy-MM-dd HH:mm:ss'))" `
    -ForegroundColor White
Write-Host 'Testing the workstation-to-domain connection as it works right now. No repairs will be attempted.' `
    -ForegroundColor DarkGray

# Computer identity, domain membership, build, and privileges.
Write-SectionHeading -Number 1 -Title 'Computer'
Write-CheckCommand `
    -Description 'Checking whether this computer is joined to an Active Directory domain.' `
    -CommandText 'Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop'
try {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }
    catch {
        $displayState.CommandText += [Environment]::NewLine + `
            'Fallback: Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop'
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    }

    if (-not $computerSystem.PartOfDomain) {
        Write-CheckResult -Status FAIL `
            -Evidence 'Computer reports PartOfDomain=False.' `
            -Reason 'This computer is not joined to an Active Directory domain, so the domain-member connectivity requirement is not met.'
    }
    else {
        Write-CheckResult -Status PASS -Evidence ''
    }

    if ([string]::IsNullOrWhiteSpace($DomainName)) {
        $DomainName = [string]$computerSystem.Domain
    }
}
catch {
    Write-CheckError -Status FAIL `
        -ErrorRecord $_ `
        -Reason 'The domain-membership check raised an error, so this required prerequisite could not be verified.'
}

Write-CheckCommand `
    -Description 'Checking which Active Directory domain will be tested.' `
    -CommandText 'The joined-domain information collected above, or the -DomainName parameter' `
    -Evaluation
if ([string]::IsNullOrWhiteSpace($DomainName)) {
    Write-CheckResult -Status FAIL `
        -Evidence 'No joined domain could be determined and -DomainName was not supplied.' `
        -Reason 'No domain name is available, so the domain-specific connectivity tests cannot be performed.'
}
else {
    $DomainName = $DomainName.Trim().TrimEnd('.')
    Write-CheckResult -Status INFO -Evidence $DomainName -InfoText "Domain: $DomainName"
}

Write-CheckCommand `
    -Description 'Checking the installed Windows version and build.' `
    -CommandText 'Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop'
try {
    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        $displayState.CommandText += [Environment]::NewLine + `
            'Fallback: Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop'
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
    }
    Write-CheckResult -Status INFO `
        -Evidence "$($operatingSystem.Caption); version $($operatingSystem.Version); build $($operatingSystem.BuildNumber)" `
        -InfoText "Host: $env:COMPUTERNAME ($($operatingSystem.Caption); version $($operatingSystem.Version); build $($operatingSystem.BuildNumber))"
}
catch {
    Write-CheckError -Status WARN `
        -ErrorRecord $_ `
        -Reason 'The Windows version could not be read, leaving the diagnostic report without operating-system context.'
}

Write-CheckCommand `
    -Description 'Checking the current identity and whether PowerShell is running as administrator.' `
    -CommandText 'Read the current Windows identity and test its local Administrator role' `
    -Method
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isDomainUser = (
    -not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN) -and
    $env:USERDNSDOMAIN.TrimEnd('.') -ieq $DomainName
)
$isLocalUser = $identity.Name -like "$env:COMPUTERNAME\*"
$elevationStatus = if ($isElevated -or $SkipSecureChannel) { 'INFO' } else { 'WARN' }
$identitySummary = if ($isDomainUser -and $isElevated) {
    "Signed in user: $($identity.Name) (domain account; PowerShell is running as administrator)"
}
elseif ($isDomainUser) {
    "Signed in user: $($identity.Name) (domain account; PowerShell is not running as administrator)"
}
elseif ($isLocalUser -and $isElevated) {
    "Signed in user: $($identity.Name) (local administrator)"
}
elseif ($isElevated) {
    "Signed in user: $($identity.Name) (non-domain account; PowerShell is running as administrator)"
}
elseif ($isLocalUser) {
    "Signed in user: $($identity.Name) (local account; PowerShell is not running as administrator)"
}
else {
    "Signed in user: $($identity.Name) (non-domain account; PowerShell is not running as administrator)"
}
Write-CheckResult -Status $elevationStatus `
    -Evidence $identitySummary `
    -InfoText $identitySummary `
    -Reason 'PowerShell is not running as administrator, so the computer-domain trust checks will be skipped and diagnostic coverage will be incomplete.'

# Required local services.
foreach ($serviceName in @('Netlogon', 'Dnscache', 'LanmanWorkstation', 'W32Time')) {
    Write-CheckCommand `
        -Description "Checking whether the required Windows service '$serviceName' is running." `
        -CommandText "Get-Service -Name '$serviceName' -ErrorAction Stop"
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        $required = $serviceName -in @('Netlogon', 'Dnscache', 'LanmanWorkstation')
        if ($service.Status -eq 'Running') {
            Write-CheckResult -Status PASS -Evidence "Status=$($service.Status)"
        }
        elseif ($required) {
            Write-CheckResult -Status FAIL `
                -Evidence "Status=$($service.Status)" `
                -Reason 'This required domain-client service is not running, so the domain functions that depend on it may be unavailable.'
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "Status=$($service.Status)" `
                -Reason 'The Windows Time service is not running, so current domain time synchronization is not assured.'
        }
    }
    catch {
        Write-CheckError -Status WARN `
            -ErrorRecord $_ `
            -Reason 'The service status could not be read, so the test cannot confirm whether this service is available.'
    }
}

# Active interfaces, DNS servers, profiles, and client addresses.
Write-SectionHeading -Number 2 -Title 'Domain network'
$activeAdapterIndexes = @()
$localIPv4Addresses = @()
Write-CheckCommand `
    -Description 'Checking which network adapters are active.' `
    -CommandText "Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up'"
try {
    $activeAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
    $activeAdapterIndexes = @($activeAdapters.InterfaceIndex)
    $adapterText = $activeAdapters |
        Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed |
        Format-Table -AutoSize | Out-String -Width 240
    Write-CheckResult -Status INFO -Evidence $adapterText.Trim()
}
catch {
    Write-CheckError -Status WARN `
        -ErrorRecord $_ `
        -Reason 'The active adapter list could not be read, so later checks may lack the interface information needed to interpret addresses and DNS settings.'
}

Write-CheckCommand `
    -Description 'Checking the usable IPv4 addresses on the active network adapters.' `
    -CommandText 'Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop'
try {
    $localIPv4Rows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            $_.InterfaceIndex -in $activeAdapterIndexes -and
            $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'
        })
    $localIPv4Addresses = @($localIPv4Rows | Select-Object -ExpandProperty IPAddress -Unique)
    $addressText = if ($localIPv4Addresses.Count -gt 0) {
        @($localIPv4Rows | ForEach-Object {
            $addressAdapter = $activeAdapters | Where-Object InterfaceIndex -eq $_.InterfaceIndex |
                Select-Object -First 1
            $networkRole = if ($addressAdapter.InterfaceDescription -match 'AnyConnect|Secure Mobility|VPN') {
                "VPN ($($_.InterfaceAlias))"
            }
            else {
                "LAN ($($_.InterfaceAlias))"
            }
            "$networkRole=$($_.IPAddress)"
        }) -join '; '
    }
    else {
        'No usable IPv4 addresses were found on active adapters.'
    }
    $addressStatus = if ($localIPv4Addresses.Count -gt 0) { 'INFO' } else { 'WARN' }
    Write-CheckResult -Status $addressStatus `
        -Evidence $addressText `
        -Reason 'No usable IPv4 address was identified on the detected active adapters, so the IPv4 path to the domain cannot be confirmed.'
}
catch {
    Write-CheckError -Status WARN `
        -ErrorRecord $_ `
        -Reason 'The IPv4 address query failed, so the test cannot verify the local addresses used to reach the domain.'
}

$profiles = @()
Write-CheckCommand `
    -Description 'Checking whether Windows recognizes an active domain-connected network.' `
    -CommandText 'Get-NetConnectionProfile -ErrorAction Stop'
try {
    $profiles = @(Get-NetConnectionProfile -ErrorAction Stop)
    $profileText = $profiles | ForEach-Object {
        "$($_.InterfaceAlias)=$($_.NetworkCategory)/$($_.IPv4Connectivity)"
    }
    if (@($profiles | Where-Object NetworkCategory -eq 'DomainAuthenticated').Count -gt 0) {
        Write-CheckResult -Status PASS -Evidence ($profileText -join '; ')
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence ($profileText -join '; ') `
            -Reason 'No returned network profile is classified as DomainAuthenticated, so Windows has not reported a domain-authenticated network in this check.'
    }
}
catch {
    Write-CheckError -Status WARN `
        -ErrorRecord $_ `
        -Reason 'Windows network profiles could not be read, so domain-authenticated network status could not be verified.'
}

$dnsConfigurations = @()
Write-CheckCommand `
    -Description 'Checking which DNS servers are configured on the active network adapters.' `
    -CommandText 'Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop'
try {
    $dnsConfigurations = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            $_.InterfaceIndex -in $activeAdapterIndexes -and @($_.ServerAddresses).Count -gt 0
        })
    $dnsText = $dnsConfigurations | ForEach-Object {
        "$($_.InterfaceAlias)=$(@($_.ServerAddresses) -join ',')"
    }
    if ($dnsConfigurations.Count -gt 0) {
        Write-CheckResult -Status INFO -Evidence ($dnsText -join '; ')
    }
    else {
        Write-CheckResult -Status FAIL `
            -Evidence 'No IPv4 DNS servers were found on active adapters.' `
            -Reason 'No IPv4 DNS server was identified on the detected active adapters, so the DNS configuration required by these domain tests could not be confirmed.'
    }
}
catch {
    Write-CheckError -Status FAIL `
        -ErrorRecord $_ `
        -Reason 'The DNS configuration query failed, so this required domain-resolution prerequisite could not be verified.'
}

$domainDnsInterfaceIndexes = @($profiles |
    Where-Object NetworkCategory -eq 'DomainAuthenticated' |
    Select-Object -ExpandProperty InterfaceIndex -Unique)
Write-CheckCommand `
    -Description 'Checking which active network adapters are intended to resolve the domain.' `
    -CommandText 'Get-DnsClient -ErrorAction Stop'
try {
    $dnsClientInterfaces = @(Get-DnsClient -ErrorAction Stop |
        Where-Object { $_.InterfaceIndex -in $activeAdapterIndexes })
    $suffixMatchedIndexes = @($dnsClientInterfaces |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.ConnectionSpecificSuffix) -and
            $_.ConnectionSpecificSuffix.TrimEnd('.') -ieq $DomainName
        } | Select-Object -ExpandProperty InterfaceIndex -Unique)
    $domainDnsInterfaceIndexes = @($domainDnsInterfaceIndexes + $suffixMatchedIndexes | Sort-Object -Unique)
    $domainDnsInterfaces = @($dnsClientInterfaces |
        Where-Object InterfaceIndex -in $domainDnsInterfaceIndexes |
        Select-Object -ExpandProperty InterfaceAlias -Unique)
    $domainDnsInterfaceText = if ($domainDnsInterfaces.Count -gt 0) {
        $domainDnsInterfaces -join ', '
    }
    else {
        'None identified'
    }
    Write-CheckResult -Status INFO -Evidence $domainDnsInterfaceText
}
catch {
    Write-CheckError -Status INFO -ErrorRecord $_
}

$dcNames = @()
$systemDomainDnsWorks = $false
$ldapSrvName = "_ldap._tcp.dc._msdcs.$DomainName"
$kerberosSrvName = "_kerberos._tcp.dc._msdcs.$DomainName"

if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
    Write-CheckCommand `
        -Description "Checking whether Windows DNS can find domain controllers for $DomainName." `
        -CommandText "Resolve-DnsName -Name '$ldapSrvName' -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop"
    try {
        $ldapSrvRecords = @(Resolve-DnsName -Name $ldapSrvName -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop)
        $dcNames = @($ldapSrvRecords | Where-Object NameTarget |
            ForEach-Object { $_.NameTarget.TrimEnd('.') } | Sort-Object -Unique)
        if ($dcNames.Count -gt 0) {
            $systemDomainDnsWorks = $true
            Write-CheckResult -Status PASS -Evidence "$($dcNames.Count) found: $($dcNames -join ', ')"
        }
        else {
            Write-CheckResult -Status FAIL `
                -Evidence 'Windows received a DNS reply, but it contained no domain controllers.' `
                -Reason 'The DNS reply contained no domain-controller service records, so this lookup did not provide the controllers required for domain discovery.'
        }
    }
    catch {
        Write-CheckError -Status FAIL `
            -ErrorRecord $_ `
            -Reason 'The domain-controller service-record lookup failed, so Windows DNS discovery of domain controllers could not be verified.'
    }

    Write-CheckCommand `
        -Description "Checking whether Windows DNS can find Kerberos sign-in servers for $DomainName." `
        -CommandText "Resolve-DnsName -Name '$kerberosSrvName' -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop"
    try {
        $kerberosSrvRecords = @(Resolve-DnsName -Name $kerberosSrvName -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop)
        $kerberosTargets = @($kerberosSrvRecords | Where-Object NameTarget |
            ForEach-Object { $_.NameTarget.TrimEnd('.') } | Sort-Object -Unique)
        if ($kerberosTargets.Count -gt 0) {
            Write-CheckResult -Status PASS -Evidence "$($kerberosTargets.Count) found: $($kerberosTargets -join ', ')"
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence 'Windows received a DNS reply, but it contained no Kerberos sign-in servers.' `
                -Reason 'The DNS reply contained no Kerberos service records, so DNS discovery of domain sign-in servers was not confirmed.'
        }
    }
    catch {
        Write-CheckError -Status WARN `
            -ErrorRecord $_ `
            -Reason 'The Kerberos service-record lookup failed, so DNS discovery of domain sign-in servers could not be verified.'
    }
}

# Query every active adapter's DNS servers directly. Failure on an unrelated LAN
# resolver is informational when Windows is already resolving the domain correctly.
$dnsServerRows = foreach ($configuration in $dnsConfigurations) {
    foreach ($serverAddress in @($configuration.ServerAddresses)) {
        [pscustomobject]@{
            InterfaceAlias = $configuration.InterfaceAlias
            InterfaceIndex = $configuration.InterfaceIndex
            ServerAddress  = $serverAddress
        }
    }
}

foreach ($dnsServerRow in @($dnsServerRows | Sort-Object ServerAddress, InterfaceAlias -Unique)) {
    $dnsTarget = "$($dnsServerRow.ServerAddress) via $($dnsServerRow.InterfaceAlias)"
    $isDomainDnsInterface = $dnsServerRow.InterfaceIndex -in $domainDnsInterfaceIndexes
    $expectedNonDomainAnswer = $systemDomainDnsWorks -and -not $isDomainDnsInterface
    Write-CheckCommand `
        -Description "Checking whether DNS server $($dnsServerRow.ServerAddress) on '$($dnsServerRow.InterfaceAlias)' can find the domain." `
        -CommandText "Resolve-DnsName -Name '$ldapSrvName' -Type SRV -Server '$($dnsServerRow.ServerAddress)' -DnsOnly -QuickTimeout -ErrorAction Stop"
    try {
        $directRecords = @(Resolve-DnsName -Name $ldapSrvName -Type SRV -Server $dnsServerRow.ServerAddress `
            -DnsOnly -QuickTimeout -ErrorAction Stop)
        $directTargets = @($directRecords | Where-Object NameTarget)
        if ($directTargets.Count -gt 0) {
            Write-CheckResult -Status PASS -Evidence "$($directTargets.Count) domain controller record(s) returned."
        }
        elseif ($expectedNonDomainAnswer) {
            Write-CheckResult -Status INFO `
                -Evidence "This DNS server belongs to a different network. It does not contain records for $DomainName, while Windows is successfully finding the domain through the VPN DNS servers."
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "The DNS server replied, but it did not return any domain controllers for $DomainName." `
                -Reason 'This resolver did not provide domain-controller records, and the test could not classify the result as an expected response from an unrelated resolver; domain discovery through this DNS server is unverified.'
        }
    }
    catch {
        if ($expectedNonDomainAnswer) {
            Write-CheckResult -Status INFO `
                -Evidence "This DNS server belongs to a different network and does not contain records for $DomainName. This is expected because Windows is successfully finding the domain through the VPN DNS servers."
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "The DNS server could not find $DomainName. Technical error: $($_.Exception.Message)" `
                -Reason 'This resolver did not provide domain-controller records, and the test could not classify the result as an expected response from an unrelated resolver; domain discovery through this DNS server is unverified.'
        }
    }

    Write-CheckCommand `
        -Description "Checking whether the workstation can make a TCP connection to DNS server $($dnsServerRow.ServerAddress)." `
        -CommandText "TCP connection to $($dnsServerRow.ServerAddress):53 with a $TcpTimeoutMilliseconds ms timeout" `
        -Method
    $tcpDns = Test-TcpPortWithTimeout -ComputerName $dnsServerRow.ServerAddress -Port 53 `
        -TimeoutMilliseconds $TcpTimeoutMilliseconds
    if ($tcpDns.Open) {
        Write-CheckResult -Status PASS -Evidence 'DNS connection succeeded.'
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence "The TCP DNS connection failed. Technical detail: $($tcpDns.Detail)" `
            -Reason 'The TCP connection to this DNS server failed; DNS operations that require TCP may fail even if UDP queries succeed.'
    }
}

# DC Locator and site. This deliberately avoids /force so it does not alter the locator cache.
$locatedDc = $null
if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
    Write-CheckCommand `
        -Description "Checking whether Windows can locate a usable domain controller for $DomainName." `
        -CommandText "nltest.exe /dsgetdc:$DomainName"
    try {
        $locator = Invoke-NativeCapture nltest.exe @("/dsgetdc:$DomainName")
        if ($locator.Text -match '(?im)^\s*DC:\s*\\\\([^\s]+)') {
            $locatedDc = $matches[1].TrimEnd('.')
            $dcNames = @($dcNames + $locatedDc | Sort-Object -Unique)
        }
        if ($locator.ExitCode -eq 0) {
            Write-CheckResult -Status PASS -Evidence $locator.Text
        }
        else {
            Write-CheckResult -Status FAIL `
                -Evidence "ExitCode=$($locator.ExitCode)`n$($locator.Text)" `
                -Reason 'DC Locator returned a nonzero exit code, so Windows did not successfully locate a usable domain controller through this check.'
        }
    }
    catch {
        Write-CheckError -Status FAIL `
            -ErrorRecord $_ `
            -Reason 'DC Locator could not be executed successfully, so this required domain-controller discovery check could not be completed.'
    }

    Write-CheckCommand `
        -Description 'Checking which Active Directory site Windows currently uses.' `
        -CommandText 'nltest.exe /dsgetsite'
    try {
        $site = Invoke-NativeCapture nltest.exe @('/dsgetsite')
        if ($site.ExitCode -eq 0) {
            Write-CheckResult -Status PASS -Evidence $site.Text
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "ExitCode=$($site.ExitCode)`n$($site.Text)" `
                -Reason 'The site query returned a nonzero exit code, so the workstation''s Active Directory site could not be determined; site-aware controller selection may be affected.'
        }
    }
    catch {
        Write-CheckError -Status WARN `
            -ErrorRecord $_ `
            -Reason 'The site query could not be completed, so the workstation''s Active Directory site and site-aware controller selection could not be verified.'
    }
}

if ($dcNames.Count -gt $MaxDomainControllers) {
    Write-CheckCommand `
        -Description 'Checking how many discovered domain controllers will be tested.' `
        -CommandText 'The domain-controller list collected by the DNS and DC Locator checks' `
        -Evaluation
    Write-CheckResult -Status WARN `
        -Evidence "Discovered $($dcNames.Count) DCs; testing the first $MaxDomainControllers alphabetically." `
        -Reason 'The discovered controller count exceeds the configured test limit, so some domain controllers will remain untested.'
    $dcNames = @($dcNames | Sort-Object | Select-Object -First $MaxDomainControllers)
}

if ($dcNames.Count -eq 0) {
    Write-CheckCommand `
        -Description 'Checking whether at least one domain controller is available for further testing.' `
        -CommandText 'The domain-controller list collected by the DNS and DC Locator checks' `
        -Evaluation
    Write-CheckResult -Status FAIL `
        -Evidence 'No domain controllers were available for testing.' `
        -Reason 'No domain controllers were discovered, so the required controller connectivity tests cannot run.'
}

# Workstation DNS registration: useful for reverse administration, but not required
# for every client-initiated domain operation.
if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
    $computerFqdn = "$env:COMPUTERNAME.$DomainName"
    Write-CheckCommand `
        -Description "Checking whether DNS contains a current IPv4 record for this workstation ($computerFqdn)." `
        -CommandText "Resolve-DnsName -Name '$computerFqdn' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop"
    try {
        $computerRecords = @(Resolve-DnsName -Name $computerFqdn -Type A -DnsOnly -QuickTimeout -ErrorAction Stop)
        $registeredAddresses = @($computerRecords | Where-Object IPAddress |
            Select-Object -ExpandProperty IPAddress -Unique)
        $matchingAddresses = @($registeredAddresses | Where-Object { $_ -in $localIPv4Addresses })
        if ($matchingAddresses.Count -gt 0) {
            Write-CheckResult -Status PASS `
                -Evidence "Registered=$($registeredAddresses -join ','); ActiveMatch=$($matchingAddresses -join ',')"
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "Registered=$($registeredAddresses -join ','); ActiveIPv4=$($localIPv4Addresses -join ',')" `
                -Reason 'None of the returned DNS addresses matches the detected active IPv4 addresses; connections initiated to this workstation by name may reach an outdated address or fail.'
        }
    }
    catch {
        Write-CheckError -Status WARN `
            -ErrorRecord $_ `
            -Reason 'The workstation DNS lookup failed, so its current address registration and inbound access by name could not be verified.'
    }
}

# Active secure-channel indicator. Cached nltest /sc_query state is intentionally
# excluded because this script reports only what can be tested right now.
Write-SectionHeading -Number 3 -Title 'Active Directory'
$testComputerSecureChannelResult = $null
if ($SkipSecureChannel) {
    Write-CheckCommand `
        -Description 'Checking whether computer-domain trust tests are enabled.' `
        -CommandText '-SkipSecureChannel' `
        -Evaluation
    Write-CheckResult -Status SKIP -Evidence 'All computer-domain trust tests were skipped because -SkipSecureChannel was supplied.'
}
elseif (-not [string]::IsNullOrWhiteSpace($DomainName)) {
    if ($isElevated) {
        Write-CheckCommand `
            -Description 'Checking the computer-domain trust using the domain controller selected by Windows.' `
            -CommandText 'Test-ComputerSecureChannel -ErrorAction Stop'
        try {
            $testComputerSecureChannelResult = Test-ComputerSecureChannel -ErrorAction Stop
            if ($testComputerSecureChannelResult) {
                Write-CheckResult -Status PASS -Evidence 'True'
            }
            else {
                Write-CheckResult -Status FAIL `
                    -Evidence 'False' `
                    -Reason 'The command returned False, meaning it did not confirm a healthy computer-domain secure channel with the selected controller.'
            }
        }
        catch {
            Write-CheckError -Status FAIL `
                -ErrorRecord $_ `
                -Reason 'The computer-domain secure-channel command raised an error, so this required trust check could not be completed; the error alone does not establish that the trust is broken.'
        }
    }
    else {
        Write-CheckCommand `
            -Description 'Checking whether PowerShell has enough privilege to run the computer-domain trust command.' `
            -CommandText 'The administrator-role result collected above' `
            -Evaluation
        Write-CheckResult -Status SKIP -Evidence 'The computer-domain trust test was not run because PowerShell is not elevated.'
    }
}

# Per-DC DNS, route, TCP, RPC, LDAP, optional SYSVOL, and optional per-DC secure channel.
$requiredPorts = [ordered]@{
    88  = 'Kerberos'
    135 = 'RPC Endpoint Mapper'
    389 = 'LDAP'
    445 = 'SMB/SYSVOL'
}
$supportingPorts = [ordered]@{
    464 = 'Kerberos password change'
}
$optionalPorts = [ordered]@{
    636  = 'LDAPS'
    3268 = 'Global Catalog'
    3269 = 'Global Catalog over TLS'
    9389 = 'Active Directory Web Services'
}
Write-CheckCommand `
    -Description 'Checking whether the Microsoft RPCPing diagnostic tool is available.' `
    -CommandText 'Get-Command rpcping.exe -ErrorAction SilentlyContinue'
$rpcPingCommand = Get-Command rpcping.exe -ErrorAction SilentlyContinue
if ($null -ne $rpcPingCommand) {
    Write-CheckResult -Status INFO -Evidence "Found at $($rpcPingCommand.Source)."
}
else {
    Write-CheckResult -Status SKIP -Evidence 'rpcping.exe is not installed, so the dynamic RPC interface test will be skipped.'
}
$usableDcCount = 0
$ldapDcCount = 0
$sysvolSuccessCount = 0

if ($dcNames.Count -gt 0) {
    Write-Host "`nDomain controllers" -ForegroundColor White
}

foreach ($dcName in $dcNames) {
    $dcRouteStatus = 'SKIP'
    $dcIPv4 = @()
    $dcDnsError = $null
    Write-CheckCommand `
        -Description "Checking whether Windows DNS can find the IPv4 address of $dcName." `
        -CommandText "Resolve-DnsName -Name '$dcName' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop"
    try {
        $dcAddressRecords = @(Resolve-DnsName -Name $dcName -Type A -DnsOnly -QuickTimeout -ErrorAction Stop)
        $dcIPv4 = @($dcAddressRecords | Where-Object IPAddress |
            Select-Object -ExpandProperty IPAddress -Unique)
    }
    catch {
        $dcDnsError = $_
    }

    $targetAddress = if ($dcIPv4.Count -gt 0) { $dcIPv4[0] } else { $dcName }
    $dcNameParts = $dcName -split '\.', 2
    $displayDcName = if ($dcNameParts.Count -eq 2) {
        "$($dcNameParts[0].ToUpperInvariant()).$($dcNameParts[1].ToLowerInvariant())"
    }
    else {
        $dcName.ToUpperInvariant()
    }
    $displayDcAddress = if ($dcIPv4.Count -gt 0) { $dcIPv4[0] } else { '(unresolved)' }
    Write-Host "`n$displayDcName  $displayDcAddress" -ForegroundColor White

    if ($null -ne $dcDnsError) {
        Write-CheckError -Status WARN `
            -ErrorRecord $dcDnsError `
            -Reason 'The controller host lookup failed, so its IPv4 address and the associated route could not be verified.'
    }
    elseif ($dcIPv4.Count -gt 0) {
        Write-CheckResult -Status PASS -Evidence ($dcIPv4 -join ', ')
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence 'No IPv4 address was returned.' `
            -Reason 'The controller name has no returned IPv4 address, so its IPv4 route and reachability cannot be verified by the address-based checks.'
    }

    if ($dcIPv4.Count -gt 0) {
        Write-CheckCommand `
            -Description "Checking which network route Windows will use to reach $dcName at $targetAddress." `
            -CommandText "Find-NetRoute -RemoteIPAddress '$targetAddress' -ErrorAction Stop"
        try {
            $routeResults = @(Find-NetRoute -RemoteIPAddress $targetAddress -ErrorAction Stop)
            $routeSourceAddress = $routeResults | Where-Object {
                $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress'
            } | Select-Object -First 1
            $routeChoice = $routeResults | Where-Object {
                $_.CimClass.CimClassName -eq 'MSFT_NetRoute'
            } | Select-Object -First 1

            if ($null -eq $routeChoice) {
                Write-CheckResult -Status WARN `
                    -Evidence 'Find-NetRoute did not return a NetRoute object.' `
                    -Reason 'Find-NetRoute returned no route object, so the test cannot confirm a selected Windows route to this controller.'
            }
            else {
                $routeEvidence = [pscustomobject][ordered]@{
                    InterfaceAlias = $routeChoice.InterfaceAlias
                    IPAddress      = $routeSourceAddress.IPAddress
                    NextHop        = $routeChoice.NextHop
                    RouteMetric    = $routeChoice.RouteMetric
                }
                Write-CheckResult -Status PASS -Evidence (($routeEvidence | Format-List | Out-String -Width 240).Trim())
            }
        }
        catch {
            Write-CheckError -Status WARN `
                -ErrorRecord $_ `
                -Reason 'The route query raised an error, so the selected path to this controller could not be verified; this does not by itself prove that no route exists.'
        }

        Write-CheckCommand `
            -Description "Checking whether $dcName responds to a simple network ping." `
            -CommandText "ICMP ping to $targetAddress with a $([Math]::Max(500, $TcpTimeoutMilliseconds)) ms timeout" `
            -Method
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($targetAddress, [Math]::Max(500, $TcpTimeoutMilliseconds))
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                Write-CheckResult -Status PASS -Evidence "Address=$targetAddress; RoundTripTime=$($reply.RoundtripTime) ms"
            }
            else {
                Write-CheckResult -Status INFO -Evidence "Address=$targetAddress; Status=$($reply.Status)"
            }
            $ping.Dispose()
        }
        catch {
            Write-CheckError -Status INFO -ErrorRecord $_
        }
    }

    $requiredOpen = $true
    foreach ($portEntry in $requiredPorts.GetEnumerator()) {
        Write-CheckCommand `
            -Description "Checking whether the workstation can reach $($portEntry.Value) on $dcName." `
            -CommandText "TCP connection to ${targetAddress}:$($portEntry.Key) with a $TcpTimeoutMilliseconds ms timeout" `
            -Method
        $portResult = Test-TcpPortWithTimeout -ComputerName $targetAddress -Port $portEntry.Key `
            -TimeoutMilliseconds $TcpTimeoutMilliseconds
        if ($portResult.Open) {
            Write-CheckResult -Status PASS -Evidence $portResult.Detail
        }
        else {
            $requiredOpen = $false
            Write-CheckResult -Status WARN `
                -Evidence $portResult.Detail `
                -Reason 'The TCP connection to this required service on this controller failed; other controllers may still provide the service.'
        }
    }
    foreach ($portEntry in $supportingPorts.GetEnumerator()) {
        Write-CheckCommand `
            -Description "Checking whether the workstation can reach $($portEntry.Value) on $dcName." `
            -CommandText "TCP connection to ${targetAddress}:$($portEntry.Key) with a $TcpTimeoutMilliseconds ms timeout" `
            -Method
        $portResult = Test-TcpPortWithTimeout -ComputerName $targetAddress -Port $portEntry.Key `
            -TimeoutMilliseconds $TcpTimeoutMilliseconds
        if ($portResult.Open) {
            Write-CheckResult -Status PASS -Evidence $portResult.Detail
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence $portResult.Detail `
                -Reason 'The TCP connection to the Kerberos password-change service failed, so password-change operations using this controller may be affected.'
        }
    }
    if ($IncludeOptionalPorts) {
        foreach ($portEntry in $optionalPorts.GetEnumerator()) {
            Write-CheckCommand `
                -Description "Checking whether the workstation can reach optional service $($portEntry.Value) on $dcName." `
                -CommandText "TCP connection to ${targetAddress}:$($portEntry.Key) with a $TcpTimeoutMilliseconds ms timeout" `
                -Method
            $portResult = Test-TcpPortWithTimeout -ComputerName $targetAddress -Port $portEntry.Key `
                -TimeoutMilliseconds $TcpTimeoutMilliseconds
            if ($portResult.Open) {
                Write-CheckResult -Status PASS -Evidence $portResult.Detail
            }
            else {
                Write-CheckResult -Status WARN `
                    -Evidence $portResult.Detail `
                    -Reason 'The TCP connection to this requested optional service failed; this matters if the environment relies on that service.'
            }
        }
    }

    $rpcOkay = $true
    if ($null -ne $rpcPingCommand) {
        Write-CheckCommand `
            -Description "Checking the Netlogon dynamic RPC interface on $dcName." `
            -CommandText "rpcping.exe /t ncacn_ip_tcp /s $targetAddress /f 12345678-1234-ABCD-EF00-01234567CFFB,1 /v 2"
        try {
            $rpcResult = Invoke-NativeCapture $rpcPingCommand.Source @(
                '/t', 'ncacn_ip_tcp', '/s', $targetAddress,
                '/f', '12345678-1234-ABCD-EF00-01234567CFFB,1', '/v', '2'
            )
            if ($rpcResult.ExitCode -eq 0) {
                Write-CheckResult -Status PASS -Evidence $rpcResult.Text
            }
            else {
                $rpcOkay = $false
                Write-CheckResult -Status WARN `
                    -Evidence "ExitCode=$($rpcResult.ExitCode)`n$($rpcResult.Text)" `
                    -Reason 'RPCPing returned a nonzero exit code, so a successful call to this controller''s Netlogon RPC interface was not confirmed.'
            }
        }
        catch {
            $rpcOkay = $false
            Write-CheckError -Status WARN `
                -ErrorRecord $_ `
                -Reason 'The Netlogon RPC diagnostic could not be completed, so dynamic RPC reachability to this controller remains unverified.'
        }
    }
    else {
        Write-CheckCommand `
            -Description "Checking whether the Netlogon dynamic RPC interface can be tested on $dcName." `
            -CommandText 'The RPCPing tool-availability result collected above' `
            -Evaluation
        Write-CheckResult -Status SKIP -Evidence 'rpcping.exe is not installed.'
    }

    Write-CheckCommand `
        -Description "Checking whether $dcName answers a basic Active Directory LDAP query." `
        -CommandText "Anonymous LDAP RootDSE query to ${dcName}:389 with a $TcpTimeoutMilliseconds ms timeout" `
        -Method
    $ldapResult = Test-LdapRootDse -DomainController $dcName -TimeoutMilliseconds $TcpTimeoutMilliseconds
    if ($ldapResult.Succeeded) {
        $ldapDcCount++
        Write-CheckResult -Status PASS -Evidence $ldapResult.Detail
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence $ldapResult.Detail `
            -Reason 'The basic LDAP query did not succeed, so a working LDAP response from this controller was not confirmed; access policy may also restrict anonymous queries.'
    }

    if ($isDomainUser) {
        $sysvolPath = "\\$dcName\SYSVOL\$DomainName"
        Write-CheckCommand `
            -Description "Checking whether the current domain user can read the SYSVOL folder on $dcName." `
            -CommandText "Test-Path -LiteralPath '$sysvolPath' -ErrorAction Stop"
        try {
            if (Test-Path -LiteralPath $sysvolPath -ErrorAction Stop) {
                $sysvolSuccessCount++
                Write-CheckResult -Status PASS -Evidence $sysvolPath
            }
            else {
                Write-CheckResult -Status WARN `
                    -Evidence "$sysvolPath was not accessible." `
                    -Reason 'The current user could not access SYSVOL on this controller, so Group Policy files there may be unavailable to this user.'
            }
        }
        catch {
            Write-CheckError -Status WARN `
                -ErrorRecord $_ `
                -Reason 'The SYSVOL access check raised an error, so access to this controller''s Group Policy files could not be verified.'
        }
    }

    if ($requiredOpen -and $rpcOkay) { $usableDcCount++ }

    if ($isElevated -and -not $SkipSecureChannel) {
        $shortDcName = ($dcName -split '\.')[0]
        Write-CheckCommand `
            -Description "Checking the computer-domain trust against $shortDcName." `
            -CommandText "Test-ComputerSecureChannel -Server '$dcName' -ErrorAction Stop"
        try {
            $perDcSecureChannel = Test-ComputerSecureChannel -Server $dcName -ErrorAction Stop
            if ($perDcSecureChannel) {
                Write-CheckResult -Status PASS -Evidence 'True'
            }
            else {
                Write-CheckResult -Status FAIL `
                    -Evidence 'False' `
                    -Reason 'The command returned False, meaning it did not confirm a healthy computer-domain secure channel with the selected controller.'
            }
        }
        catch {
            Write-CheckError -Status FAIL `
                -ErrorRecord $_ `
                -Reason 'The computer-domain secure-channel command raised an error, so this required trust check could not be completed; the error alone does not establish that the trust is broken.'
        }
    }

}

$displayState.SuppressOutput = $true
if ($dcNames.Count -gt 0) {
    Write-CheckCommand `
        -Description 'Checking whether at least one domain controller passed every required network-path test.' `
        -CommandText 'The required TCP-port and Netlogon RPC results collected above' `
        -Evaluation
    if ($usableDcCount -gt 0) {
        Write-CheckResult -Status PASS -Evidence "$usableDcCount of $($dcNames.Count) tested DC(s) passed the required path tests."
    }
    else {
        Write-CheckResult -Status FAIL `
            -Evidence 'No tested DC passed all required TCP and available Netlogon RPC checks.' `
            -Reason 'Every tested controller failed at least one required TCP or available Netlogon RPC check, so no complete required network path was verified.'
    }

    Write-CheckCommand `
        -Description 'Checking whether at least one domain controller answered the basic Active Directory LDAP query.' `
        -CommandText 'The LDAP RootDSE results collected above' `
        -Evaluation
    if ($ldapDcCount -gt 0) {
        Write-CheckResult -Status PASS -Evidence "$ldapDcCount of $($dcNames.Count) tested DC(s) answered RootDSE."
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence 'No tested DC answered the LDAP RootDSE query.' `
            -Reason 'No tested controller answered the basic LDAP query, leaving LDAP functionality unverified; restrictions on anonymous queries can also cause this result.'
    }
}
$displayState.SuppressOutput = $false

# Time source and an active offset sample from the located or first discovered DC.
Write-SectionHeading -Number 4 -Title 'Time'
Write-CheckCommand `
    -Description 'Checking which time source Windows is currently using.' `
    -CommandText 'w32tm.exe /query /source'
try {
    $timeSource = Invoke-NativeCapture w32tm.exe @('/query', '/source')
    if ($timeSource.ExitCode -eq 0 -and $timeSource.Text -notmatch 'Local CMOS Clock|Free-running') {
        Write-CheckResult -Status PASS -Evidence $timeSource.Text
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence "ExitCode=$($timeSource.ExitCode)`n$($timeSource.Text)" `
            -Reason $(if ($timeSource.ExitCode -ne 0) { 'The time-source query returned a nonzero exit code, so the active synchronization source could not be verified.' } else { 'Windows reports a local or free-running clock, so synchronization with a domain time source was not confirmed.' })
    }

    Write-CheckCommand `
        -Description 'Checking the current Windows Time synchronization status.' `
        -CommandText 'w32tm.exe /query /status'
    $timeStatus = Invoke-NativeCapture w32tm.exe @('/query', '/status')
    if ($timeStatus.ExitCode -eq 0) {
        if ($timeStatus.Text -match '(?im)Leap Indicator:\s*3|Stratum:\s*0|Last Sync Error:\s*(?!0\b)') {
            Write-CheckResult -Status WARN `
                -Evidence $timeStatus.Text `
                -Reason 'The output matched Leap Indicator 3, Stratum 0, or a nonzero Last Sync Error, so healthy time synchronization was not confirmed.'
        }
        else {
            Write-CheckResult -Status PASS -Evidence $timeStatus.Text
        }
    }
    else {
        Write-CheckResult -Status WARN `
            -Evidence "ExitCode=$($timeStatus.ExitCode)`n$($timeStatus.Text)" `
            -Reason 'The time-status query returned a nonzero exit code, so synchronization health could not be verified.'
    }
}
catch {
    Write-CheckError -Status WARN `
        -ErrorRecord $_ `
        -Reason 'A Windows Time query could not be completed, so the workstation''s time source or synchronization state remains unverified.'
}

$timeTarget = if ($locatedDc) { $locatedDc } elseif ($dcNames.Count -gt 0) { $dcNames[0] } else { $null }
if ($timeTarget) {
    Write-CheckCommand `
        -Description "Comparing this workstation's clock with $timeTarget." `
        -CommandText "w32tm.exe /stripchart /computer:$timeTarget /samples:1 /dataonly"
    try {
        $stripchart = Invoke-NativeCapture w32tm.exe @(
            '/stripchart', "/computer:$timeTarget", '/samples:1', '/dataonly'
        )
        if ($stripchart.ExitCode -eq 0 -and $stripchart.Text -match '([+-][0-9]+(?:[\.,][0-9]+)?)s') {
            $offsetText = $matches[1].TrimEnd('s').Replace(',', '.')
            $offsetSeconds = [Math]::Abs([double]::Parse(
                $offsetText, [Globalization.CultureInfo]::InvariantCulture
            ))
            if ($offsetSeconds -gt 300) {
                Write-CheckResult -Status FAIL `
                    -Evidence "Absolute offset=$offsetSeconds seconds.`n$($stripchart.Text)" `
                    -Reason 'The measured clock difference exceeds 300 seconds, crossing this test''s failure threshold because this degree of clock skew can prevent Kerberos authentication.'
            }
            elseif ($offsetSeconds -gt 60) {
                Write-CheckResult -Status WARN `
                    -Evidence "Absolute offset=$offsetSeconds seconds.`n$($stripchart.Text)" `
                    -Reason 'The measured clock difference exceeds this test''s 60-second warning threshold, indicating time drift that should be investigated before it reaches the 300-second failure threshold.'
            }
            else {
                Write-CheckResult -Status PASS -Evidence "Absolute offset=$offsetSeconds seconds.`n$($stripchart.Text)"
            }
        }
        elseif ($stripchart.ExitCode -eq 0) {
            Write-CheckResult -Status INFO -Evidence "Response received but offset was not parsed.`n$($stripchart.Text)"
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "ExitCode=$($stripchart.ExitCode)`n$($stripchart.Text)" `
                -Reason 'The clock comparison returned a nonzero exit code, so the time difference from the domain controller could not be measured.'
        }
    }
    catch {
        Write-CheckError -Status WARN `
            -ErrorRecord $_ `
            -Reason 'The clock comparison could not be completed, so the workstation''s time difference from the domain controller remains unknown.'
    }
}

# Current-user Kerberos is meaningful only for a domain user. It does not expose
# the Local System computer-account ticket cache.
Write-SectionHeading -Number 5 -Title 'User-level tests'
if (-not $isDomainUser) {
    Write-CheckCommand `
        -Description 'Checking whether user-context SYSVOL and Kerberos tests can be run.' `
        -CommandText 'The current sign-in identity collected above' `
        -Evaluation
    $userTestSkipMessage = if ($isLocalUser) {
        "User authentication tests were not run because $($identity.Name) is a local account."
    }
    else {
        "User authentication tests were not run because $($identity.Name) is not an account from $DomainName."
    }
    Write-CheckResult -Status SKIP -Evidence $userTestSkipMessage
}
elseif ($dcNames.Count -gt 0) {
    Write-CheckCommand `
        -Description 'Checking whether any tested domain controller provided an accessible SYSVOL folder.' `
        -CommandText 'The authenticated SYSVOL results collected above' `
        -Evaluation
    if ($sysvolSuccessCount -gt 0) {
        Write-CheckResult -Status PASS `
            -Evidence "$sysvolSuccessCount of $($dcNames.Count) tested domain controller(s) allowed user access to SYSVOL."
    }
    else {
        Write-CheckResult -Status FAIL `
            -Evidence 'The domain user could not access SYSVOL on any tested DC.' `
            -Reason 'SYSVOL access failed on every tested controller, so no accessible source of domain Group Policy files was verified for the current user.'
    }
}

if ($isDomainUser) {
    Write-CheckCommand `
        -Description 'Checking whether the current domain user has a Kerberos ticket-granting ticket.' `
        -CommandText 'klist.exe'
    try {
        $ticketList = Invoke-NativeCapture klist.exe @()
        if ($ticketList.ExitCode -eq 0 -and $ticketList.Text -match "(?i)krbtgt/$([regex]::Escape($DomainName))") {
            Write-CheckResult -Status PASS -Evidence 'A ticket-granting ticket for the joined domain is present.'
        }
        else {
            Write-CheckResult -Status WARN `
                -Evidence "ExitCode=$($ticketList.ExitCode); no matching domain TGT was found." `
                -Reason $(if ($ticketList.ExitCode -ne 0) { 'The ticket-list command returned a nonzero exit code, so the current user domain ticket-granting ticket could not be verified.' } else { 'No ticket-granting ticket matching the domain was found for the current user, so current Kerberos sign-in readiness is unverified; this can occur after offline sign-in.' })
        }
    }
    catch {
        Write-CheckError -Status WARN `
            -ErrorRecord $_ `
            -Reason 'The Kerberos ticket query failed, so the current user''s domain ticket-granting ticket could not be verified.'
    }
}

$failedCount = $statusCounts.FAIL
$warningCount = $statusCounts.WARN
$skippedCount = $statusCounts.SKIP
$passedCount = $statusCounts.PASS
$overallStatus = if ($failedCount -gt 0) { 'FAIL' } elseif ($warningCount -gt 0) { 'WARN' } else { 'PASS' }
Write-Host "`nTest complete." -ForegroundColor White
Write-Host ("Passed: {0}  Warnings: {1}  Failed: {2}  Skipped: {3}" -f `
    $passedCount, $warningCount, $failedCount, $skippedCount) -ForegroundColor DarkGray

$finalBackground = if ($overallStatus -eq 'FAIL') { 'Red' } elseif ($overallStatus -eq 'WARN') { 'Yellow' } else { 'Green' }
$finalForeground = if ($overallStatus -eq 'FAIL') { 'White' } else { 'Black' }
$finalMeaning = if ($overallStatus -eq 'FAIL') {
    'One or more current domain connectivity tests failed.'
}
elseif ($overallStatus -eq 'WARN') {
    'No required test failed, but one or more checks produced a warning.'
}
else {
    'The current workstation-to-domain connection passed all required tests.'
}
Write-Host " FINAL RESULT: $overallStatus - $finalMeaning " `
    -ForegroundColor $finalForeground -BackgroundColor $finalBackground

if ($failedCount -gt 0 -or $warningCount -gt 0) {
    Write-Host "Here are the test(s) that didn't pass -- see above for more detail" -ForegroundColor White
    foreach ($line in $recapLines) {
        $recapColor = if ($line.StartsWith('[FAIL]')) { 'Red' } else { 'Yellow' }
        Write-Host $line.Substring(0, 6) -ForegroundColor $recapColor -NoNewline
        Write-Host $line.Substring(6) -ForegroundColor White
    }
}
