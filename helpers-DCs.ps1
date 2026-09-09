<#
A collection of helper functions for Domain Controllers
#>


function Search-ADUserAnyProperty {
  <#
  .SYNOPSIS
  Search Active Directory users by a pattern across multiple common attributes.

  .DESCRIPTION
  This function wraps Get-ADUser with a wide LDAP filter that checks a user-supplied
  pattern against multiple commonly used identifier attributes (e.g. sAMAccountName,
  userPrincipalName, displayName, cn, givenName, sn, mail, proxyAddresses).
  It's intended as a convenient "search anywhere that matters" for finding users when
  you only know part of a name, email, alias, or login.

  Results include useful profile fields: Display Name, Department, Job Title, State,
  Company, OU (derived from DistinguishedName), and all proxyAddresses flattened into
  a comma-separated list. Optionally you can also search phone fields and/or restrict
  the search scope with -SearchBase.

  .PARAMETER Pattern
  The text pattern to search for (wildcards are automatically added at both ends).

  .PARAMETER SearchBase
  Optional LDAP distinguished name to scope the search.

  .PARAMETER IncludePhones
  If specified, phone-related attributes are included in the search (makes the search a bit slower)

  .EXAMPLE
  # Find any user whose name, alias, or email contains "nick"
  Search-ADUserAnyProperty -Pattern 'nick'

  .EXAMPLE
  # Search within a specific OU, also matching phone numbers
  Search-ADUserAnyProperty -Pattern '2103' -IncludePhones -SearchBase 'OU=Athens,OU=Users,DC=corp,DC=example,DC=com'

  .EXAMPLE
  # Export results to CSV
  Search-ADUserAnyProperty -Pattern 'nick' |
    Export-Csv C:\temp\ad-search.csv -NoTypeInformation -Encoding UTF8
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Pattern,
    [string]$SearchBase,
    [switch]$IncludePhones
  )

  function Escape-Ldap([string]$s){
    $s = $s -replace '\\','\5c' -replace '\*','\2a' -replace '\(','\28' -replace '\)','\29'
    if($s.Contains([char]0)){ $s = $s -replace ([char]0), '\00' }
    $s
  }

  $p = '*' + (Escape-Ldap $Pattern) + '*'
  $attrs = @('cn','displayName','mail','samAccountName','userPrincipalName','givenName','sn','proxyAddresses','department','title','company','st')
  if($IncludePhones){ $attrs += @('telephoneNumber','mobile','homePhone') }

  $or = ($attrs | ForEach-Object { "($_=$p)" }) -join ''
  $ldap = "(|$or)"

  $props = @('displayName','samAccountName','userPrincipalName','mail','department','title','company','st','distinguishedName','proxyAddresses')
  if($IncludePhones){ $props += @('telephoneNumber','mobile','homePhone') }

  $adArgs = @{ LDAPFilter=$ldap; Properties=$props }
  if($SearchBase){ $adArgs.SearchBase = $SearchBase }

  $Results = Get-ADUser @adArgs

  if(((-not $Results) -or ($Results.Count -eq 0)) -and (-not $IncludePhones)){
    Write-Host -for yellow "No matches. Phone numbers were not searched; add -IncludePhones to include telephoneNumber, mobile, homePhone."
  }  
  if($Results -and ($Results.Count -gt 10)){
    Write-Host -for yellow "Too many matches. You may wish to pipe me to ogv. E.g.:`n    Search-ADUserAnyProperty foo | ogv"
  }  

  $results | Select-Object `
    @{n='DisplayName';e={$_.DisplayName}},
    @{n='SamAccountName';e={$_.SamAccountName}},
    @{n='UserPrincipalName';e={$_.UserPrincipalName}},
    @{n='Mail';e={$_.mail}},
    @{n='Department';e={$_.Department}},
    @{n='JobTitle';e={$_.Title}},
    @{n='State';e={$_.st}},
    @{n='Company';e={$_.Company}},
    @{n='ProxyAddresses';e={($_.proxyAddresses -join ', ')}},
    @{n='OU';e={($_.DistinguishedName -replace '^[^,]+,','')}}

}
