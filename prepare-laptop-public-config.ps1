<#
.SYNOPSIS
Defines shared Windows release support groups for laptop quality checks.

.DESCRIPTION
Dot-source this public configuration to populate
$WIN_RELEASES_WITH_LONG_SUPPORT and $WIN_RELEASES_WITH_MEDIUM_SUPPORT.
The caller combines these groups when checking a laptop's Windows release.

The complete workflow also uses a public function library and separate private
configuration and caller scripts. Private configuration supplies deployment
settings such as network details, account naming rules, and required software.
Those settings are maintained separately from this published configuration.

.NOTES
The long-support group contains Windows 11 Pro releases with at least one
calendar month of support remaining at the last recorded verification.
Consult the repository instructions when maintaining the release lists.
#>

$WIN_RELEASES_WITH_LONG_SUPPORT = @(
    '25H2',
    '26H1',
    '26H2'
)

$WIN_RELEASES_WITH_MEDIUM_SUPPORT = @()
