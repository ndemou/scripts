<#
A collection of helper functions for handling files
#>

function Get-HardLinks {
<# 
.SYNOPSIS
Lists files in the current directory that have >1 hardlink, and shows all link paths
.EXAMPLE
Get-HardLinks|Format-List
#>
    Get-ChildItem -File | ForEach-Object {
      $links = & fsutil hardlink list $_.FullName 2>$null
      if ($LASTEXITCODE -eq 0 -and $links.Count -gt 1) {
        [pscustomobject]@{
          File      = $_.Name
          LinkCount = $links.Count
          Links     = ($links -join "`n")
        }
      }
    } 
}