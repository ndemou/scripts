function sed {
<#
.SYNOPSIS
Performs an in-place search and replace on a text file (similar to Linux sed -i).

.DESCRIPTION
Reads the contents of the specified file, performs a search and replace,
and writes the modified contents back to the same file in UTF-8 encoding.
By default, the search pattern is treated as a regular expression.
Use -Literal to match the pattern as plain text.

.PARAMETER File
The path to the text file to modify.

.PARAMETER Pattern
The text or regex pattern to search for.

.PARAMETER Replacement
The replacement text to insert in place of matches.

.PARAMETER Literal
If specified, the search pattern will be treated as literal text instead of regex.

.EXAMPLE
sed 'file.txt' 'old' 'new'
Replaces all occurrences of "old" with "new" in file.txt (regex mode).

.EXAMPLE
sed 'file.txt' '\d+' 'NUMBER'
Replaces all numbers with the text "NUMBER" in file.txt (regex mode).

.EXAMPLE
sed 'file.txt' 'e.t.c.' 'etc.' -Literal
Replaces the literal string "e.t.c." with "etc." in file.txt.

.NOTES
Without -Literal, the -replace operator uses regex syntax.
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]$File,

        [Parameter(Mandatory=$true)]
        [string]$Pattern,

        [Parameter(Mandatory=$true)]
        [string]$Replacement,

        [switch]$Literal
    )

    if ($Literal) {
        $Pattern = [regex]::Escape($Pattern)
    }

    (Get-Content $File -Raw) -replace $Pattern, $Replacement |
        Set-Content $File -Encoding utf8
}
