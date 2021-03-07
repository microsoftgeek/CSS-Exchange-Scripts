[CmdletBinding()]
param (

)

$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { $_.Name -ne ".build" } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } |
    Where-Object { $_.Name.Contains(".Tests.ps1") }
    Sort-Object Name |
    ForEach-Object { $_.FullName }

$scriptFiles |
    ForEach-Object {
        Write-Host "Working on file $_"
        Invoke-Pester -Script $_
    }