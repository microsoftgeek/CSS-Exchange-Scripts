[CmdletBinding()]
param (

)
Install-Module Pester -Force -SkipPublisherCheck
Install-Module az.resources -scope currentuser -force -SkipPublisherCheck
Install-Module az.accounts -Scope CurrentUser -Force -SkipPublisherCheck


$repoRoot = Get-Item "$PSScriptRoot\.."

$scriptFiles = Get-ChildItem -Path $repoRoot -Directory |
    Where-Object { $_.Name -ne ".build" } |
    ForEach-Object { Get-ChildItem -Path $_.FullName *.ps1 -Recurse } |
    Where-Object { $_.Name.Contains(".Tests.ps1") }
    Sort-Object Name |
    ForEach-Object { return $_.FullName }

$scriptFiles |
    ForEach-Object {
        if ($null -ne $_.FullName) {
            Write-Host "Working on file $($_.FullName)"
            Invoke-Pester -Script $_.FullName
        } else {
            Write-Host "Working on file $_"
            Invoke-Pester -Script $_
        }
    }