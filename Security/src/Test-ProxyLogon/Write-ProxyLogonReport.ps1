function Write-ProxyLogonReport {
    <#
.SYNOPSIS
    Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

.DESCRIPTION
    Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

.PARAMETER InputObject
    The reports provided by Test-ExchangeProxyLogon

.PARAMETER OutPath
    Path to a FOLDER in which to generate output logfiles.
    This command will only write to the console screen if no path is provided.

.EXAMPLE
    PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn | Write-ProxyLogonReport -OutPath C:\logs

    Gather data from all exchange servers in the organization and write a report to C:\logs
#>
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline = $true)]
        $InputObject,

        [string]
        $OutPath = "$PSScriptRoot\Test-ProxyLogonLogs",

        [switch]
        $DisplayOnly,

        [switch]
        $CollectFiles
    )

    begin {
        if ($OutPath -and -not $DisplayOnly) {
            New-Item $OutPath -ItemType Directory -Force | Out-Null
        }
    }

    process {
        foreach ($report in $InputObject) {

            $isLocalMachine = $report.ComputerName -eq $env:COMPUTERNAME

            if ($CollectFiles) {
                $LogFileOutPath = $OutPath + "\CollectedLogFiles\" + $report.ComputerName
                if (-not (Test-Path -Path $LogFileOutPath)) {
                    New-Item $LogFileOutPath -ItemType Directory -Force | Out-Null
                }
            }

            Write-Host "ProxyLogon Status: Exchange Server $($report.ComputerName)"

            if ($null -ne $report.LogAgeDays) {
                Write-Host ("  Log age days: Oabgen {0} Ecp {1} Autod {2} Eas {3} EcpProxy {4} Ews {5} Mapi {6} Oab {7} Owa {8} OwaCal {9} Powershell {10} RpcHttp {11}" -f `
                        $report.LogAgeDays.Oabgen, `
                        $report.LogAgeDays.Ecp, `
                        $report.LogAgeDays.AutodProxy, `
                        $report.LogAgeDays.EasProxy, `
                        $report.LogAgeDays.EcpProxy, `
                        $report.LogAgeDays.EwsProxy, `
                        $report.LogAgeDays.MapiProxy, `
                        $report.LogAgeDays.OabProxy, `
                        $report.LogAgeDays.OwaProxy, `
                        $report.LogAgeDays.OwaCalendarProxy, `
                        $report.LogAgeDays.PowershellProxy, `
                        $report.LogAgeDays.RpcHttpProxy)

                if (-not $DisplayOnly) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-LogAgeDays.csv"
                    $report.LogAgeDays | Export-Csv -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                }
            }

            if (-not $report.IssuesFound) {
                Write-Host "  Nothing suspicious detected" -ForegroundColor Green
                Write-Host ""
                continue
            }
            if ($report.Cve26855.Hits.Count -gt 0) {
                Write-Host "  [CVE-2021-26855] Suspicious activity found in Http Proxy log!" -ForegroundColor Red
                if (-not $DisplayOnly) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26855.csv"
                    $report.Cve26855.Hits | Export-Csv -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                } else {
                    $report.Cve26855.Hits | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                }
                if ($CollectFiles -and $isLocalMachine) {
                    Write-Host " Copying Files:"
                    if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26855")) {
                        Write-Host " Creating CVE26855 Collection Directory"
                        New-Item "$($LogFileOutPath)\CVE26855" -ItemType Directory -Force | Out-Null
                    }
                    foreach ($entry in $report.Cve26855.FileList) {
                        if (Test-Path -Path $entry) {
                            Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE26855" -ForegroundColor Green
                            Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE26855"
                        } else {
                            Write-Host "  Warning: Unable to copy file $($entry). File does not exist." -ForegroundColor Red
                        }
                    }
                }
                Write-Host ""
            }
            if ($report.Cve26857.Count -gt 0) {
                Write-Host "  [CVE-2021-26857] Suspicious activity found in Eventlog!" -ForegroundColor Red
                Write-Host "  $(@($report.Cve26857).Count) events found"
                if (-not $DisplayOnly) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26857.csv"
                    $report.Cve26857 | Select-Object TimeCreated, MachineName, Message | Export-Csv -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                }

                if ($CollectFiles -and $isLocalMachine) {
                    Write-Host "`n`r Copying Application Event Log"
                    if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26857")) {
                        Write-Host "  Creating CVE26857 Collection Directory"
                        New-Item "$($LogFileOutPath)\CVE26857" -ItemType Directory -Force | Out-Null
                    }

                    Start-Process wevtutil -ArgumentList "epl Software $($LogFileOutPath)\CVE26857\Application.evtx"
                }
                Write-Host ""
            }
            if ($report.Cve26858.Count -gt 0) {
                Write-Host "  [CVE-2021-26858] Suspicious activity found in OAB generator logs!" -ForegroundColor Red
                Write-Host "  Please review the following files for 'Download failed and temporary file' entries:"
                foreach ($entry in $report.Cve26858) {
                    Write-Host "   $entry"
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE26858")) {
                            Write-Host " Creating CVE26858 Collection Directory`n`r"
                            New-Item "$($LogFileOutPath)\CVE26858" -ItemType Directory -Force | Out-Null
                        }
                        if (Test-Path -Path $entry) {
                            Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE26858" -ForegroundColor Green
                            Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE26858"
                        } else {
                            Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist.`n`r " -ForegroundColor Red
                        }
                    }
                }
                if (-not $DisplayOnly) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858.log"
                    $report.Cve26858 | Set-Content -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                }
                Write-Host ""
            }
            if ($report.Cve27065.Count -gt 0) {
                Write-Host "  [CVE-2021-27065] Suspicious activity found in ECP logs!" -ForegroundColor Red
                Write-Host "  Please review the following files for 'Set-*VirtualDirectory' entries:"
                foreach ($entry in $report.Cve27065) {
                    Write-Host "   $entry"
                    if ($CollectFiles -and $isLocalMachine) {
                        Write-Host " Copying Files:"
                        if (-not (Test-Path -Path "$($LogFileOutPath)\CVE27065")) {
                            Write-Host " Creating CVE27065 Collection Directory"
                            New-Item "$($LogFileOutPath)\CVE27065" -ItemType Directory -Force | Out-Null
                        }
                        if (Test-Path -Path $entry) {
                            Write-Host "  Copying $($entry) to $($LogFileOutPath)\CVE27065" -ForegroundColor Green
                            Copy-Item -Path $entry -Destination "$($LogFileOutPath)\CVE27065"
                        } else {
                            Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist." -ForegroundColor Red
                        }
                    }
                }
                if (-not $DisplayOnly) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065.log"
                    $report.Cve27065 | Set-Content -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                }
                Write-Host ""
            }
            if ($report.Suspicious.Count -gt 0) {
                Write-Host "  Other suspicious files found: $(@($report.Suspicious).Count)"
                if (-not $DisplayOnly) {
                    $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-other.csv"
                    $report.Suspicious | Export-Csv -Path $newFile
                    Write-Host "  Report exported to: $newFile"
                } else {
                    foreach ($entry in $report.Suspicious) {
                        Write-Host "   $($entry.Type) : $($entry.Path)"
                    }
                }
                if ($CollectFiles -and $isLocalMachine) {
                    Write-Host " Copying Files:"

                    #Deleting and recreating suspiciousFiles folder to prevent overwrite exceptions due to folders (folder name: myfolder.zip)
                    if ( Test-Path -Path "$($LogFileOutPath)\SuspiciousFiles" ) {
                        Remove-Item -Path "$($LogFileOutPath)\SuspiciousFiles" -Recurse -Force
                    }
                    Write-Host "  Creating SuspiciousFiles Collection Directory"
                    New-Item "$($LogFileOutPath)\SuspiciousFiles" -ItemType Directory -Force | Out-Null

                    $fileNumber = 0
                    foreach ($entry in $report.Suspicious) {
                        if (Test-Path -Path $entry.path) {
                            Write-Host "  Copying $($entry.Path) to $($LogFileOutPath)\SuspiciousFiles" -ForegroundColor Green
                            Copy-Item -Path $entry.Path -Destination "$($LogFileOutPath)\SuspiciousFiles\$($entry.Name)_$fileNumber"
                            $fileNumber += 1
                        } else {
                            Write-Host "  Warning: Unable to copy file $($entry.Path). File does not exist." -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }
}
