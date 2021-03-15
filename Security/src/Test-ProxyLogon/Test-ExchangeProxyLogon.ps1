function Test-ExchangeProxyLogon {
    <#
.SYNOPSIS
    Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.

.DESCRIPTION
    Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.

    Will do so in parallel if more than one server is specified, so long as names aren't provided by pipeline.
    The vulnerabilities are described in CVE-2021-26855, 26858, 26857, and 27065

.PARAMETER ComputerName
    The list of server names to scan for signs of compromise.
    Do not provide these by pipeline if you want parallel processing.

.PARAMETER Credential
    Credentials to use for remote connections.

.EXAMPLE
    PS C:\> Test-ExchangeProxyLogon

    Scans the current computer for signs of ProxyLogon vulnerability compromise.

.EXAMPLE
    PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn

    Scans all exchange servers in the organization for ProxyLogon vulnerability compromises
#>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ComputerName,

        [System.Management.Automation.PSCredential]
        $Credential
    )
    begin {
        #region Remoting Scriptblock
        $scriptBlock = {
            #region Functions
            function Get-ExchangeInstallPath {
                return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
            }

            function Get-Cve26855 {
                [CmdletBinding()]
                param ()

                $exchangePath = Get-ExchangeInstallPath
                if ($null -eq $exchangePath) {
                    Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26855 test."
                    return
                }

                $HttpProxyPath = Join-Path -Path $exchangePath -ChildPath "Logging\HttpProxy"
                $Activity = "Checking for CVE-2021-26855 in the HttpProxy logs"

                $outProps = @(
                    "DateTime", "RequestId", "ClientIPAddress", "UrlHost",
                    "UrlStem", "RoutingHint", "UserAgent", "AnchorMailbox",
                    "HttpStatus"
                )

                $files = (Get-ChildItem -Recurse -Path $HttpProxyPath -Filter '*.log').FullName

                $allResults = @{
                    Hits     = [System.Collections.ArrayList]@()
                    FileList = [System.Collections.ArrayList]@()
                }

                $progressId = [Math]::Abs(($env:COMPUTERNAME).GetHashCode())

                Write-Progress -Activity $Activity -Id $progressId

                $sw = New-Object System.Diagnostics.Stopwatch
                $sw.Start()

                For ( $i = 0; $i -lt $files.Count; ++$i ) {
                    if ($sw.ElapsedMilliseconds -gt 1000) {
                        Write-Progress -Activity $Activity -Status "$i / $($files.Count)" -PercentComplete ($i * 100 / $files.Count) -Id $progressId
                        $sw.Restart()
                    }

                    if ( ( Test-Path $files[$i] ) -and ( Select-String -Path $files[$i] -Pattern "ServerInfo~" -Quiet ) ) {
                        [Void]$allResults.FileList.Add( $files[$i] )

                        Import-Csv -Path $files[$i] -ErrorAction SilentlyContinue |
                            Where-Object { $_.AnchorMailbox -Like 'ServerInfo~*/*' -and $_.AnchorMailbox -notlike 'ServerInfo~*/autodiscover*' -and $_.AnchorMailbox -notlike 'ServerInfo~localhost*/*' } |
                            Select-Object -Property $outProps |
                            ForEach-Object {
                                [Void]$allResults.Hits.Add( $_ )
                            }
                    }
                }

                Write-Progress -Activity $Activity -Id $progressId -Completed

                return $allResults
            }

            function Get-Cve26857 {
                [CmdletBinding()]
                param ()
                try {
                    Get-WinEvent -FilterHashtable @{
                        LogName      = 'Application'
                        ProviderName = 'MSExchange Unified Messaging'
                        Level        = '2'
                    } -ErrorAction SilentlyContinue | Where-Object Message -Like "*System.InvalidCastException*"
                } catch {
                    Write-Host "  MSExchange Unified Messaging provider is not present or events not found in the Application Event log"
                }
            }

            function Get-Cve26858 {
                [CmdletBinding()]
                param ()

                $exchangePath = Get-ExchangeInstallPath
                if ($null -eq $exchangePath) {
                    Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26858 test."
                    return
                }

                Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path
            }

            function Get-Cve27065 {
                [CmdletBinding()]
                param ()

                $exchangePath = Get-ExchangeInstallPath
                if ($null -eq $exchangePath) {
                    Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-27065 test."
                    return
                }

                Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Select-String "Set-.+VirtualDirectory" -List | Select-Object -ExpandProperty Path
            }

            function Get-SuspiciousFile {
                [CmdletBinding()]
                param ()

                $zipFilter = ".7z", ".zip", ".rar"
                $dmpFilter = "lsass.*dmp"
                $dmpPaths = "c:\root", "$env:WINDIR\temp"

                Get-ChildItem -Path $dmpPaths -Filter $dmpFilter -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'LsassDump'
                            Path         = $_.FullName
                            Name         = $_.Name
                            LastWrite    = $_.LastWriteTimeUtc
                        }
                    }

                Get-ChildItem -Path $env:ProgramData -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        If ( $_.Extension -in $zipFilter ) {
                            [PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                Type         = 'SuspiciousArchive'
                                Path         = $_.FullName
                                Name         = $_.Name
                                LastWrite    = $_.LastWriteTimeUtc
                            }
                        }
                    }
            }

            function Get-AgeInDays {
                param ( $dateString )
                if ( $dateString -and $dateString -as [DateTime] ) {
                    $CURTIME = Get-Date
                    $age = $CURTIME.Subtract($dateString)
                    return $age.TotalDays.ToString("N1")
                }
                return ""
            }

            function Get-LogAge {
                [CmdletBinding()]
                param ()

                $exchangePath = Get-ExchangeInstallPath
                if ($null -eq $exchangePath) {
                    Write-Host "  Exchange 2013 or later not found. Skipping log age checks."
                    return $null
                }

                [PSCustomObject]@{
                    Oabgen           = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    Ecp              = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    AutodProxy       = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Autodiscover" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    EasProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Eas" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    EcpProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    EwsProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ews" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    MapiProxy        = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Mapi" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    OabProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Oab" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    OwaProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Owa" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    OwaCalendarProxy = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\OwaCalendar" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    PowershellProxy  = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\PowerShell" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    RpcHttpProxy     = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\RpcHttp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                }
            }
            #endregion Functions

            $results = [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Cve26855     = Get-Cve26855
                Cve26857     = @(Get-Cve26857)
                Cve26858     = @(Get-Cve26858)
                Cve27065     = @(Get-Cve27065)
                Suspicious   = @(Get-SuspiciousFile)
                LogAgeDays   = Get-LogAge
                IssuesFound  = $false
            }

            if ($results.Cve26855.Hits.Count -or $results.Cve26857.Count -or $results.Cve26858.Count -or $results.Cve27065.Count -or $results.Suspicious.Count) {
                $results.IssuesFound = $true
            }

            $results
        }
        #endregion Remoting Scriptblock
        $parameters = @{
            ScriptBlock = $scriptBlock
        }
        if ($Credential) { $parameters['Credential'] = $Credential }
    }
    process {
        if ($null -ne $ComputerName) {
            Invoke-Command @parameters -ComputerName $ComputerName
        } else {
            Invoke-Command @parameters
        }
    }
}
