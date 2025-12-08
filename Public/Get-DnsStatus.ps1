function Get-DnsStatus {
    <#
    .SYNOPSIS
        Reports the DNS Scavenging (Janitor) status.

    .DESCRIPTION
        Retrieves DNS Scavenging configuration for servers and displays them in a left-aligned table.
        
    .PARAMETER ComputerName
        A list of DNS servers to check. Defaults to all Domain Controllers (FQDNs).
        
    .PARAMETER Exclude
        A list of Server Names to exclude. 
        Accepts Short Names (e.g., 'DC01') or FQDNs.

    .EXAMPLE
        Get-DnsStatus -Exclude "AWSDC01"
        
        This will filter out "AWSDC01" AND "AWSDC01.mekorot.co.il".
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName = (Get-ADDomainController -Filter *).HostName,

        [Parameter(HelpMessage = "List of servers to skip (e.g., 'DC05','DC06')")]
        [string[]]$Exclude
    )

    process {
        # 1. SMART FILTERING
        # We filter the list. We check if the Server Name is exactly the excluded string
        # OR if the Server Name starts with the excluded string followed by a dot (handling FQDNs).
        $TargetServers = $ComputerName | Where-Object { 
            $CurrentServer = $_
            $ShouldExclude = $false

            if ($Exclude) {
                foreach ($Item in $Exclude) {
                    if ($CurrentServer -eq $Item -or $CurrentServer -like "$Item.*") {
                        $ShouldExclude = $true
                        break
                    }
                }
            }
            # Return $true to keep the server, $false to skip it
            -not $ShouldExclude 
        }

        # 2. Accumulate Results
        $Results = foreach ($Server in $TargetServers) {
            try {
                $DnsSettings = Get-DnsServerScavenging -ComputerName $Server -ErrorAction Stop

                [PSCustomObject]@{
                    'Server Name'              = $Server
                    'Janitor'                  = $DnsSettings.ScavengingState
                    'Server Scavenging Period' = $DnsSettings.ScavengingInterval
                    'Default No-Refresh'       = $DnsSettings.NoRefreshInterval
                    'Default Refresh'          = $DnsSettings.RefreshInterval
                }
            }
            catch {
                Write-Warning "Could not connect to DNS on '$Server': $($_.Exception.Message)"
                
                [PSCustomObject]@{
                    'Server Name'              = $Server
                    'Janitor'                  = "ERROR"
                    'Server Scavenging Period' = $null
                    'Default No-Refresh'       = $null
                    'Default Refresh'          = $null
                }
            }
        }

        # 3. Output with Forced Left Alignment
        # Using Format-Table with explicit left alignment for every column
        if ($Results) {
            $Results | Format-Table @{Label='Server Name'; Expression={$_.'Server Name'}; Alignment='Left'},
                                    @{Label='Janitor'; Expression={$_.'Janitor'}; Alignment='Left'},
                                    @{Label='Server Scavenging Period'; Expression={$_.'Server Scavenging Period'}; Alignment='Left'},
                                    @{Label='Default No-Refresh'; Expression={$_.'Default No-Refresh'}; Alignment='Left'},
                                    @{Label='Default Refresh'; Expression={$_.'Default Refresh'}; Alignment='Left'} -AutoSize
        }
    }
}