function Get-DomainControllerBuild {
    <#
    .SYNOPSIS
        Retrieves the full Windows Build version (including UBR) from Domain Controllers.

    .DESCRIPTION
        This function queries Domain Controllers to retrieve OS Version and Update Build Revision (UBR).
        It supports querying by specific Active Directory Site, the entire domain, or a specific list of servers.
        It uses parallel processing (Invoke-Command) for high performance.

    .PARAMETER ComputerName
        A specific list of Domain Controller names to query.
        Cannot be used with -SiteName or -Exclude.

    .PARAMETER SiteName
        The Active Directory Site name to target. If omitted, targets all DCs in the domain.
    
    .PARAMETER Exclude
        A list of Domain Controller names (HostName or simple Name) to exclude from the report.
        Only available when querying via AD (Site or All), not when using -ComputerName.

    .PARAMETER SortBy
        The property to sort by. Options: "DCName" or "FullBuild" (default).

    .PARAMETER SortOrder
        The direction of the sort. Options: "Ascend" (default) or "Descend".

    .EXAMPLE
        Get-DomainControllerBuild
        Returns build info for all DCs in the domain.

    .EXAMPLE
        Get-DomainControllerBuild -SiteName "HQ-Site" -Exclude "DC05"
        Returns build info for DCs in "HQ-Site", excluding DC05.

    .EXAMPLE
        Get-DomainControllerBuild -ComputerName "DC01", "DC02"
        Returns build info only for the specific servers listed.
    #>
    [CmdletBinding(DefaultParameterSetName = 'QueryAD')]
    param (
        # Parameter Set: Direct List of Servers
        [Parameter(ParameterSetName = 'DirectList', Mandatory = $true, Position = 0)]
        [string[]]$ComputerName,

        # Parameter Set: Query AD (By Site or All)
        [Parameter(ParameterSetName = 'QueryAD')]
        [string]$SiteName,

        [Parameter(ParameterSetName = 'QueryAD')]
        [string[]]$Exclude,

        # Common Parameters
        [Parameter(ParameterSetName = 'QueryAD')]
        [Parameter(ParameterSetName = 'DirectList')]
        [ValidateSet('DCName', 'FullBuild', 'IPAddress')]
        [string]$SortBy = 'FullBuild',

        [Parameter(ParameterSetName = 'QueryAD')]
        [Parameter(ParameterSetName = 'DirectList')]
        [ValidateSet('Ascend', 'Descend')]
        [string]$SortOrder = 'Ascend'
    )

    process {
        $TargetList = @()

        # --- LOGIC BRANCH 1: User provided specific server names ---
        if ($PSCmdlet.ParameterSetName -eq 'DirectList') {
            Write-Verbose "Targeting specific server list: $($ComputerName -join ', ')"
            $TargetList = $ComputerName
        }
        
        # --- LOGIC BRANCH 2: User wants to query AD (Site or All) ---
        else {
            Write-Verbose "Retrieving list of Domain Controllers from Active Directory..."
            
            try {
                if ($SiteName) {
                    Write-Verbose "Filter: Site '$SiteName'"
                    $DCs = Get-ADDomainController -Filter { Site -eq $SiteName } -ErrorAction Stop
                }
                else {
                    Write-Verbose "Filter: All Domain Controllers"
                    $DCs = Get-ADDomainController -Filter * -ErrorAction Stop
                }
            }
            catch {
                Write-Error "Failed to retrieve Domain Controllers. $_"
                return
            }

            # Filter out excluded DCs
            if ($Exclude) {
                Write-Verbose "Excluding: $($Exclude -join ', ')"
                $DCs = $DCs | Where-Object { 
                    $Exclude -notcontains $_.Name -and $Exclude -notcontains $_.HostName 
                }
            }

            if ($DCs.Count -eq 0) {
                Write-Warning "No Domain Controllers found matching criteria."
                return
            }

            $TargetList = $DCs.HostName
        }

        # --- EXECUTION: Parallel Processing ---
        Write-Verbose "Querying $($TargetList.Count) servers..."

        $Results = Invoke-Command -ComputerName $TargetList -ErrorAction SilentlyContinue -ScriptBlock {
            try {
                # Get OS Version from CIM/WMI
                $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                
                # Get UBR from Registry
                $UBRKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
                $UBR = $UBRKey.UBR

                # Get IP Address (Primary IPv4)
                $IP = (Get-CimInstance Win32_NetworkAdapterConfiguration | 
                      Where-Object { $_.IPEnabled -eq $true }).IPAddress | 
                      Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } | 
                      Select-Object -First 1

                [PSCustomObject]@{
                    DCName    = $env:COMPUTERNAME
                    IPAddress = $IP
                    FullBuild = "$($OS.Version).$UBR"
                }
            }
            catch {
                Write-Warning "$($env:COMPUTERNAME): $($_.Exception.Message)"
            }
        }

        # --- OUTPUT & SORTING ---
        $SortProperty = if ($SortBy -eq 'FullBuild') { 
            { [version]$_.FullBuild } 
        } else { 
            $SortBy 
        }

        $Results | Select-Object DCName, IPAddress, FullBuild | 
                   Sort-Object -Property $SortProperty -Descending:($SortOrder -eq 'Descend') | 
                   Format-Table -AutoSize
    }
}