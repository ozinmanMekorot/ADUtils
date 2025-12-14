function Get-ADUDomainControllerBuild {
    <#
    .SYNOPSIS
        Retrieves the full Windows Build version (including UBR) from Domain Controllers.

    .DESCRIPTION
        This function queries Domain Controllers to retrieve OS Version and Update Build Revision (UBR).
        It supports querying by specific Active Directory Site, the entire domain, or a specific list of servers.
        
        *Update*: Handles connection errors by listing them as "Error" and ensures DC names are consistently formatted (short names).

    .PARAMETER ComputerName
        A specific list of Domain Controller names to query.
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

            # We use HostName (FQDN) for the connection to be safe, but we will clean up the display later
            $TargetList = $DCs.HostName
        }

        # --- EXECUTION: Parallel Processing ---
        Write-Verbose "Querying $($TargetList.Count) servers..."

        # Use SilentlyContinue so we can handle the missing ones manually
        $Results = Invoke-Command -ComputerName $TargetList -ErrorAction SilentlyContinue -ScriptBlock {
            try {
                $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $UBRKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
                $UBR = $UBRKey.UBR

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
                # Internal script block error (Connection succeeded, but execution failed)
                [PSCustomObject]@{
                    DCName    = $env:COMPUTERNAME
                    IPAddress = "Check Access"
                    FullBuild = "Error"
                }
            }
        }

        # --- ERROR HANDLING: Detect Connection Failures ---
        $RespondingHosts = $Results.PSComputerName
        $FailedHosts = $TargetList | Where-Object { $RespondingHosts -notcontains $_ }

        $ErrorRecords = foreach ($FailedDC in $FailedHosts) {
            # FIX: Split the string on '.' and take the first part to ensure we only show Hostname, not FQDN
            $ShortName = $FailedDC.Split('.')[0]

            [PSCustomObject]@{
                DCName    = $ShortName
                IPAddress = "-"
                FullBuild = "Error"
            }
        }

        # Merge successful results with error records
        $FinalOutput = $Results + $ErrorRecords

        # --- OUTPUT & SORTING ---
        $SortProperty = if ($SortBy -eq 'FullBuild') { 
            { 
                if ($_.FullBuild -match '^\d') { 
                    [version]$_.FullBuild 
                } else { 
                    [version]"0.0" 
                }
            } 
        } else { 
            $SortBy 
        }

        $FinalOutput | Select-Object DCName, IPAddress, FullBuild | 
                       Sort-Object -Property $SortProperty -Descending:($SortOrder -eq 'Descend') | 
                       Format-Table -AutoSize
    }
}