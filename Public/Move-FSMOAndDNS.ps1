function Move-FSMOAndDNS {
    <#
    .SYNOPSIS
        Transfers FSMO roles and relocates the DNS Scavenging (Janitor) responsibility.

    .DESCRIPTION
        This function moves Active Directory FSMO roles and the DNS Scavenging service.
        
        Features:
        1. Auto-Detection: Automatically scans the domain to find the current DNS Janitor(s) and disables them.
        2. Flexible Targeting: 
           - 'AllToOne' mode moves everything to a single server.
           - 'Granular' mode allows specifying a unique destination for every role.
        3. Configuration: Sets the new Janitor to a 3-day scavenging interval.

    .PARAMETER DestinationServer
        (Parameter Set: AllToOne)
        The server that will receive ALL FSMO roles and become the new DNS Janitor.

    .PARAMETER PDCMaster
        (Parameter Set: Granular)
        Target for the PDC Emulator role.

    .PARAMETER RIDMaster
        (Parameter Set: Granular)
        Target for the RID Master role.

    .PARAMETER InfrastructureMaster
        (Parameter Set: Granular)
        Target for the Infrastructure Master role.

    .PARAMETER SchemaMaster
        (Parameter Set: Granular)
        Target for the Schema Master role.

    .PARAMETER DomainNamingMaster
        (Parameter Set: Granular)
        Target for the Domain Naming Master role.

    .PARAMETER DNSJanitorTarget
        (Parameter Set: Granular)
        Target for the DNS Scavenging role.

    .EXAMPLE
        Move-FSMOAndDNS -DestinationServer "DC02"
        
        Auto-detects current Janitor, disables it, moves all FSMO to DC02, and enables Janitor on DC02.

    .EXAMPLE
        Move-FSMOAndDNS -PDCMaster "DC01" -RIDMaster "DC01" -InfrastructureMaster "DC02" -SchemaMaster "DC01" -DomainNamingMaster "DC01" -DNSJanitorTarget "DC03"
        
        Moves roles to specific locations. DC03 becomes the new DNS Janitor.
    #>
    [CmdletBinding(DefaultParameterSetName = "AllToOne", SupportsShouldProcess = $true)]
    param(
        # --- Parameter Set: All To One ---
        [Parameter(Mandatory = $true, ParameterSetName = "AllToOne", HelpMessage = "Destination for ALL FSMO roles and DNS Janitor")]
        [string]$DestinationServer,

        # --- Parameter Set: Granular ---
        [Parameter(Mandatory = $true, ParameterSetName = "Granular")]
        [string]$PDCMaster,

        [Parameter(Mandatory = $true, ParameterSetName = "Granular")]
        [string]$RIDMaster,

        [Parameter(Mandatory = $true, ParameterSetName = "Granular")]
        [string]$InfrastructureMaster,

        [Parameter(Mandatory = $true, ParameterSetName = "Granular")]
        [string]$SchemaMaster,

        [Parameter(Mandatory = $true, ParameterSetName = "Granular")]
        [string]$DomainNamingMaster,

        [Parameter(Mandatory = $true, ParameterSetName = "Granular", HelpMessage = "Server that will take over DNS Scavenging")]
        [string]$DNSJanitorTarget
    )

    process {
        # 1. Validation: Check Modules
        if (-not (Get-Module -Name ActiveDirectory)) { Import-Module ActiveDirectory -ErrorAction Stop }
        if (-not (Get-Module -Name DnsServer)) { Import-Module DnsServer -ErrorAction Stop }

        Write-Host "--- ADUtils Role Migration ---" -ForegroundColor Cyan

        # ---------------------------------------------------------
        # PHASE 1: Detect Current Janitor(s)
        # ---------------------------------------------------------
        Write-Host "Detecting current DNS Janitor servers..." -NoNewline
        $AllDCs = (Get-ADDomainController -Filter *).HostName
        $CurrentJanitors = @()

        foreach ($DC in $AllDCs) {
            try {
                $Settings = Get-DnsServerScavenging -ComputerName $DC -ErrorAction Stop
                if ($Settings.ScavengingState -eq $true) {
                    $CurrentJanitors += $DC
                }
            }
            catch {
                Write-Verbose "Could not check DNS on $DC. Skipping."
            }
        }

        if ($CurrentJanitors.Count -eq 0) {
            Write-Host " None Found (Fresh Setup)" -ForegroundColor Yellow
        }
        else {
            Write-Host " Found: $($CurrentJanitors -join ', ')" -ForegroundColor Yellow
        }

        # ---------------------------------------------------------
        # PHASE 2: Map Targets
        # ---------------------------------------------------------
        $FsmoMoves = @{}
        $TargetDNS = $null

        if ($PSCmdlet.ParameterSetName -eq "AllToOne") {
            Write-Verbose "Mode: AllToOne -> Targeting $DestinationServer"
            $FsmoMoves.Add("PDCEmulator", $DestinationServer)
            $FsmoMoves.Add("RIDMaster", $DestinationServer)
            $FsmoMoves.Add("InfrastructureMaster", $DestinationServer)
            $FsmoMoves.Add("SchemaMaster", $DestinationServer)
            $FsmoMoves.Add("DomainNamingMaster", $DestinationServer)
            $TargetDNS = $DestinationServer
        }
        else {
            Write-Verbose "Mode: Granular"
            $FsmoMoves.Add("PDCEmulator", $PDCMaster)
            $FsmoMoves.Add("RIDMaster", $RIDMaster)
            $FsmoMoves.Add("InfrastructureMaster", $InfrastructureMaster)
            $FsmoMoves.Add("SchemaMaster", $SchemaMaster)
            $FsmoMoves.Add("DomainNamingMaster", $DomainNamingMaster)
            $TargetDNS = $DNSJanitorTarget
        }

        # ---------------------------------------------------------
        # PHASE 3: Move FSMO Roles
        # ---------------------------------------------------------
        Write-Host "`n--- Moving FSMO Roles ---" -ForegroundColor Cyan
        
        foreach ($Role in $FsmoMoves.Keys) {
            $Target = $FsmoMoves[$Role]
            
            # Identify current holder
            $CurrentHolder = (Get-ADDomain).$Role
            if (-not $CurrentHolder) { $CurrentHolder = (Get-ADForest).$Role }

            if ($CurrentHolder -match $Target) {
                Write-Host "Skipping $Role - Already on $Target" -ForegroundColor Gray
            }
            else {
                if ($PSCmdlet.ShouldProcess("$Target", "Transfer FSMO Role: $Role (From: $CurrentHolder)")) {
                    Try {
                        Write-Host "Moving $Role to $Target..." -NoNewline
                        Move-ADDirectoryServerOperationMasterRole -Identity $Target -OperationMasterRole $Role -Confirm:$false -Force -ErrorAction Stop
                        Write-Host " [OK]" -ForegroundColor Green
                    }
                    Catch {
                        Write-Host " [FAILED]" -ForegroundColor Red
                        Write-Error "Error moving $Role : $($_.Exception.Message)"
                    }
                }
            }
        }

        # ---------------------------------------------------------
        # PHASE 4: Move DNS Janitor
        # ---------------------------------------------------------
        Write-Host "`n--- Moving DNS Janitor Role ---" -ForegroundColor Cyan
        
        # A. Disable OLD Janitors (detected in Phase 1)
        foreach ($OldJanitor in $CurrentJanitors) {
            # Skip if the detected janitor IS the new target (we will handle enabling it in Step B)
            if ($OldJanitor -eq $TargetDNS) { continue }

            if ($PSCmdlet.ShouldProcess("$OldJanitor", "Disable DNS Scavenging (Stop Old Janitor)")) {
                Try {
                    $ZeroTime = New-TimeSpan -Seconds 0
                    Set-DnsServerScavenging -ComputerName $OldJanitor -ScavengingState $false -ScavengingInterval $ZeroTime -ErrorAction Stop
                    Write-Host "Disabled Scavenging on: $OldJanitor" -ForegroundColor Green
                }
                Catch {
                    Write-Error "Failed to disable scavenging on $OldJanitor : $_"
                }
            }
        }

        # B. Enable NEW Target
        if ($PSCmdlet.ShouldProcess("$TargetDNS", "Enable DNS Scavenging (Interval: 3 Days)")) {
            Try {
                $Interval = New-TimeSpan -Days 3
                Set-DnsServerScavenging -ComputerName $TargetDNS -ScavengingState $true -ScavengingInterval $Interval -ErrorAction Stop
                Write-Host "Enabled Scavenging on Target: $TargetDNS (Interval: 3 Days)" -ForegroundColor Green
            }
            Catch {
                Write-Error "Failed to enable scavenging on $TargetDNS : $_"
            }
        }
        
        Write-Host "`nMigration Complete." -ForegroundColor Cyan
    }
}