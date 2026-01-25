function New-ADUgMSA {
    <#
    .SYNOPSIS
        Creates a Group Managed Service Account (gMSA), a corresponding security group, 
        and generates a setup script for the target servers.

    .DESCRIPTION
        This function orchestrates the creation of a gMSA environment with strict Domain Controller affinity.
        
        Improvements in this version:
        1. Resolves Computer Names to Distinguished Names (DN) to ensure robust group addition.
        2. Uses "Try-Create" logic for gMSA to avoid "Object Not Found" errors during pre-checks.
        3. Locks all operations to a single Domain Controller to prevent replication latency.

    .PARAMETER ApplicationName
        The base name of the application (e.g., "IISProd"). 
        Used to generate the Service Name (IISProdSVC) and Group Name.

    .PARAMETER ComputerNames
        An array of computer names (NetBIOS or FQDN) that will host this service.
        These computers will be added to the security group.

    .EXAMPLE
        New-ADUgMSA -ApplicationName "SQLApp" -ComputerNames "SQL01", "SQL02"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$ApplicationName,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String[]]$ComputerNames
    )

    begin {
        # --- Configuration Constants ---
        $DomainSuffix     = "MEKOROT.CO.IL"
        $BaseDC           = "DC=mekorot,DC=co,DC=il"
        $gMSA_OU          = "OU=Managed Service Accounts,$BaseDC"
        $Group_OU         = "OU=gMSA Computer Groups,OU=Applications,$BaseDC"
        $ScriptExportPath = "C:\gmsa_scripts"

        # --- DC Affinity Selection ---
        try {
            # Select the first writeable DC and force it to a string
            $DCInfo = Get-ADDomainController -Discover -Writable | Select-Object -First 1
            [string]$TargetDC = $DCInfo.HostName

            if ([string]::IsNullOrWhiteSpace($TargetDC)) { Throw "Hostname is empty" }
            Write-Verbose "DC Affinity Locked: Operations will be performed on $TargetDC"
        }
        catch {
            Throw "Could not locate a writeable Domain Controller. Error: $_"
        }
    }

    process {
        # --- Name Calculations ---
        $ServiceName = "${ApplicationName}SVC"
        $DNSHostName = "${ServiceName}.$DomainSuffix"
        $GroupName   = "G-${ApplicationName}-COMPUTERS-USING-GMSA-${ServiceName}"

        Write-Verbose "Processing Service: $ServiceName"
        Write-Verbose "Processing Group:   $GroupName"

        try {
            # -----------------------------------------------------------
            # 1. Create Security Group
            # -----------------------------------------------------------
            $GroupParams = @{
                Name          = $GroupName
                GroupScope    = 'Global'
                GroupCategory = 'Security'
                Path          = $Group_OU
                Description   = "Computer Members of this group can use gMSA $ServiceName"
                Server        = $TargetDC
            }

            # Holder for the Group Distinguished Name
            $GroupDN = $null

            # Try to get the group first
            try {
                $ExistingGroup = Get-ADGroup -Identity $GroupName -Server $TargetDC -ErrorAction Stop
                $GroupDN = $ExistingGroup.DistinguishedName
                Write-Warning "Group '$GroupName' already exists. Using existing group."
            }
            catch {
                # Group does not exist, create it
                if ($PSCmdlet.ShouldProcess($GroupName, "Create AD Security Group on $TargetDC")) {
                    $NewGroup = New-ADGroup @GroupParams -PassThru
                    $GroupDN = $NewGroup.DistinguishedName
                    Write-Host "Created Group: $GroupName" -ForegroundColor Cyan
                }
            }

            # If WhatIf mode, create a fake DN so the script continues
            if ($PSCmdlet.ParameterSetName -eq 'WhatIf' -and -not $GroupDN) {
                $GroupDN = "CN=$GroupName,$Group_OU"
            }

            # -----------------------------------------------------------
            # 2. Add Computers to Group (Robust Resolution)
            # -----------------------------------------------------------
            if ($GroupDN) {
                foreach ($ComputerName in $ComputerNames) {
                    if ($PSCmdlet.ShouldProcess($ComputerName, "Add to Group $GroupName on $TargetDC")) {
                        try {
                            # NEW: Resolve the string to a real AD Computer Object first
                            # We search by Name (NetBIOS) to be safe.
                            $CompObj = Get-ADComputer -Filter "Name -eq '$ComputerName'" -Server $TargetDC -ErrorAction Stop | Select-Object -First 1
                            
                            if ($CompObj) {
                                # Add using the safe DistinguishedName
                                Add-ADGroupMember -Identity $GroupDN -Members $CompObj.DistinguishedName -Server $TargetDC -ErrorAction Stop
                                Write-Verbose "Added $($CompObj.Name) to group."
                            }
                            else {
                                Write-Error "Computer '$ComputerName' was not found in AD on $TargetDC. Please check the name."
                            }
                        }
                        catch {
                            Write-Error "Failed to add '$ComputerName' to group on $TargetDC. Error: $_"
                        }
                    }
                }
            }

            # -----------------------------------------------------------
            # 3. Create gMSA (Try/Catch Pattern)
            # -----------------------------------------------------------
            $ServiceParams = @{
                Name        = $ServiceName
                DNSHostName = $DNSHostName
                Path        = $gMSA_OU
                Description = "Group Managed Service Account for $ApplicationName. Allowed Hosts: $GroupName"
                PrincipalsAllowedToRetrieveManagedPassword = $GroupDN 
                Enabled     = $true
                Server      = $TargetDC
            }

            if ($PSCmdlet.ShouldProcess($ServiceName, "Create gMSA Account on $TargetDC")) {
                try {
                    # We try to create immediately. If it exists, it throws an error we catch.
                    # This avoids the "Cannot find object" error when checking for non-existent accounts.
                    New-ADServiceAccount @ServiceParams -ErrorAction Stop
                    Write-Host "Successfully created gMSA: $ServiceName" -ForegroundColor Green
                }
                catch {
                    if ($_.Exception.Message -like "*already exists*") {
                        Write-Warning "gMSA '$ServiceName' already exists."
                    }
                    else {
                        # Genuine error (Permissions, KDS Key missing, etc.)
                        Write-Error "Failed to create gMSA '$ServiceName'. Error: $_"
                    }
                }
            }

            # -----------------------------------------------------------
            # 4. Generate Installation Script
            # -----------------------------------------------------------
            if ($PSCmdlet.ShouldProcess($ScriptExportPath, "Generate Server Script")) {
                
                if (-not (Test-Path -Path $ScriptExportPath)) {
                    New-Item -Path $ScriptExportPath -ItemType Directory -Force | Out-Null
                }

                $ScriptFile = Join-Path -Path $ScriptExportPath -ChildPath "$ServiceName.ps1"
                
                $ScriptContent = @"
# ---------------------------------------------------------
# gMSA Installation Script for Service: $ServiceName
# Run this on: $( $ComputerNames -join ', ' )
# Generated by ADUtils on $(Get-Date)
# ---------------------------------------------------------

Write-Host "Checking RSAT-AD-PowerShell..." -ForegroundColor Cyan
try {
    $Feature = Get-WindowsFeature RSAT-AD-PowerShell -ErrorAction SilentlyContinue
    if ($null -eq $Feature -or -not $Feature.Installed) {
        Add-WindowsFeature RSAT-AD-PowerShell
        Write-Host "RSAT Tools Installed." -ForegroundColor Green
    }
}
catch {
    Write-Warning "Could not install RSAT tools automatically. Ensure internet/SXS access."
}

# --- NO REBOOT LOGIC START ---
Write-Host "Refreshing Computer Kerberos Tickets (Avoiding Reboot)..." -ForegroundColor Cyan
# This purges the tickets for the Local System session (0x3e7)
# This allows the server to 'see' its new gMSA permissions immediately.
klist -li 0x3e7 purge | Out-Null

Write-Host "Forcing Computer Policy Update..." -ForegroundColor Cyan
gpupdate /target:computer /force | Out-Null
# --- NO REBOOT LOGIC END ---

Write-Host "Installing gMSA: $ServiceName" -ForegroundColor Cyan
try {
    # We clear the error variable to ensure a clean check
    $Error.Clear()
    Install-ADServiceAccount -Identity "$ServiceName" -ErrorAction Stop
    Write-Host "Success: Account installed." -ForegroundColor Green
}
catch {
    Write-Host "Failed to install gMSA. Attempting one-time dependency check..." -ForegroundColor Yellow
    
    # Check if the KDS Root Key is actually ready (common failure point)
    $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
    if (-not $kdsKey) {
        Write-Error "CRITICAL: No KDS Root Key found in AD. gMSA cannot function."
    } else {
        Write-Error "Failed to install gMSA. Error: $_"
    }
}

Write-Host "Testing gMSA Connectivity..." -ForegroundColor Cyan
# Small pause to allow AD to settle after the install command
Start-Sleep -Seconds 2 
$Test = Test-ADServiceAccount -Identity "$ServiceName"

if ($Test) { 
    Write-Host "Test Passed: TRUE" -ForegroundColor Green 
    Write-Host "The account is ready for use in Services, IIS, or Tasks." -ForegroundColor White
}
else { 
    Write-Host "Test Failed: FALSE" -ForegroundColor Red
    Write-Host "Ensure $( $ComputerNames -join ', ' ) is a member of the gMSA Access Group." -ForegroundColor Yellow
}
"@

                Set-Content -Path $ScriptFile -Value $ScriptContent
                Write-Host "Script generated at: $ScriptFile" -ForegroundColor Cyan
                Write-Host "ACTION: Run this script on the target servers." -ForegroundColor Yellow
            }

        }
        catch {
            Write-Error "Detailed Failure Message: $_"
        }
    }
}