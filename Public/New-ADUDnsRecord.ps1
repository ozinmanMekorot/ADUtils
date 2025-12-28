function New-ADUDnsRecord {
    <#
    .SYNOPSIS
        Creates a "Locked" Static A-Record and manages Multiple PTRs with Orphan Cleanup.

    .DESCRIPTION
        1. Auto-detects the DNS Janitor.
        2. Creates a clean Static A-Record (Deleting old A-records for this name).
        3. LOCKING: Loops indefinitely until the AD Object is found, then locks permissions.
        4. PTR Logic:
           - Scans ALL existing PTRs for this IP.
           - Checks if the hostname they point to actually exists (has an A-record).
           - If NO A-record exists -> Deletes the PTR (Orphan).
           - If A-record exists -> Keeps the PTR.
           - Adds the NEW PTR if it doesn't already exist.

    .PARAMETER ZoneName
        The Forward Lookup Zone name (e.g., 'mekorot.co.il').

    .PARAMETER RecordName
        The hostname for the record (e.g., 'RSHDC01R').

    .PARAMETER IpAddress
        The IPv4 address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [string]$RecordName,

        [Parameter(Mandatory = $true)]
        [ipaddress]$IpAddress
    )

    process {
        if (-not (Get-Module -Name ActiveDirectory)) { Import-Module ActiveDirectory -ErrorAction Stop }
        if (-not (Get-Module -Name DnsServer)) { Import-Module DnsServer -ErrorAction Stop }

        Write-Host "--- Secure DNS Record Creation ($RecordName) ---" -ForegroundColor Cyan
        
        # ---------------------------------------------------------
        # STEP 1: LOCATE DNS JANITOR
        # ---------------------------------------------------------
        Write-Host "Locating DNS Janitor..." -NoNewline
        $AllDCs = (Get-ADDomainController -Filter *).HostName
        $DnsServer = $null

        foreach ($DC in $AllDCs) {
            try {
                $Settings = Get-DnsServerScavenging -ComputerName $DC -ErrorAction Stop
                if ($Settings.ScavengingState -eq $true) {
                    $DnsServer = $DC
                    break 
                }
            }
            catch { continue }
        }

        if (-not $DnsServer) {
            $DnsServer = $AllDCs[0]
            Write-Host " [Warning: No Janitor. Using: $DnsServer]" -ForegroundColor Yellow
        } else {
            Write-Host " [Found: $DnsServer]" -ForegroundColor Green
        }

        # ---------------------------------------------------------
        # STEP 2: CREATE A-RECORD
        # ---------------------------------------------------------
        Write-Host "`n--- Step 2: Creating Static A-Record ---" -ForegroundColor Cyan

        # Clean existing A-records for this NAME
        try {
            $ExistingRecords = @(Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $RecordName -ComputerName $DnsServer -ErrorAction SilentlyContinue)
            if ($ExistingRecords.Count -gt 0) {
                Write-Host "Clearing $($ExistingRecords.Count) old entries for '$RecordName'..." -ForegroundColor Yellow
                $ExistingRecords | Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DnsServer -Force -Confirm:$false
            }
        }
        catch { Write-Warning "Error clearing old records: $_" }

        # Create New Static Record
        try {
            Add-DnsServerResourceRecordA -Name $RecordName -ZoneName $ZoneName -IPv4Address $IpAddress -ComputerName $DnsServer -ErrorAction Stop
            Write-Host "Success: Record '$RecordName' -> '$IpAddress' created." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create A-Record: $_"
            return
        }

        # ---------------------------------------------------------
        # STEP 3: LOCK PERMISSIONS (Infinite Loop Loop)
        # ---------------------------------------------------------
        Write-Host "`n--- Step 3: Locking Permissions ---" -ForegroundColor Cyan
        
        $AdFilter = "(&(objectClass=dnsNode)(name=$RecordName))"
        $DnsObject = $null
        $RootDSE = (Get-ADRootDSE).defaultNamingContext
        
        # Loop until the object is found
        do {
            Write-Host "Searching for AD Object..." -NoNewline
            
            # Check DomainDnsZones
            $DnsObject = Get-ADObject -LDAPFilter $AdFilter -SearchBase "DC=DomainDnsZones,$RootDSE" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            
            # Check ForestDnsZones if not found
            if (-not $DnsObject) {
                $DnsObject = Get-ADObject -LDAPFilter $AdFilter -SearchBase "DC=ForestDnsZones,$RootDSE" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            }

            if (-not $DnsObject) {
                Write-Host " Not found. Sleeping 3s..." -ForegroundColor Gray
                Start-Sleep -Seconds 3
            }

        } while (-not $DnsObject)

        Write-Host " [FOUND]" -ForegroundColor Green
        Write-Host "Target: $($DnsObject.DistinguishedName)" -ForegroundColor Gray

        # --- Apply Permissions ---
        $AclPath = "AD:\" + $DnsObject.DistinguishedName
        $Acl = Get-Acl -Path $AclPath

        try {
            $Domain = Get-ADDomain
            $AdminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $Domain.SID)
        }
        catch { $AdminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") }

        $Acl.SetOwner($AdminSid)
        $Acl.SetAccessRuleProtection($true, $true) 
        
        $Rules = $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        $ChangesMade = $false

        foreach ($Rule in $Rules) {
            $IsAdmin = ($Rule.IdentityReference -eq $AdminSid) -or ($Rule.IdentityReference.Value -match "S-1-5-18") -or ($Rule.IdentityReference.Value -match "S-1-5-32-544")
            $AllowsWrite = ($Rule.FileSystemRights -match "Write") -or ($Rule.ActiveDirectoryRights -match "WriteProperty") -or ($Rule.ActiveDirectoryRights -match "GenericWrite")
            
            if (-not $IsAdmin -and $AllowsWrite) {
                $Acl.RemoveAccessRule($Rule) | Out-Null
                $ChangesMade = $true
            }
        }

        if ($ChangesMade) {
            Set-Acl -Path $AclPath -AclObject $Acl
            Write-Host "Permissions LOCKED." -ForegroundColor Green
        } else {
            Write-Host "Permissions were already secure." -ForegroundColor Green
        }


        # ---------------------------------------------------------
        # STEP 4: REVERSE DNS (ORPHAN CLEANUP & ADDITION)
        # ---------------------------------------------------------
        Write-Host "`n--- Step 4: Configuring Reverse DNS (PTR) ---" -ForegroundColor Cyan

        $IpBytes = $IpAddress.IPAddressToString.Split('.')
        $ReverseZoneName = "{0}.{1}.{2}.in-addr.arpa" -f $IpBytes[2], $IpBytes[1], $IpBytes[0]
        $ReverseNodeName = $IpBytes[3]

        # 1. Ensure Zone Exists
        if (-not (Get-DnsServerZone -Name $ReverseZoneName -ComputerName $DnsServer -ErrorAction SilentlyContinue)) {
            Write-Host "Creating missing Reverse Zone: $ReverseZoneName" -ForegroundColor Yellow
            try { Add-DnsServerPrimaryZone -Name $ReverseZoneName -ReplicationScope Domain -ComputerName $DnsServer -ErrorAction Stop }
            catch { Write-Error "Failed to create Reverse Zone."; return }
        }

        # 2. Get ALL existing PTRs for this IP
        $ExistingPtrs = @(Get-DnsServerResourceRecord -ZoneName $ReverseZoneName -Name $ReverseNodeName -ComputerName $DnsServer -ErrorAction SilentlyContinue)
        
        # 3. CLEANUP: Scan for Orphans
        if ($ExistingPtrs) {
            Write-Host "Scanning $($ExistingPtrs.Count) existing PTRs for orphans..." -ForegroundColor Gray
            
            foreach ($Ptr in $ExistingPtrs) {
                $TargetHost = $Ptr.RecordData.PtrDomainName
                $TargetHostClean = $TargetHost.TrimEnd('.')
                
                Write-Host "Checking: $TargetHostClean ... " -NoNewline
                
                $ARecordExists = Resolve-DnsName -Name $TargetHostClean -Type A -Server $DnsServer -ErrorAction SilentlyContinue
                
                if ($ARecordExists) {
                    Write-Host "[VALID]" -ForegroundColor Green
                }
                else {
                    Write-Host "[ORPHANED - DELETING]" -ForegroundColor Red
                    try {
                        Remove-DnsServerResourceRecord -ZoneName $ReverseZoneName -InputObject $Ptr -ComputerName $DnsServer -Force -Confirm:$false
                    }
                    catch { Write-Warning "Failed to delete orphan: $_" }
                }
            }
        }

        # 4. ADD NEW PTR (If missing)
        $NewPtrHostName = "$RecordName.$ZoneName"
        if (-not $NewPtrHostName.EndsWith(".")) { $NewPtrHostName += "." }

        # Refresh list after deletions
        $RemainingPtrs = @(Get-DnsServerResourceRecord -ZoneName $ReverseZoneName -Name $ReverseNodeName -ComputerName $DnsServer -ErrorAction SilentlyContinue)
        $AlreadyExists = $false
        
        foreach ($Ptr in $RemainingPtrs) {
            if ($Ptr.RecordData.PtrDomainName -eq $NewPtrHostName) {
                $AlreadyExists = $true
                break
            }
        }

        if ($AlreadyExists) {
            Write-Host "PTR for '$NewPtrHostName' already exists. Skipping." -ForegroundColor Green
        }
        else {
            try {
                Add-DnsServerResourceRecordPtr -Name $ReverseNodeName -ZoneName $ReverseZoneName -PtrDomainName $NewPtrHostName -ComputerName $DnsServer -ErrorAction Stop
                Write-Host "PTR Created: $ReverseNodeName -> $NewPtrHostName" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to add PTR: $_"
            }
        }

        Write-Host "`nOperation Complete." -ForegroundColor Cyan
    }
}