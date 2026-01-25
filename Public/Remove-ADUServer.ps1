function Remove-ADUServer {
    <#
    .SYNOPSIS
        Decommissions a server by performing a graceful shutdown, relocating the AD object to a 
        holding OU, updating metadata, and executing a hostname-specific DNS cleanup.

    .DESCRIPTION
        The Remove-ADUServer function automates the standard server retirement lifecycle 
        within the mekorot.co.il domain. 

        Key Logic Pillars:
        1. Janitor Discovery: Automatically scans all Domain Controllers to identify the 
           current DNS Janitor (the server with Scavenging enabled) to ensure record 
           consistency and prevent replication delays during deletion.
        2. Graceful Shutdown: Attempts to power down the target host via WMI/RPC. If the 
           host is unreachable or scavenging has already occurred, the script gracefully 
           proceeds to administrative cleanup.
        3. AD Management: Moves the computer object to 'DisabledComputers/DeleteMe' and 
           stamps the description with a "disabled by script" date for auditing.
        4. Shared IP Safety (PTR Protection): Designed for multi-instance environments 
           (e.g., SQL Clusters). The function retrieves the specific Pointer (PTR) record 
           data and only deletes the entry matching the Target FQDN. This prevents 
           accidental deletion of other hostnames sharing the same IP address.
        5. InputObject Deletion: Uses direct object piping for DNS removal to bypass 
           "Failed to get record" errors often caused by complex reverse lookup zone paths.

    .PARAMETER ComputerName
        The NetBIOS name of the server to decommission. The function will resolve the 
        FQDN and IP address via Active Directory and DNS.

    .EXAMPLE
        Remove-ADUServer -ComputerName MEKMOBDB
    
        Finds the active Janitor, shuts down MEKMOBDB, moves it to the 'DeleteMe' OU, 
        and removes only the DNS records specifically belonging to MEKMOBDB.
    #>
    [CmdletBinding(ConfirmImpact = 'High', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$ComputerName
    )

    process {
        if ($PSCmdlet.ShouldProcess($ComputerName, "Decommission server and cleanup records")) {
            try {
                # --- PHASE 1: DETECT DNS JANITOR ---
                Write-Host "[*] Detecting current DNS Janitor..." -ForegroundColor Cyan
                $AllDCs = (Get-ADDomainController -Filter *).HostName
                $JanitorTarget = $null
                foreach ($DC in $AllDCs) {
                    try {
                        $Settings = Get-DnsServerScavenging -ComputerName $DC -ErrorAction Stop
                        if ($Settings.ScavengingState -eq $true) { $JanitorTarget = $DC; break }
                    } catch { }
                }
                $JanitorTarget = if ($JanitorTarget) { $JanitorTarget } else { "mekorot.co.il" }
                Write-Host "[V] Target DNS Server: $JanitorTarget" -ForegroundColor Green

                # --- PHASE 2: AD DATA ---
                $ADObj = Get-ADComputer -Identity $ComputerName -Properties IPv4Address, DistinguishedName, DNSHostName -ErrorAction Stop
                $TargetFQDN = if ($ADObj.DNSHostName) { $ADObj.DNSHostName } else { "$ComputerName.mekorot.co.il" }
                $TargetFQDNMatch = "$TargetFQDN.".ToLower()

                # --- PHASE 3: SHUTDOWN ---
                $TargetAddress = if ($ADObj.IPv4Address) { $ADObj.IPv4Address } else { $ComputerName }
                if (Test-Connection -ComputerName $TargetAddress -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    try { Stop-Computer -ComputerName $TargetAddress -Force -ErrorAction Stop } catch { }
                }

                # --- PHASE 4: AD ATTRIBUTES & MOVE ---
                $TargetOU = "OU=DeleteMe,OU=DisabledComputers,DC=mekorot,DC=co,DC=il"
                $DateString = Get-Date -Format "MMM dd, yyyy"
                Set-ADComputer -Identity $ADObj.DistinguishedName -Description "Disabled by script on $DateString" -ErrorAction Stop
                Move-ADObject -Identity $ADObj.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
                Write-Host "[*] AD Object moved and updated." -ForegroundColor Green

                # --- PHASE 5: SAFE DNS CLEANUP ---
                Write-Host "[*] Starting safe DNS cleanup..." -ForegroundColor Cyan
                $IPsToDelete = New-Object System.Collections.Generic.List[string]
                
                # Fetch A-Records
                $DNSRecords = Get-DnsServerResourceRecord -ComputerName $JanitorTarget -ZoneName "mekorot.co.il" -Name $ComputerName -RRType A -ErrorAction SilentlyContinue
                if ($DNSRecords) { $DNSRecords | ForEach-Object { $IPsToDelete.Add($_.RecordData.IPv4Address.IPAddressToString) } }
                if ($ADObj.IPv4Address -and -not ($IPsToDelete -contains $ADObj.IPv4Address)) { $IPsToDelete.Add($ADObj.IPv4Address) }

                foreach ($IP in $IPsToDelete) {
                    $Octets = $IP.Split('.')
                    if ($Octets.Count -eq 4) {
                        # Search all reverse zones
                        $ReverseZones = Get-DnsServerZone -ComputerName $JanitorTarget | Where-Object { $_.ZoneName -like "*in-addr.arpa" }
                        
                        foreach ($Zone in $ReverseZones) {
                            # We find the record object first
                            $PTRs = Get-DnsServerResourceRecord -ComputerName $JanitorTarget -ZoneName $Zone.ZoneName -RRType PTR -ErrorAction SilentlyContinue | Where-Object { $_.HostName -eq $Octets[3] }

                            foreach ($PTR in $PTRs) {
                                $CurrentPtrData = $PTR.RecordData.PtrDomainName.ToLower()
                                
                                if ($CurrentPtrData -eq $TargetFQDNMatch -or $CurrentPtrData -eq $TargetFQDN.ToLower()) {
                                    Write-Host "[!] Removing matching PTR: $IP -> $CurrentPtrData" -ForegroundColor Yellow
                                    
                                    # CRITICAL FIX: Use -InputObject. This passes the exact object found, 
                                    # which prevents the "Failed to get record" lookup error.
                                    $PTR | Remove-DnsServerResourceRecord -ComputerName $JanitorTarget -ZoneName $Zone.ZoneName -Force
                                }
                            }
                        }
                    }
                    
                    # Remove A-Record using the same InputObject pipe for safety
                    $ARecs = Get-DnsServerResourceRecord -ComputerName $JanitorTarget -ZoneName "mekorot.co.il" -Name $ComputerName -RRType A -ErrorAction SilentlyContinue
                    foreach ($ARec in $ARecs) {
                        if ($ARec.RecordData.IPv4Address.IPAddressToString -eq $IP) {
                            Write-Host "[!] Removing A-Record: $ComputerName ($IP)" -ForegroundColor Yellow
                            $ARec | Remove-DnsServerResourceRecord -ComputerName $JanitorTarget -ZoneName "mekorot.co.il" -Force
                        }
                    }
                }

                Write-Host "[V] Successfully decommissioned $ComputerName." -ForegroundColor Green
            }
            catch {
                Write-Error "CRITICAL: Could not process $ComputerName. Error: $($_.Exception.Message)"
            }
        }
    }
}