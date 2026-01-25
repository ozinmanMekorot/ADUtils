function Start-ADUSiteReplication {
    <#
    .SYNOPSIS
        Identifies the PDC Emulator and Starts a full Active Directory replication.
    #>
    process {
        try {
            Write-Host "Locating PDC Emulator..." -ForegroundColor Cyan
            
            # Identify the PDC Emulator for the current domain
            $PDC = (Get-ADDomain).PDCEmulator

            if ($null -eq $PDC) {
                throw "Could not identify the PDC Emulator. Ensure RSAT tools are installed."
            }

            Write-Host "PDC Emulator found: $PDC" -ForegroundColor Green
            Write-Host "Initiating forest-wide replication via Invoke-Command..." -ForegroundColor Yellow

            # Execute the syncall command on the PDC
            Invoke-Command -ComputerName $PDC -ScriptBlock {
                repadmin /syncall /AdePq
            }
        }
        catch {
            Write-Error "Failed to Start replication: $($_.Exception.Message)"
        }
    }
}