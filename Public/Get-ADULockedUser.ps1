function Get-ADULockedUser {
    <#
    .SYNOPSIS
        Checks if a user is locked and traces the source. 
        If 'WORKSTATION' is returned, it performs a Deep Trace using Event 4776.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeDC = @()
    )

    process {
        try {
            # 1. Check current lockout status
            $user = Get-ADUser -Identity $Identity -Properties LockedOut, DisplayName, SID
            
            if (-not $user.LockedOut) {
                return "User '$Identity' is not locked."
            }

            Write-Host "User is LOCKED. Tracing source..." -ForegroundColor Red
            $userSid = $user.SID.Value
            $userName = $user.DisplayName
            $samName = $user.SamAccountName

            # 2. Get all DCs and filter exclusions
            $allDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
            $targetDCs = $allDCs | Where-Object {
                $currentDC = $_
                -not ($ExcludeDC | Where-Object { $currentDC -like "*$_*" })
            }

            $lockoutEvents = @()

            foreach ($dc in $targetDCs) {
                Write-Verbose "Querying $dc..."
                
                try {
                    # Query 4740 (Lockout Event)
                    $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                        LogName = 'Security'; Id = 4740; StartTime = (Get-Date).AddDays(-1)
                    } -ErrorAction SilentlyContinue | Where-Object { 
                        $_.Properties[0].Value -eq $userName -or $_.Properties[2].Value -eq $userSid 
                    }

                    foreach ($event in $events) {
                        $source = $event.Properties[1].Value
                        
                        # DEEP TRACE LOGIC: If source is generic, look for NTLM 4776 events at that timestamp
                        if ($source -eq "WORKSTATION" -or [string]::IsNullOrWhiteSpace($source)) {
                            $timeBufferStart = $event.TimeCreated.AddSeconds(-5)
                            $timeBufferEnd = $event.TimeCreated.AddSeconds(5)

                            $ntlmEvent = Get-WinEvent -ComputerName $dc -FilterHashtable @{
                                LogName = 'Security'; Id = 4776; StartTime = $timeBufferStart; EndTime = $timeBufferEnd
                            } -ErrorAction SilentlyContinue | Where-Object { 
                                $_.Properties[1].Value -eq $samName 
                            } | Select-Object -First 1

                            if ($ntlmEvent) {
                                # Property index [2] in 4776 is often the real source workstation/IP
                                $source = "$($ntlmEvent.Properties[2].Value) (via DeepTrace 4776)"
                            }
                        }

                        $lockoutEvents += [PSCustomObject]@{
                            Time             = $event.TimeCreated
                            User             = $event.Properties[0].Value
                            SourceComputer   = $source
                            DomainController = $dc
                        }
                    }
                }
                catch {
                    Write-Warning "Unable to reach or query Domain Controller: $dc"
                }
            }

            if ($lockoutEvents) {
                return $lockoutEvents | Sort-Object Time -Descending
            }
            else {
                return "User is locked out, but no 4740 events were found in the last 24 hours."
            }
        }
        catch {
            Write-Error "Error retrieving user: $($_.Exception.Message)"
        }
    }
}
