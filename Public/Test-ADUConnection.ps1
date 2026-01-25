function Test-ADUConnection {
<#
.SYNOPSIS
    Tests network connectivity for critical Active Directory ports and displays a matrix report.

.DESCRIPTION
    Validates AD port connectivity between a source and destination(s).
    The output is pivoted so that each Domain Controller is a row, and each port status is a column.

.PARAMETER SourceServer
    The hostname/IP initiating the test. Defaults to local.

.PARAMETER DestinationServer
    A specific target DC to test.

.PARAMETER SiteName
    An AD Site name to test against all DCs in that site.
#>
    [CmdletBinding(DefaultParameterSetName = "ServerName")]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SourceServer = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true, ParameterSetName = "ServerName")]
        [string]$DestinationServer,

        [Parameter(Mandatory = $true, ParameterSetName = "SiteName")]
        [string]$SiteName
    )

    process {
        $TargetList = @()

        # Resolve Targets based on Site or Name
        if ($PSCmdlet.ParameterSetName -eq "SiteName") {
            try {
                $TargetList = (Get-ADDomainController -Filter "Site -eq '$SiteName'").HostName
                if (-not $TargetList) { throw "No DCs found in site '$SiteName'." }
            } catch {
                Write-Error "AD Query Failed: $($_.Exception.Message)"
                return
            }
        } else {
            $TargetList = @($DestinationServer)
        }

        # Port Logic
        $ScriptBlock = {
            param($Targets)
            $Ports = @(135, 389, 636, 3268, 88, 53, 445, 5985)
            
            $Results = foreach ($T in $Targets) {
                $Entry = [ordered]@{ "Destination" = $T }
                foreach ($P in $Ports) {
                    $Check = Test-NetConnection -ComputerName $T -Port $P -InformationLevel Quiet -WarningAction SilentlyContinue
                    # Using icons for a cleaner look: ✔ for Pass, ✘ for Fail
                    $Entry["Port_$P"] = if ($Check) { "PASS" } else { "!! FAIL !!" }
                }
                [PSCustomObject]$Entry
            }
            return $Results
        }

        Write-Host "`n=== AD CONNECTIVITY AUDIT MATRIX ===" -ForegroundColor Cyan
        Write-Host "Source: [$SourceServer] | Target Site: [$SiteName]" -ForegroundColor White
        Write-Host "Timestamp: $(Get-Date)"
        Write-Host ("-" * 40)

        try {
            if ($SourceServer -eq $env:COMPUTERNAME -or $SourceServer -eq "localhost") {
                $FinalOutput = & $ScriptBlock $TargetList
            } else {
                $FinalOutput = Invoke-Command -ComputerName $SourceServer -ScriptBlock $ScriptBlock -ArgumentList (,$TargetList) -ErrorAction Stop
            }

            # Return the object and format it as a table for the console
            $FinalOutput | Format-Table -AutoSize
            
            Write-Host "Audit Complete." -ForegroundColor Green
        } catch {
            Write-Error "Remote execution failed: $($_.Exception.Message)"
        }
    }
}