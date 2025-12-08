function Get-PasswordExpiry {
    <#
    .SYNOPSIS
        Checks if an Active Directory user's password has exceeded the maximum age.
    
    .DESCRIPTION
        This function retrieves the PasswordLastSet property of an AD user, calculates the age 
        of the password, and compares it against a defined threshold (default 90 days).
        
    .PARAMETER UserName
        The SAMAccountName of the user to check.
        
    .PARAMETER MaxPasswordAge
        The number of days before a password is considered expired. Default is 90.
        
    .EXAMPLE
        Get-PasswordExpiry -UserName "jdoe"
        Checks user "jdoe" against the default 90-day limit.
        
    .EXAMPLE
        Get-PasswordExpiry -UserName "admin01" -MaxPasswordAge 30
        Checks user "admin01" against a stricter 30-day limit.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$UserName,

        [int]$MaxPasswordAge = 90
    )

    process {
        try {
            # Retrieve the user from Active Directory with specific properties
            $ADUser = Get-ADUser -Identity $UserName -Properties PasswordLastSet, PasswordNeverExpires -ErrorAction Stop

            # Check if "Password Never Expires" is checked in AD
            if ($ADUser.PasswordNeverExpires -eq $true) {
                return [PSCustomObject]@{
                    UserName          = $UserName
                    PasswordLastSet   = $ADUser.PasswordLastSet
                    DaysSinceSet      = $null
                    ExpiresOn         = "Never"
                    NeedsChange       = $false
                    Status            = "Password set to never expire"
                }
            }

            # Check if PasswordLastSet is null (usually means user must change at next logon or new account)
            if ($null -eq $ADUser.PasswordLastSet) {
                return [PSCustomObject]@{
                    UserName          = $UserName
                    PasswordLastSet   = $null
                    DaysSinceSet      = $null
                    ExpiresOn         = "Immediate"
                    NeedsChange       = $true
                    Status            = "Password must be changed at next logon"
                }
            }

            # Calculate Dates
            $DateSet = $ADUser.PasswordLastSet
            $CurrentDate = Get-Date
            $TimeSpan = New-TimeSpan -Start $DateSet -End $CurrentDate
            $DaysActive = $TimeSpan.Days
            
            # Calculate when it expires based on the input ($MaxPasswordAge)
            $ExpiryDate = $DateSet.AddDays($MaxPasswordAge)
            
            # Boolean logic: Is the password older than the max age?
            $IsExpired = $DaysActive -ge $MaxPasswordAge

            # Return a custom object
            return [PSCustomObject]@{
                UserName          = $UserName
                PasswordLastSet   = $DateSet
                DaysSinceSet      = $DaysActive
                ExpiresOn         = $ExpiryDate
                NeedsChange       = $IsExpired
                Status            = if ($IsExpired) { "EXPIRED" } else { "Valid" }
            }

        }
        catch {
            Write-Warning "Could not find user '$UserName' or unable to contact Domain Controller."
            Write-Error $_.Exception.Message
        }
    }
}

