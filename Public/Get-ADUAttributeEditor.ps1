function Get-ADUAttributeEditor {
    <#
    .SYNOPSIS
        Opens a Read-Only Grid View window mimicking the ADUC Attribute Editor tab.

    .DESCRIPTION
        This function retrieves all properties (attributes) of a specified Active Directory object
        (User, Computer, or Group) and displays them in a searchable Grid View window.
        
        It automatically converts unreadable Integer dates (FileTime) into human-readable DateTimes.
        
    .PARAMETER Identity
        The Identity (SamAccountName, DistinguishedName, GUID) of the object to inspect.
        Also accepts Display Names or partial matches via ANR fallback.

    .PARAMETER ShowPopulated
        If specified, the grid will hide empty attributes (those marked "<not set>") and only show attributes with values.

    .EXAMPLE
        Get-ADUAttributeEditor -Identity "jdoe"
        Opens a window showing all raw attributes for user jdoe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [string]$Identity,

        [Parameter()]
        [switch]$ShowPopulated
    )

    process {
        try {
            $ADObject = $null
            # Extended properties to ensure we capture constructed attributes.
            # Removed 'PasswordLastSet' and 'LastLogonDate' as they are Get-ADUser aliases, not valid for Get-ADObject.
            # Real attributes like 'pwdLastSet' are covered by '*'
            $PropsToGet = @("*", "allowedAttributesEffective", "CanonicalName", "Created", "Modified", "msDS-UserPasswordExpiryTimeComputed", "createTimeStamp", "modifyTimeStamp")

            # 1. Try strict Identity lookup first
            try {
                $ADObject = Get-ADObject -Identity $Identity -Properties $PropsToGet -ErrorAction Stop
            }
            catch {
                Write-Verbose "Identity lookup failed. Trying ANR search..."
            }

            # 2. Fallback: Try Ambiguous Name Resolution (ANR)
            if (-not $ADObject) {
                $Found = @(Get-ADObject -LDAPFilter "(anr=$Identity)" -Properties $PropsToGet -ErrorAction Stop)
                
                if ($Found.Count -gt 1) {
                    Write-Error "Multiple objects found matching '$Identity'. Please be more specific (e.g. use a unique ID)."
                    return
                }
                elseif ($Found.Count -eq 0) {
                    Write-Error "Object '$Identity' not found."
                    return
                }
                
                $ADObject = $Found[0]
            }

            # 3. CRITICAL FIX: Unwrap Array if present
            # This prevents the "Capacity, Count, SyncRoot" view seen in your screenshot
            if ($ADObject -is [System.Collections.IEnumerable] -and $ADObject -isnot [string]) {
                $ADObject = $ADObject | Select-Object -First 1
            }

            # Double check we have a valid object
            if (-not $ADObject) { return }

            # Define FileTime attributes that need conversion to Date
            $DateAttributes = @(
                "lastLogon", "lastLogonTimestamp", "accountExpires", "badPasswordTime", 
                "lastLogoff", "lockoutTime", "pwdLastSet", "creationTime",
                "msDS-UserPasswordExpiryTimeComputed"
            )

            # Initialize Attribute List
            $AllAttributeNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            # Add Populated Attributes
            $PopulatedProperties = $ADObject.PSObject.Properties.Name
            foreach ($name in $PopulatedProperties) { [void]$AllAttributeNames.Add($name) }

            # Add Empty/Schema Attributes
            if ($ADObject.allowedAttributesEffective) {
                foreach ($attr in $ADObject.allowedAttributesEffective) { [void]$AllAttributeNames.Add($attr) }
            } 
            else {
                # Schema fallback logic would go here, but allowedAttributesEffective is preferred
            }

            # Build Output
            $OutputList = foreach ($AttrName in $AllAttributeNames) {
                $Val = $null
                $Type = ""
                
                if ($PopulatedProperties -contains $AttrName) {
                    $Prop = $ADObject.PSObject.Properties[$AttrName]
                    $RawVal = $Prop.Value
                    $Type = $Prop.TypeNameOfValue

                    # --- CONVERSION LOGIC ---
                    
                    # 1. Handle FileTime Integers (Dates)
                    if ($DateAttributes -contains $AttrName -and $RawVal -is [int64] -and $RawVal -gt 0) {
                        # Handle "Never" (Max Value)
                        if ($RawVal -eq 9223372036854775807) {
                            $Val = "Never"
                        }
                        else {
                            try {
                                $Val = [DateTime]::FromFileTime($RawVal).ToString("g") # General Date Format
                            }
                            catch {
                                $Val = $RawVal # Fallback if conversion fails
                            }
                        }
                    }
                    # 2. Handle Generalized Time Strings (e.g. 20230101120000.0Z)
                    elseif ($RawVal -is [string] -and $RawVal -match '^\d{14}\.\d+Z$') {
                        try {
                            $Val = [DateTime]::ParseExact($RawVal.Substring(0,14), "yyyyMMddHHmmss", $null).ToString("g")
                        }
                        catch {
                            $Val = $RawVal
                        }
                    }
                    # 3. Handle Multi-valued Arrays
                    elseif ($RawVal -is [System.Collections.IEnumerable] -and $RawVal -isnot [string]) {
                        $Val = $RawVal -join ', '
                    }
                    else {
                        $Val = $RawVal
                    }
                }
                else {
                    $Val = "<not set>"
                    $Type = "Schema Attribute"
                }

                # Create Object
                [PSCustomObject]@{
                    Attribute = $AttrName
                    Value     = $Val
                    Type      = $Type
                }
            }

            # Apply Filter if requested
            if ($ShowPopulated) {
                $OutputList = $OutputList | Where-Object { 
                    $_.Value -ne "<not set>" -and 
                    $_.Value -ne $null -and 
                    $_.Value -ne "" 
                }
            }

            # Output to GridView
            $OutputList | Sort-Object Attribute | 
                Out-GridView -Title "Attribute Editor: $($ADObject.Name) [$($ADObject.ObjectClass)]" -Wait
        }
        catch {
            Write-Error "Error retrieving object: $($_.Exception.Message)"
        }
    }
}
