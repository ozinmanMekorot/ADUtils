function Get-ADUObject {
    <#
    .SYNOPSIS
        Finds Active Directory objects with easy wildcard support. 
        Can inspect attributes via the private helper 'Get-ADUAttributeEditor'.

    .DESCRIPTION
        1. Searches for objects using Wildcards or ANR.
        2. Supports retrieving specific properties via -Properties parameter.
        3. Returns the objects with specific columns (Name, Class, DN, GUID + Requested Properties).
        4. Supports handing off to the Attribute Editor for deep inspection.
        
        NOTE: This function outputs raw objects. Default display is a Table.

    .PARAMETER Identity
        The search string. Can be a Name, SamAccountName, or wildcard pattern (e.g. *SQL*).

    .PARAMETER Properties
        A list of additional properties to retrieve and display (e.g. "Description", "mail").
        Use "*" to retrieve all properties.

    .PARAMETER ShowAttributes
        Opens the Attribute Editor showing ALL attributes.

    .PARAMETER ShowPopulatedAttributes
        Opens the Attribute Editor showing ONLY populated attributes.
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$Identity,

        [Parameter(Position=1)]
        [string[]]$Properties,

        [Parameter(ParameterSetName = "FullAttr")]
        [switch]$ShowAttributes,

        [Parameter(ParameterSetName = "PopAttr")]
        [switch]$ShowPopulatedAttributes
    )

    process {
        $Results = @()
        
        # --- BUILD PARAMETERS (SPLATTING) ---
        # We use a hashtable to hold parameters.
        # We ONLY add 'Properties' if the user actually asked for them.
        # This prevents passing an empty array/null which causes Get-ADObject to fail.
        $SearchParams = @{
            ErrorAction = 'SilentlyContinue'
        }
        
        if ($Properties) {
            $SearchParams['Properties'] = $Properties
        }

        # --- 1. SEARCH LOGIC ---
        Write-Verbose "Searching for: $Identity"

        # A. Wildcard Search
        if ($Identity -like "*`**") {
            try {
                # Add Filter to params
                $SearchParams['Filter'] = "Name -like '$Identity'"
                $Results = @(Get-ADObject @SearchParams)
            } catch {}
        }
        # B. Direct/ANR Search
        else {
            try {
                # 1. Try Identity Match
                # Identity doesn't take Filter, so we construct a separate command or param set
                # But Get-ADObject -Identity doesn't accept Filter, so we run directly.
                $IdentityParams = $SearchParams.Clone()
                $IdentityParams['Identity'] = $Identity
                
                $Results = @(Get-ADObject @IdentityParams)
            } catch {}

            # 2. If not found, try ANR
            if ($Results.Count -eq 0) {
                try {
                    $AnrParams = $SearchParams.Clone()
                    $AnrParams['LDAPFilter'] = "(anr=$Identity)"
                    
                    $Results = @(Get-ADObject @AnrParams)
                } catch {}
            }
        }

        # --- 2. NO RESULTS ---
        if ($Results.Count -eq 0) {
            Write-Warning "No objects found matching '$Identity'."
            return
        }

        # --- 3. DISPLAY & SELECTION LOGIC ---
        
        # Calculate Columns to Show
        $DisplayColumns = @('Name', 'ObjectClass', 'DistinguishedName', 'ObjectGUID')
        
        # Add requested properties to columns (unless *)
        if ($Properties -and -not ($Properties -contains '*')) {
            $DisplayColumns += $Properties
            $DisplayColumns = $DisplayColumns | Select-Object -Unique
        }

        # Scenario A: Standard Display (No Attribute Editor requested)
        if (-not $ShowAttributes -and -not $ShowPopulatedAttributes) {
            
            if ($Results.Count -gt 1) {
                Write-Host "Found $($Results.Count) objects." -ForegroundColor Cyan
            }

            # CASE 1: Wildcard Properties (*) -> Return Raw
            if ($Properties -contains '*') {
                return $Results
            }
            
            # CASE 2: Specific or Default Properties -> Select Columns
            # We return the OBJECT (Select-Object), allowing | Format-List to work outside.
            return ($Results | Select-Object $DisplayColumns)
        }

        # Scenario B: Attribute Editor Requested
        $TargetObject = $null

        if ($Results.Count -eq 1) {
            $TargetObject = $Results[0]
        }
        else {
            Write-Host "Search returned $($Results.Count) objects. Please select one." -ForegroundColor Yellow
            
            if ($Properties -contains '*') {
                 $TargetObject = $Results | Out-GridView -Title "Multiple objects found for '$Identity'. Select ONE." -PassThru
            }
            else {
                 $TargetObject = $Results | Select-Object $DisplayColumns | 
                            Out-GridView -Title "Multiple objects found for '$Identity'. Select ONE." -PassThru
            }
        }

        # --- 4. HANDOFF TO PRIVATE FUNCTION ---
        if ($TargetObject) {
            $DN = $TargetObject.DistinguishedName

            if ($ShowPopulatedAttributes) {
                Get-ADUAttributeEditor -Identity $DN -ShowPopulated
            }
            else {
                Get-ADUAttributeEditor -Identity $DN
            }
        }
    }
}