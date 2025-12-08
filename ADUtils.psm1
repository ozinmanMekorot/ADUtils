# Get the location of the module files
$Public  = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue )

# 1. Load Private functions (Internal helpers)
# We dot-source them (.) so they are available to the module, 
# but we do NOT export them to the user.
foreach($Import in $Private) {
    Try {
        . $Import.FullName
    } Catch {
        Write-Error "Failed to import Private function $($Import.Name): $_"
    }
}

# 2. Load Public functions (User facing)
# We dot-source them AND explicitly export them using their filename.
foreach($Import in $Public) {
    Try {
        . $Import.FullName
        Export-ModuleMember -Function $Import.BaseName
    } Catch {
        Write-Error "Failed to import Public function $($Import.Name): $_"
    }
}