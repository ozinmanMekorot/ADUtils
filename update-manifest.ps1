<#
.SYNOPSIS
    Updates the module manifest FunctionsToExport field based on the Public folder.
#>
param (
    [String]$ModulePath = $PSScriptRoot
)

# 1. Locate the .psd1 file (The Manifest)
$ManifestItem = Get-ChildItem -Path $ModulePath -Filter *.psd1 -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $ManifestItem) {
    Write-Error "Could not find a .psd1 manifest file in '$ModulePath'."
    return
}

Write-Host "Found Manifest: $($ManifestItem.Name)" -ForegroundColor Cyan

# 2. Locate the Public folder
$PublicFolder = Join-Path -Path $ModulePath -ChildPath "Public"

if (-not (Test-Path -Path $PublicFolder)) {
    Write-Warning "Could not find a 'Public' folder in '$ModulePath'. Setting FunctionsToExport to empty."
    $PublicFunctions = @()
}
else {
    # 3. Get all .ps1 files in Public and extract their BaseName (filename without extension)
    $PublicFiles = Get-ChildItem -Path $PublicFolder -Filter *.ps1 -Recurse
    $PublicFunctions = $PublicFiles.BaseName
    
    Write-Host "Found $( $PublicFunctions.Count ) public functions." -ForegroundColor Green
}

# 4. Update the Manifest
# We explicitly set FunctionsToExport. 
# Note: Update-ModuleManifest preserves other fields (Version, Author, etc.) automatically.
try {
    Update-ModuleManifest -Path $ManifestItem.FullName -FunctionsToExport $PublicFunctions -ErrorAction Stop
    Write-Host "Success! Manifest updated." -ForegroundColor Green
}
catch {
    Write-Error "Failed to update manifest: $_"
}