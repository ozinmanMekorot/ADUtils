# Get the location of the module files
$PublicPath  = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
$PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'

# 1. Load Private functions
if (Test-Path -Path $PrivatePath) {
    $Private = Get-ChildItem -Path $PrivatePath -Filter '*.ps1'
    foreach($Import in $Private) {
        Try {
            . $Import.FullName
        } Catch {
            Write-Error "Failed to import Private function $($Import.Name): $_"
        }
    }
}

# 2. Load Public functions
if (Test-Path -Path $PublicPath) {
    $Public = Get-ChildItem -Path $PublicPath -Filter '*.ps1'
    foreach($Import in $Public) {
        Try {
            . $Import.FullName
            Export-ModuleMember -Function $Import.BaseName
        } Catch {
            Write-Error "Failed to import Public function $($Import.Name): $_"
        }
    }
}