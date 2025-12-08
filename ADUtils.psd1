@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'ADUtils.psm1'

    # Version number of this module.
    ModuleVersion = '1.0'

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-7890-1234-567890abcdef'

    # Author of this module
    Author = 'Omer Zinman'

    # Company or vendor of this module
    CompanyName = 'Mekorot'

    # Copyright statement for this module
    Copyright = '(c) 2025. All rights reserved.'

    # Prefix for all commands in this module. 
    DefaultCommandPrefix = 'ADU'

    # Functions to export from this module. 
    # We set this to '*' to allow the ADUtils.psm1 loader to handle the specifics dynamically.
    FunctionsToExport = '*'

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = @()

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @('ActiveDirectory')

    # Description of the functionality provided by this module
    Description = 'Personal utilities for Active Directory management.'
}