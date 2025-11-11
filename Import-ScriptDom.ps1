<#
    .SYNOPSIS
        Import ScriptDom assembly to the current PowerShell session.
    .DESCRIPTION
        This script loads the ScriptDom assembly to the current PowerShell session.
        It checks if the assembly is already loaded and if it is, it checks if the loaded version is older than the new version.
        If the loaded version is older, it throws an error and suggests to close and reopen the PowerShell session.
        If the assembly is not loaded, it loads the new version.
    .LINK
        https://github.com/mcflyamorim
#>

function Import-ScriptDom { Param([string]$ScriptPath )
    function Find-File {
        Param(
            [Parameter(Mandatory=$true)]
            [string]$FileName,
            [Parameter(Mandatory=$true)]
            [string[]]$PathList
        )
    
        $File = $null
        ForEach($Path in $PathList)
        {
            Write-Msg ("Searching: {0}" -f $Path) -Level Output
            $File += Get-ChildItem $Path -ErrorAction SilentlyContinue -Filter $FileName -Recurse `
                        | Select-Object FullName, @{Name="FileVersionRaw";Expression={$_.VersionInfo.FileVersionRaw}}
        }
        foreach ($f in $File) {
            Write-Msg ("Found file: {0} - Version: {1}" -f $f.FullName, $f.FileVersionRaw) -Level Output
        }
    
        return $File | Sort-Object FileVersionRaw -Descending | Select-Object -First 1
    }

    $LoadedAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.FullName -like '*ScriptDom*'} | Sort-Object -Property ImageRuntimeVersion -Descending | Select-Object -First 1
    if ($LoadedAssembly) {
        return
    }
    Write-Msg "Starting script to load ScriptDom" -Level Starting
	$SearchPathList = @("${env:ProgramFiles}\Microsoft SQL Server")
    $SearchPathList += @("${env:ProgramFiles(x86)}\Microsoft SQL Server")
    $SearchPathList += @($ScriptPath)

	# Write-Msg "Searching for: Microsoft.SqlServer.TransactSql.ScriptDom.dll"
	$ScriptDomFile = Find-File -FileName "Microsoft.SqlServer.TransactSql.ScriptDom.dll" -PathList $SearchPathList | Select-Object -ExpandProperty FullName 
	if (-not $ScriptDomFile)
	{
		Write-Msg "Could not find the file: Microsoft.SqlServer.TransactSql.ScriptDom.dll" -Level Error
	}
    else
    {
        # Get FileVersion of new assembly
        $NewFileVersion = (Get-Item $ScriptDomFile).VersionInfo.FileVersionRaw

        $LoadedAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {$_.FullName -like '*ScriptDom*'} | Sort-Object -Property ImageRuntimeVersion -Descending | Select-Object -First 1
        if (-not $LoadedAssembly) {
            Write-Msg ("ScriptDom is not loaded, loading the latest available version {0}" -f $NewFileVersion)
            Add-Type -Path $ScriptDomFile
            Write-Msg "ScriptDom loaded successfully" -Level Finished
            return
        }
        $Location = $LoadedAssembly | Select-Object -ExpandProperty Location
        # Get FileVersion of loaded assembly
        $LoadedFileVersion = (Get-Item $Location).VersionInfo.FileVersionRaw
        if ($LoadedAssembly){
            Write-Msg ("ScriptDom type already loaded with version {0}" -f $LoadedFileVersion) -Level Output
        }

        # Check if the loaded assembly is older than the new assembly
        if ($NewFileVersion -gt $LoadedFileVersion) {
            throw ("ScriptDom type already loaded but with different version ({0}). Close and reopen the PowerShell session to unload the assembly and load the new version ({1})." -f $LoadedFileVersion, $NewFileVersion)
            # Write-Msg ("Adding ScriptDom type loaded successfully {0}" -f $ScriptDomFile) -Level Starting
            # Add-Type -Path $ScriptDomFile
            # Write-Msg "ScriptDom loaded successfully" -Level Finished               
        }
        else {
            Write-Msg "ScriptDom type already loaded and is the latest version" -Level Finished
        }
    }
}

try {
    $ScriptPath = Split-Path -parent $($MyInvocation.MyCommand.Definition)
    Import-ScriptDom -ScriptPath $ScriptPath
}
catch {
    Write-Msg -Message "Error trying to load ScriptDOM, check the following message for more info." -Level Error
    Write-Msg -Message "ErrorMessage: $($_.Exception.Message)" -Level Error
    return $null
}