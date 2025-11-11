# Check if function Write-Msg is already loaded, if not, load it
$ScriptPath = Split-Path -Parent $($MyInvocation.MyCommand.Definition)

function Write-Msg {
    param (
        [string]$Message = '',
		[string]$Level = 'Output', # Output|Warning|Error
        [switch]$VerboseMsg
    )
    $ForegroundColor = switch ($Level) {
        'Starting'  {'White'}
        'Finished'  {'Green'}
        'Output'  {'Cyan'}
        'Warning' {'Yellow'}
        'Error'   {'Red'}
        Default {'Cyan'}
    }
    $Level = switch ($Level) {
            'Starting' {'Starting'}
            'Finished' {'Finished'}
            'Output'   {'Output  '}
            'Warning'  {'Warning '}
            'Error'    {'Error   '}
    }    
    $dt = Get-Date -format "yyyy-MM-dd hh:mm:ss"
    if (($ShowVerboseMessages) -and ($VerboseMsg)){
        Write-Host ("[{0}] - $Level - {1} `r" -f $dt, $Message) -ForegroundColor $ForegroundColor
    }
    elseif ($false -eq $VerboseMsg) {
        Write-Host ("[{0}] - $Level - {1} `r" -f $dt, $Message) -ForegroundColor $ForegroundColor
    }
    if ($null -eq $script:TraceBuffer){
        $script:TraceBuffer = @()
    }
    if ($VerboseMsg) {$script:TraceBuffer += "[{0:HH:mm:ss.fff}] {1,-8} {2}" -f (Get-Date), $Level, $Message}
    
}

# Check if DbaTools module is already loaded, if not, try to import it
# Module may be installed but not imported into the PS scope session... if so, call import-module
if(-not (Get-Module -Name dbatools)){
    if(Get-Module -Name dbatools -ListAvailable){
        Write-Msg "dbatools is not imported but is available, running import-module to load it on this PS session."
        Import-Module dbatools -Force -ErrorAction Stop
    }
}
if(-not (Get-Module -Name dbatools)){
    Write-Msg "dbatools is not installed, trying to install"
    Write-Msg "Trying to manually install dbatools from `"$ScriptPath`" folder"
    if (Test-Path -Path "$ScriptPath\dbatools.zip" -PathType Leaf){
        try {
            foreach ($modpath in $($env:PSModulePath -split [IO.Path]::PathSeparator)) {
                #Grab the user's default home directory module path for later
                if ($modpath -like "*$([Environment]::UserName)*") {
                    $userpath = $modpath
                }
                try {
                    $temppath = Join-Path -Path $modpath -ChildPath "dbatools"
                    $localpath = (Get-ChildItem $temppath -ErrorAction Stop).FullName
                } catch {
                    $localpath = $null
                }
            }
            if ($null -eq $localpath) {
                if (!(Test-Path -Path $userpath)) {
                    try {
                        Write-Msg "Creating directory: $userpath"
                        New-Item -Path $userpath -ItemType Directory | Out-Null
                    } catch {
                        throw "Can't create $userpath. You may need to Run as Administrator: $_"
                    }
                }
                # In case dbatools is not currently installed in any PSModulePath put it in the $userpath
                if (Test-Path -Path $userpath) {
                    $localpath = $userpath
                }
            } else {
                Write-Msg "Updating current install"
            }
            $path = $localpath
            if (!(Test-Path -Path $path)) {
                try {
                    Write-Msg "Creating directory: $path"
                    New-Item -Path $path -ItemType Directory | Out-Null
                } catch {
                    throw "Can't create $path. You may need to Run as Administrator: $_"
                }
            }

            $dbatoolsDir = "$path"
            $OutZip = Join-Path $dbatoolsDir 'dbatools.zip'
            Copy-Item -Path "$ScriptPath\dbatools.zip" -Destination $OutZip -ErrorAction Stop | Out-Null
            if (Test-Path $OutZip) {
                Write-Msg "Trying to unzip $OutZip file"
                Add-Type -AssemblyName 'System.Io.Compression.FileSystem'
                [io.compression.zipfile]::ExtractToDirectory($OutZip, $dbatoolsDir)
            }
            else {
                throw "$OutZip file was not found"
            }
            $dbatools_library_path = Join-Path -Path $dbatoolsDir -ChildPath "dbatools.library"
            $dbatools_path = Join-Path -Path $dbatoolsDir -ChildPath "dbatools"
            Import-Module $dbatools_library_path -Force -ErrorAction Stop
            Import-Module $dbatools_path -Force -ErrorAction Stop
            Write-Msg "dbatools installed successfully"
        } catch {
            throw "Error trying to install dbatools from folder`n$_"
        }
    }
    else {
        throw "Could not find file $ScriptPath\dbatools.zip, please make sure you've copied dbatools.zip file to folder of this script."
    }
    if (-not (Get-Module -Name dbatools)) {
        try {
            Write-Msg "Trying to install dbatools via Install-Module"
            Install-Module dbatools -Scope CurrentUser -Confirm:$False -Force -ErrorAction Stop | Out-Null
            Import-Module dbatools -Force -ErrorAction Stop
        } catch {
            $Err = (Get-ErrorMessage -Record $_)
            Write-Msg "Error trying to install dbatools via Install-Module" -Level Error
            Write-Msg "ErrorMessage: $Err" -Level Error
        }
    }
}

if(Get-Module -Name dbatools){
    $trustcert = Get-DbatoolsConfig -FullName 'sql.connection.trustcert' | Select-Object -ExpandProperty Value
    if (!$trustcert){
        Set-DbatoolsConfig -FullName 'sql.connection.trustcert' -Value $true -Register
        Set-DbatoolsConfig -Name Import.EncryptionMessageCheck -Value $false -PassThru -Register
    }
}

# Check if dbatools module was loaded successfully, if not, return
if (-not (Get-Module -Name dbatools)) {
    Write-Msg "dbatools is not installed, please install it before continue" -Level Error
    return
}
function Invoke-Command2 {
    <#
        .SYNOPSIS
            Wrapper function that calls Invoke-Command and gracefully handles credentials.

        .DESCRIPTION
            Wrapper function that calls Invoke-Command and gracefully handles credentials.

        .PARAMETER ComputerName
            Default: $env:COMPUTERNAME
            The computer to invoke the scriptblock on.

        .PARAMETER Credential
            The credentials to use.
            Can accept $null on older PowerShell versions, since it expects type object, not PSCredential

        .PARAMETER ScriptBlock
            The code to run on the targeted system

        .PARAMETER InputObject
            Object that could be used in the ScriptBlock as $Input.
            NOTE:
            The object will be de-serialized once passed through the remote pipeline.
            Some objects (like hashtables) do not support de-serialization.

        .PARAMETER Authentication
            Choose an authentication to use for the connection

        .PARAMETER ConfigurationName
            Name of the remote PSSessionConfiguration to use.
            Should be registered already using Register-PSSessionConfiguration or internal Register-RemoteSessionConfiguration.

        .PARAMETER UseSSL
            Enables SSL

        .PARAMETER Port
            Uses a specific Port to connect

        .PARAMETER ArgumentList
            Any arguments to pass to the scriptblock being run

        .PARAMETER Raw
            Passes through the raw return data, rather than prettifying stuff.

        .PARAMETER RequiredPSVersion
            Verifies that remote Powershell version is meeting specified requirements.

        .EXAMPLE
            PS C:\> Invoke-Command2 -ComputerName sql2014 -Credential $Credential -ScriptBlock { dir }

            Executes the scriptblock '{ dir }' on the computer sql2014 using the credentials stored in $Credential.
            If $Credential is null, no harm done.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUsePSCredentialType", "")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
    param (
        [DbaInstanceParameter]$ComputerName = $env:COMPUTERNAME,
        [object]$Credential,
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [parameter(ValueFromPipeline)]
        [object[]]$InputObject,
        [ValidateSet('Default', 'Basic', 'Negotiate', 'NegotiateWithImplicitCredential', 'Credssp', 'Digest', 'Kerberos')]
        [string]$Authentication = 'Default',
        [string]$ConfigurationName,
        [switch]$UseSSL = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSession.UseSSL' -Fallback $false),
        [nullable[int]]$Port = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSession.Port' -Fallback $null),
        [switch]$Raw,
        [version]$RequiredPSVersion
    )
    <# Note: Credential stays as an object type for legacy reasons. #>

    $InvokeCommandSplat = @{ }
    if ($ArgumentList) {
        $InvokeCommandSplat["ArgumentList"] = $ArgumentList
    }
    if ($InputObject) {
        $InvokeCommandSplat["InputObject"] = $InputObject
    }
    if (-not $ComputerName.IsLocalHost) {
        $runspaceId = [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.InstanceId
        # sessions with different Authentication should have different session names
        if ($ConfigurationName) {
            $sessionName = "dbatools_$($Authentication)_$($ConfigurationName)_$($runspaceId)_$($ComputerName.ComputerName)"
        } else {
            $sessionName = "dbatools_$($Authentication)_$($runspaceId)_$($ComputerName.ComputerName)"
        }

        # Retrieve a session from the session cache, if available (it's unique per runspace)
        $currentSession = [Dataplat.Dbatools.Connection.ConnectionHost]::PSSessionGet($runspaceId, $sessionName) | Where-Object { $_.State -Match "Opened|Disconnected" }
        if (-not $currentSession) {
            Write-Message -Level Debug "Creating new $Authentication session [$sessionName] for $($ComputerName.ComputerName)"
            $psSessionSplat = @{
                ComputerName   = $ComputerName.ComputerName
                Authentication = $Authentication
                Name           = $sessionName
                ErrorAction    = 'Stop'
                UseSSL         = $UseSSL
            }
            if (($null -ne $Port) -and ($Port -gt 0)) {
                $psSessionSplat.Port = $Port
                Write-Message -Level Verbose -Message "Using Port: $($psSessionSplat.Port)"
            }
            if (Test-Windows -NoWarn) {
                $psSessionOptionsSplat = @{
                    IdleTimeout         = (New-TimeSpan -Minutes 10).TotalMilliSeconds
                    IncludePortInSPN    = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSessionOption.IncludePortInSPN' -Fallback $false)
                    SkipCACheck         = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSessionOption.SkipCACheck' -Fallback $false)
                    SkipCNCheck         = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSessionOption.SkipCNCheck' -Fallback $false)
                    SkipRevocationCheck = (Get-DbatoolsConfigValue -FullName 'PSRemoting.PsSessionOption.SkipRevocationCheck' -Fallback $false)
                }
                $sessionOption = New-PSSessionOption @psSessionOptionsSplat
                $psSessionSplat += @{ SessionOption = $sessionOption }
            }
            if ($Credential) {
                $psSessionSplat += @{ Credential = $Credential }
            }
            if ($ConfigurationName) {
                $psSessionSplat += @{ ConfigurationName = $ConfigurationName }
            }
            $currentSession = New-PSSession @psSessionSplat
            $InvokeCommandSplat["Session"] = $currentSession
        } else {
            Write-Message -Level Debug "Found an existing session $sessionName, reusing it"
            if ($currentSession.State -eq "Disconnected") {
                $null = $currentSession | Connect-PSSession -ErrorAction Stop
            }
            $InvokeCommandSplat["Session"] = $currentSession

            # Refresh the session registration if registered, to reset countdown until purge
            [Dataplat.Dbatools.Connection.ConnectionHost]::PSSessionSet($runspaceId, $sessionName, $currentSession)
        }
    }
    if ($RequiredPSVersion) {
        $remoteVersion = Invoke-Command @InvokeCommandSplat -ScriptBlock { $PSVersionTable }
        if ($remoteVersion.PSVersion -and $remoteVersion.PSVersion -lt $RequiredPSVersion) {
            throw "Remote PS version $($remoteVersion.PSVersion) is less than defined requirement ($RequiredPSVersion)"
        }
    }

    $InvokeCommandSplat.ScriptBlock = $ScriptBlock
    if ($Raw) {
        Invoke-Command @InvokeCommandSplat
    } else {
        Invoke-Command @InvokeCommandSplat | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    }

    if (-not $ComputerName.IsLocalhost) {
        # Tell the system to clean up if the session expires
        [Dataplat.Dbatools.Connection.ConnectionHost]::PSSessionSet($runspaceId, $sessionName, $currentSession)

        if (-not (Get-DbatoolsConfigValue -FullName 'PSRemoting.Sessions.Enable' -Fallback $true)) {
            $currentSession | Remove-PSSession
        }
    }
}

# Check if ImportExcel module is already loaded, if not, try to import it
# Module may be installed but not imported into the PS scope session... if so, call import-module
if(-not (Get-Module -Name ImportExcel)){
    if(Get-Module -Name ImportExcel -ListAvailable){
        Write-Msg "ImportExcel is not imported but is available, running import-module to load it on this PS session."
        Import-Module ImportExcel -Force -ErrorAction Stop
    }
}

if(-not (Get-Module -Name ImportExcel)){
    Write-Msg "ImportExcel is not installed, trying to install"
    Write-Msg "Trying to manually install ImportExcel from Util folder"
    if (Test-Path -Path "$ScriptPath\ImportExcel.zip" -PathType Leaf){
        try {
            foreach ($modpath in $($env:PSModulePath -split [IO.Path]::PathSeparator)) {
                #Grab the user's default home directory module path for later
                if ($modpath -like "*$([Environment]::UserName)*") {
                    $userpath = $modpath
                }
                try {
                    $temppath = Join-Path -Path $modpath -ChildPath "ImportExcel"
                    $localpath = (Get-ChildItem $temppath -ErrorAction Stop).FullName
                } catch {
                    $localpath = $null
                }
            }
            if ($null -eq $localpath) {
                if (!(Test-Path -Path $userpath)) {
                    try {
                        Write-Msg "Creating directory: $userpath"
                        New-Item -Path $userpath -ItemType Directory | Out-Null
                    } catch {
                        throw "Can't create $userpath. You may need to Run as Administrator: $_"
                    }
                }
                # In case ImportExcel is not currently installed in any PSModulePath put it in the $userpath
                if (Test-Path -Path $userpath) {
                    $localpath = Join-Path -Path $userpath -ChildPath "ImportExcel"
                }
            } else {
                Write-Msg "Updating current install"
            }
            $path = $localpath
            if (!(Test-Path -Path $path)) {
                try {
                    Write-Msg "Creating directory: $path"
                    New-Item -Path $path -ItemType Directory | Out-Null
                } catch {
                    throw "Can't create $path. You may need to Run as Administrator: $_"
                }
            }

            $ImportExcelDir = "$path"
            $OutZip = Join-Path $ImportExcelDir 'ImportExcel.zip'
            Copy-Item -Path "$ScriptPath\ImportExcel.zip" -Destination $OutZip -ErrorAction Stop | Out-Null
            if (Test-Path $OutZip) {
                Write-Msg "Trying to unzip $OutZip file"
                Add-Type -AssemblyName 'System.Io.Compression.FileSystem'
                [io.compression.zipfile]::ExtractToDirectory($OutZip, $ImportExcelDir)
                if (Test-Path "$ImportExcelDir\ImportExcel.psd1") {
                    Write-Msg "File extracted to $ImportExcelDir"
                }
            }
            else {
                throw "$OutZip file was not found"
            }
            Import-Module $ImportExcelDir -Force -ErrorAction Stop
            Write-Msg "ImportExcel installed successfully"
        } catch {
            Enable-Buttons
            $Err = (Get-ErrorMessage -Record $_)
            Write-Msg "Error trying to install ImportExcel from Util folder" -Level Error
            Write-Msg "ErrorMessage: $Err" -Level Error
        }
    }
    else {
        Write-Msg "Could not find file $ScriptPath\ImportExcel.zip, please make sure you've copied ImportExcel.zip file to Util folder of this script." -Level Error
        fnReturn
    }
    if (-not (Get-Module -Name ImportExcel)) {
        try {
            Write-Msg "Trying to install ImportExcel via Install-Module"
            Install-Module ImportExcel -Scope CurrentUser -Confirm:$False -Force -ErrorAction Stop | Out-Null
            Import-Module ImportExcel -Force -ErrorAction Stop
        } catch {
            Enable-Buttons
            Write-Msg "Error trying to install ImportExcel via Install-Module" -Level Error
            $Err = (Get-ErrorMessage -Record $_) 
            Write-Msg "ErrorMessage: $Err" -Level Error
        }
    }
}
# Check if ImportExcel module was loaded successfully, if not, return
if (-not (Get-Module -Name ImportExcel)) {
    Write-Msg "ImportExcel is not installed, please install it before continue" -Level Error
    return
}