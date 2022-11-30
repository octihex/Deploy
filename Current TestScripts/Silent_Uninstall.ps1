#Script honteusement volé sur powershellgallery.com/packages/CommonStuff

function Get-InstalledSoftware {
    <#
    .SYNOPSIS
    Function returns installed applications.

    .DESCRIPTION
    Function returns installed applications.
    Such information is retrieved from registry keys 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'.

    .PARAMETER ComputerName
    Name of the remote computer where you want to run this function.

    .PARAMETER AppName
    (optional) Name of the application(s) to look for.
    It can be just part of the app name.

    .PARAMETER DontIgnoreUpdates
    Switch for getting Windows Updates too.

    .PARAMETER Property
    What properties of the registry key should be returned.

    Default is 'DisplayVersion', 'UninstallString'.

    DisplayName will be always returned no matter what.

    .PARAMETER Ogv
    Switch for getting results in Out-GridView.

    .EXAMPLE
    Get-InstalledSoftware

    Show all installed applications on local computer

    .EXAMPLE
    Get-InstalledSoftware -AppName Dell, Zip

    Check whether applications with name Dell or Zip is installed.

    .EXAMPLE
    Get-InstalledSoftware -AppName Dell -Property Publisher, Contact, VersionMajor -Ogv

    Check whether application with name Dell is installed and output results to Out-GridView.
    #>

    [CmdletBinding()]
    param(
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object { try { Get-ItemPropertyValue -Path $_.pspath -Name DisplayName -ErrorAction Stop } catch { $null } } | Where-Object { $_ -like "*$WordToComplete*" } | ForEach-Object { "'$_'" }
            })]
        [string[]] $appName,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $computerName,

        [switch] $dontIgnoreUpdates,

        [ValidateNotNullOrEmpty()]
        [ValidateSet('AuthorizedCDFPrefix', 'Comments', 'Contact', 'DisplayName', 'DisplayVersion', 'EstimatedSize', 'HelpLink', 'HelpTelephone', 'InstallDate', 'InstallLocation', 'InstallSource', 'Language', 'ModifyPath', 'NoModify', 'NoRepair', 'Publisher', 'QuietUninstallString', 'UninstallString', 'URLInfoAbout', 'URLUpdateInfo', 'Version', 'VersionMajor', 'VersionMinor', 'WindowsInstaller')]
        [string[]] $property = ('DisplayName', 'DisplayVersion', 'UninstallString'),

        [switch] $ogv
    )

    PROCESS {
        $scriptBlock = {
            param ($Property, $DontIgnoreUpdates, $appName)

            # where to search for applications
            $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

            # define what properties should be outputted
            $SelectProperty = @('DisplayName') # DisplayName will be always outputted
            if ($Property) {
                $SelectProperty += $Property
            }
            $SelectProperty = $SelectProperty | Select-Object -Unique

            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)
            if (!$RegBase) {
                Write-Error "Unable to open registry on $env:COMPUTERNAME"
                return
            }

            foreach ($RegKey in $RegistryLocation) {
                Write-Verbose "Checking '$RegKey'"
                foreach ($appKeyName in $RegBase.OpenSubKey($RegKey).GetSubKeyNames()) {
                    Write-Verbose "`t'$appKeyName'"
                    $ObjectProperty = [ordered]@{}
                    foreach ($CurrentProperty in $SelectProperty) {
                        Write-Verbose "`t`tGetting value of '$CurrentProperty' in '$RegKey$appKeyName'"
                        $ObjectProperty.$CurrentProperty = ($RegBase.OpenSubKey("$RegKey$appKeyName")).GetValue($CurrentProperty)
                    }

                    if (!$ObjectProperty.DisplayName) {
                        # Skipping. There are some weird records in registry key that are not related to any app"
                        continue
                    }

                    $ObjectProperty.ComputerName = $env:COMPUTERNAME

                    # create final object
                    $appObj = New-Object -TypeName PSCustomObject -Property $ObjectProperty

                    if ($appName) {
                        $appNameRegex = $appName | ForEach-Object {
                            [regex]::Escape($_)
                        }
                        $appNameRegex = $appNameRegex -join "|"
                        $appObj = $appObj | Where-Object { $_.DisplayName -match $appNameRegex }
                    }

                    if (!$DontIgnoreUpdates) {
                        $appObj = $appObj | Where-Object { $_.DisplayName -notlike "*Update for Microsoft*" -and $_.DisplayName -notlike "Security Update*" }
                    }

                    $appObj
                }
            }
        }

        $param = @{
            scriptBlock  = $scriptBlock
            ArgumentList = $property, $dontIgnoreUpdates, $appName
        }
        if ($computerName) {
            $param.computerName = $computerName
            $param.HideComputerName = $true
        }

        $result = Invoke-Command @param

        if ($computerName) {
            $result = $result | Select-Object * -ExcludeProperty RunspaceId
        }
    }

    END {
        if ($ogv) {
            $comp = $env:COMPUTERNAME
            if ($computerName) { $comp = $computerName }
            $result | Out-GridView -PassThru -Title "Installed software on $comp"
        } else {
            $result
        }
    }
}

function Uninstall-ApplicationViaUninstallString {
    <#
    .SYNOPSIS
    Function for uninstalling applications using uninstall string (command) that is saved in registry for each application.

    .DESCRIPTION
    Function for uninstalling applications using uninstall string (command) that is saved in registry for each application.
    This functions cannot guarantee that uninstall process will be unattended!

    .PARAMETER name
    Name of the application(s) to uninstall.
    Can be retrieved using function Get-InstalledSoftware.

    .PARAMETER addArgument
    Argument that should be added to those from uninstall string.
    Can be helpful if you need to do unattended uninstall and know the right parameter for it.

    .EXAMPLE
    Uninstall-ApplicationViaUninstallString -name "7-Zip 22.01 (x64)"

    Uninstall 7zip application.

    .EXAMPLE
    Get-InstalledSoftware -appName Dell | Uninstall-ApplicationViaUninstallString

    Uninstall every application that has 'Dell' in its name.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("displayName")]
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object { try { Get-ItemPropertyValue -Path $_.pspath -Name DisplayName -ErrorAction Stop } catch { $null } } | Where-Object { $_ -like "*$WordToComplete*" } | ForEach-Object { "'$_'" }
            })]
        [string[]] $name,

        [string] $addArgument
    )

    begin {
        # without admin rights msiexec uninstall fails without any error
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "Run with administrator rights"
        }

        if (!(Get-Command Get-InstalledSoftware)) {
            throw "Function Get-InstalledSoftware is missing"
        }
    }

    process {
        $appList = Get-InstalledSoftware -property DisplayName, UninstallString, QuietUninstallString | Where-Object DisplayName -In $name

        if ($appList) {
            foreach ($app in $appList) {
                if ($app.QuietUninstallString) {
                    $uninstallCommand = $app.QuietUninstallString
                } else {
                    $uninstallCommand = $app.UninstallString
                }
                $name = $app.DisplayName

                if (!$uninstallCommand) {
                    Write-Warning "Uninstall command is not defined for app '$name'"
                    continue
                }

                if ($uninstallCommand -like "msiexec.exe*") {
                    # it is MSI
                    $uninstallMSIArgument = $uninstallCommand -replace "MsiExec.exe"
                    # sometimes there is /I (install) instead of /X (uninstall) parameter
                    $uninstallMSIArgument = $uninstallMSIArgument -replace "/I", "/X"
                    # add silent and norestart switches
                    $uninstallMSIArgument = "$uninstallMSIArgument /QN"
                    if ($addArgument) {
                        $uninstallMSIArgument = $uninstallMSIArgument + " " + $addArgument
                    }
                    Write-Warning "Uninstalling app '$name' via: msiexec.exe $uninstallMSIArgument"
                    Start-Process "msiexec.exe" -ArgumentList $uninstallMSIArgument -Wait
                } else {
                    # it is EXE
                    #region extract path to the EXE uninstaller
                    # path to EXE is typically surrounded by double quotes
                    $match = ([regex]'("[^"]+")(.*)').Matches($uninstallCommand)
                    if (!$match.count) {
                        # string doesn't contain ", try search for ' instead
                        $match = ([regex]"('[^']+')(.*)").Matches($uninstallCommand)
                    }
                    if ($match.count) {
                        $uninstallExe = $match.captures.groups[1].value
                    } else {
                        # string doesn't contain even '
                        # before blindly use the whole string as path to an EXE, check whether it doesn't contain common argument prefixes '/', '-' ('-' can be part of the EXE path, but it is more safe to make false positive then fail later because of faulty command)
                        if ($uninstallCommand -notmatch "/|-") {
                            $uninstallExe = $uninstallCommand
                        }
                    }
                    if (!$uninstallExe) {
                        Write-Error "Unable to extract EXE path from '$uninstallCommand'"
                        continue
                    }
                    #endregion extract path to the EXE uninstaller
                    if ($match.count) {
                        $uninstallExeArgument = $match.captures.groups[2].value
                    } else {
                        Write-Verbose "I've used whole uninstall string as EXE path"
                    }
                    if ($addArgument) {
                        $uninstallExeArgument = $uninstallExeArgument + " " + $addArgument
                    }
                    # Start-Process param block
                    $param = @{
                        FilePath = $uninstallExe
                        Wait     = $true
                    }
                    if ($uninstallExeArgument) {
                        $param.ArgumentList = $uninstallExeArgument
                    }
                    Write-Warning "Uninstalling app '$name' via: $uninstallExe $uninstallExeArgument"
                    Start-Process @param
                }
            }
        } else {
            Write-Warning "No software with name $($name -join ', ') was found. Get the correct name by running 'Get-InstalledSoftware' function."
        }
    }
}
