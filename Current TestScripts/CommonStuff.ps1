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
    Get-InstalledSoftware -DisplayName 7zip

    Check whether application with name 7zip is installed on local computer.

    .EXAMPLE
    Get-InstalledSoftware -DisplayName 7zip -Property Publisher, Contact, VersionMajor -Ogv

    Check whether application with name 7zip is installed on local computer and output results to Out-GridView with just selected properties.

    .EXAMPLE
    Get-InstalledSoftware -ComputerName PC01

    Show all installed applications on computer PC01.
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

function Invoke-AsLoggedUser {
    <#
    .SYNOPSIS
    Function for running specified code under all logged users (impersonate the currently logged on user).
    Common use case is when code is running under SYSTEM and you need to run something under logged users (to modify user registry etc).

    .DESCRIPTION
    Function for running specified code under all logged users (impersonate the currently logged on user).
    Common use case is when code is running under SYSTEM and you need to run something under logged users (to modify user registry etc).

    You have to run this under SYSTEM account, or ADMIN account (but in such case helper sched. task will be created, content to run will be saved to disk and called from sched. task under SYSTEM account).

    Helper files and sched. tasks are automatically deleted.

    .PARAMETER ScriptBlock
    Scriptblock that should be run under logged users.

    .PARAMETER ComputerName
    Name of computer, where to run this.
    If specified, psremoting will be used to connect, this function with scriptBlock to run will be saved to disk and run through helper scheduled task under SYSTEM account.

    .PARAMETER ReturnTranscript
    Return output of the scriptBlock being run.

    .PARAMETER NoWait
    Don't wait for scriptBlock code finish.

    .PARAMETER UseWindowsPowerShell
    Use default PowerShell exe instead of of the one, this was launched under.

    .PARAMETER NonElevatedSession
    Run non elevated.

    .PARAMETER Visible
    Parameter description

    .PARAMETER CacheToDisk
    Necessity for long scriptBlocks. Content will be saved to disk and run from there.

    .PARAMETER Argument
    If you need to pass some variables to the scriptBlock.
    Hashtable where keys will be names of variables and values will be, well values :)

    Example:
    [hashtable]$Argument = @{
        name = "John"
        cities = "Boston", "Prague"
        hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }}
    }

    Will in beginning of the scriptBlock define variables:
    $name = 'John'
    $cities = 'Boston', 'Prague'
    $hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }

    ! ONLY STRING, ARRAY and HASHTABLE variables are supported !

    .EXAMPLE
    Invoke-AsLoggedUser {New-Item C:\temp\$env:username}

    On local computer will call given scriptblock under all logged users.

    .EXAMPLE
    Invoke-AsLoggedUser {New-Item "$env:USERPROFILE\$name"} -computerName PC-01 -ReturnTranscript -Argument @{name = 'someFolder'} -Verbose

    On computer PC-01 will call given scriptblock under all logged users i.e. will create folder 'someFolder' in root of each user profile.
    Transcript of the run scriptBlock will be outputted in console too.

    .NOTES
    Based on https://github.com/KelvinTegelaar/RunAsUser
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)]
        [string] $ComputerName,
        [Parameter(Mandatory = $false)]
        [switch] $ReturnTranscript,
        [Parameter(Mandatory = $false)]
        [switch]$NoWait,
        [Parameter(Mandatory = $false)]
        [switch]$UseWindowsPowerShell,
        [Parameter(Mandatory = $false)]
        [switch]$NonElevatedSession,
        [Parameter(Mandatory = $false)]
        [switch]$Visible,
        [Parameter(Mandatory = $false)]
        [switch]$CacheToDisk,
        [Parameter(Mandatory = $false)]
        [hashtable]$Argument
    )

    if ($ReturnTranscript -and $NoWait) {
        throw "It is not possible to return transcript if you don't want to wait for code finish"
    }

    #region variables
    $TranscriptPath = "C:\78943728TEMP63287789\Invoke-AsLoggedUser.log"
    #endregion variables

    #region functions
    function Create-VariableTextDefinition {
        <#
        .SYNOPSIS
        Function will convert hashtable content to text definition of variables, where hash key is name of variable and hash value is therefore value of this new variable.

        .PARAMETER hashTable
        HashTable which content will be transformed to variables

        .PARAMETER returnHashItself
        Returns text representation of hashTable parameter value itself.

        .EXAMPLE
        [hashtable]$Argument = @{
            string = "jmeno"
            array = "neco", "necojineho"
            hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }}
        }

        Create-VariableTextDefinition $Argument
    #>

        [CmdletBinding()]
        [Parameter(Mandatory = $true)]
        param (
            [hashtable] $hashTable
            ,
            [switch] $returnHashItself
        )

        function _convertToStringRepresentation {
            param ($object)

            $type = $object.gettype()
            if (($type.Name -eq 'Object[]' -and $type.BaseType.Name -eq 'Array') -or ($type.Name -eq 'ArrayList')) {
                Write-Verbose "array"
                ($object | ForEach-Object {
                        _convertToStringRepresentation $_
                    }) -join ", "
            } elseif ($type.Name -eq 'HashTable' -and $type.BaseType.Name -eq 'Object') {
                Write-Verbose "hash"
                $hashContent = $object.getenumerator() | ForEach-Object {
                    '{0} = {1};' -f $_.key, (_convertToStringRepresentation $_.value)
                }
                "@{$hashContent}"
            } elseif ($type.Name -eq 'String') {
                Write-Verbose "string"
                "'$object'"
            } else {
                throw "undefined type"
            }
        }
        if ($returnHashItself) {
            _convertToStringRepresentation $hashTable
        } else {
            $hashTable.GetEnumerator() | % {
                $variableName = $_.Key
                $variableValue = _convertToStringRepresentation $_.value
                "`$$variableName = $variableValue"
            }
        }
    }

    function Get-LoggedOnUser {
        quser | Select-Object -Skip 1 | ForEach-Object {
            $CurrentLine = $_.Trim() -Replace '\s+', ' ' -Split '\s'
            $HashProps = @{
                UserName     = $CurrentLine[0]
                ComputerName = $env:COMPUTERNAME
            }

            # If session is disconnected different fields will be selected
            if ($CurrentLine[2] -eq 'Disc') {
                $HashProps.SessionName = $null
                $HashProps.Id = $CurrentLine[1]
                $HashProps.State = $CurrentLine[2]
                $HashProps.IdleTime = $CurrentLine[3]
                $HashProps.LogonTime = $CurrentLine[4..6] -join ' '
            } else {
                $HashProps.SessionName = $CurrentLine[1]
                $HashProps.Id = $CurrentLine[2]
                $HashProps.State = $CurrentLine[3]
                $HashProps.IdleTime = $CurrentLine[4]
                $HashProps.LogonTime = $CurrentLine[5..7] -join ' '
            }

            $obj = New-Object -TypeName PSCustomObject -Property $HashProps | Select-Object -Property UserName, ComputerName, SessionName, Id, State, IdleTime, LogonTime
            #insert a new type name for the object
            $obj.psobject.Typenames.Insert(0, 'My.GetLoggedOnUser')
            $obj
        }
    }

    function _Invoke-AsLoggedUser {
        if (!("RunAsUser.ProcessExtensions" -as [type])) {
            $source = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RunAsUser
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public readonly UInt32 SessionID;

            [MarshalAs(UnmanagedType.LPStr)]
            public readonly String pWinStationName;

            public readonly WTS_CONNECTSTATE_CLASS State;
        }
    }

    internal class NativeMethods
    {
        [DllImport("kernel32", SetLastError=true)]
        public static extern int WaitForSingleObject(
          IntPtr hHandle,
          int dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(
            IntPtr hSnapshot);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(
            ref IntPtr lpEnvironment,
            SafeHandle hToken,
            bool bInherit);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(
            SafeHandle hToken,
            String lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref NativeHelpers.STARTUPINFO lpStartupInfo,
            out NativeHelpers.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyEnvironmentBlock(
            IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            SafeHandle ExistingTokenHandle,
            uint dwDesiredAccess,
            IntPtr lpThreadAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out SafeNativeHandle DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            SafeHandle TokenHandle,
            uint TokenInformationClass,
            SafeMemoryBuffer TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(
            IntPtr pMemory);

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("Wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(
            uint SessionId,
            out SafeNativeHandle phToken);
    }

    internal class SafeMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }
        public SafeMemoryBuffer(IntPtr handle) : base(true)
        {
            base.SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeHandle() : base(true) { }
        public SafeNativeHandle(IntPtr handle) : base(true) { this.handle = handle; }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }

    internal enum SW
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_MAX = 10
    }

    internal enum TokenElevationType
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited,
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }

    internal enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive,
        WTSConnected,
        WTSConnectQuery,
        WTSShadow,
        WTSDisconnected,
        WTSIdle,
        WTSListen,
        WTSReset,
        WTSDown,
        WTSInit
    }

    public class Win32Exception : System.ComponentModel.Win32Exception
    {
        private string _msg;

        public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public Win32Exception(int errorCode, string message) : base(errorCode)
        {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }

        public override string Message { get { return _msg; } }
        public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
    }

    public static class ProcessExtensions
    {
        #region Win32 Constants

        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int CREATE_NO_WINDOW = 0x08000000;

        private const int CREATE_NEW_CONSOLE = 0x00000010;

        private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
        private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

        #endregion

        // Gets the user token from the currently active session
        private static SafeNativeHandle GetSessionUserToken(bool elevated)
        {
            var activeSessionId = INVALID_SESSION_ID;
            var pSessionInfo = IntPtr.Zero;
            var sessionCount = 0;

            // Get a handle to the user access token for the current active session.
            if (NativeMethods.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount))
            {
                try
                {
                    var arrayElementSize = Marshal.SizeOf(typeof(NativeHelpers.WTS_SESSION_INFO));
                    var current = pSessionInfo;

                    for (var i = 0; i < sessionCount; i++)
                    {
                        var si = (NativeHelpers.WTS_SESSION_INFO)Marshal.PtrToStructure(
                            current, typeof(NativeHelpers.WTS_SESSION_INFO));
                        current = IntPtr.Add(current, arrayElementSize);

                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        {
                            activeSessionId = si.SessionID;
                            break;
                        }
                    }
                }
                finally
                {
                    NativeMethods.WTSFreeMemory(pSessionInfo);
                }
            }

            // If enumerating did not work, fall back to the old method
            if (activeSessionId == INVALID_SESSION_ID)
            {
                activeSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
            }

            SafeNativeHandle hImpersonationToken;
            if (!NativeMethods.WTSQueryUserToken(activeSessionId, out hImpersonationToken))
            {
                throw new Win32Exception("WTSQueryUserToken failed to get access token.");
            }

            using (hImpersonationToken)
            {
                // First see if the token is the full token or not. If it is a limited token we need to get the
                // linked (full/elevated token) and use that for the CreateProcess task. If it is already the full or
                // default token then we already have the best token possible.
                TokenElevationType elevationType = GetTokenElevationType(hImpersonationToken);

                if (elevationType == TokenElevationType.TokenElevationTypeLimited && elevated == true)
                {
                    using (var linkedToken = GetTokenLinkedToken(hImpersonationToken))
                        return DuplicateTokenAsPrimary(linkedToken);
                }
                else
                {
                    return DuplicateTokenAsPrimary(hImpersonationToken);
                }
            }
        }

        public static int StartProcessAsCurrentUser(string appPath, string cmdLine = null, string workDir = null, bool visible = true,int wait = -1, bool elevated = true)
        {
            using (var hUserToken = GetSessionUserToken(elevated))
            {
                var startInfo = new NativeHelpers.STARTUPINFO();
                startInfo.cb = Marshal.SizeOf(startInfo);

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                //startInfo.lpDesktop = "winsta0\\default";

                IntPtr pEnv = IntPtr.Zero;
                if (!NativeMethods.CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                {
                    throw new Win32Exception("CreateEnvironmentBlock failed.");
                }
                try
                {
                    StringBuilder commandLine = new StringBuilder(cmdLine);
                    var procInfo = new NativeHelpers.PROCESS_INFORMATION();

                    if (!NativeMethods.CreateProcessAsUserW(hUserToken,
                        appPath, // Application Name
                        commandLine, // Command Line
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        dwCreationFlags,
                        pEnv,
                        workDir, // Working directory
                        ref startInfo,
                        out procInfo))
                    {
                        throw new Win32Exception("CreateProcessAsUser failed.");
                    }

                    try
                    {
                        NativeMethods.WaitForSingleObject( procInfo.hProcess, wait);
                        return procInfo.dwProcessId;
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(procInfo.hThread);
                        NativeMethods.CloseHandle(procInfo.hProcess);
                    }
                }
                finally
                {
                    NativeMethods.DestroyEnvironmentBlock(pEnv);
                }
            }
        }

        private static SafeNativeHandle DuplicateTokenAsPrimary(SafeHandle hToken)
        {
            SafeNativeHandle pDupToken;
            if (!NativeMethods.DuplicateTokenEx(hToken, 0, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenPrimary, out pDupToken))
            {
                throw new Win32Exception("DuplicateTokenEx failed.");
            }

            return pDupToken;
        }

        private static TokenElevationType GetTokenElevationType(SafeHandle hToken)
        {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 18))
            {
                return (TokenElevationType)Marshal.ReadInt32(tokenInfo.DangerousGetHandle());
            }
        }

        private static SafeNativeHandle GetTokenLinkedToken(SafeHandle hToken)
        {
            using (SafeMemoryBuffer tokenInfo = GetTokenInformation(hToken, 19))
            {
                return new SafeNativeHandle(Marshal.ReadIntPtr(tokenInfo.DangerousGetHandle()));
            }
        }

        private static SafeMemoryBuffer GetTokenInformation(SafeHandle hToken, uint infoClass)
        {
            int returnLength;
            bool res = NativeMethods.GetTokenInformation(hToken, infoClass, new SafeMemoryBuffer(IntPtr.Zero), 0,
                out returnLength);
            int errCode = Marshal.GetLastWin32Error();
            if (!res && errCode != 24 && errCode != 122)  // ERROR_INSUFFICIENT_BUFFER, ERROR_BAD_LENGTH
            {
                throw new Win32Exception(errCode, String.Format("GetTokenInformation({0}) failed to get buffer length", infoClass));
            }

            SafeMemoryBuffer tokenInfo = new SafeMemoryBuffer(returnLength);
            if (!NativeMethods.GetTokenInformation(hToken, infoClass, tokenInfo, returnLength, out returnLength))
                throw new Win32Exception(String.Format("GetTokenInformation({0}) failed", infoClass));

            return tokenInfo;
        }
    }
}
"@
            Add-Type -TypeDefinition $source -Language CSharp
        }
        if ($CacheToDisk) {
            $ScriptGuid = New-Guid
            $null = New-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
            $pwshcommand = "-ExecutionPolicy Bypass -Window Normal -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
        } else {
            $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
            $pwshcommand = "-ExecutionPolicy Bypass -Window Normal -EncodedCommand $($encodedcommand)"
        }
        $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
        if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
        if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) {
            Write-Error -Message "The encoded script is longer than the command line parameter limit. Please execute the script with the -CacheToDisk option."
            return
        }
        $privs = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' }
        if ($privs.State -eq "Disabled") {
            Write-Error -Message "Not running with correct privilege. You must run this script as system or have the SeDelegateSessionUserImpersonatePrivilege token."
            return
        } else {
            try {
                # Use the same PowerShell executable as the one that invoked the function, Unless -UseWindowsPowerShell is defined

                if (!$UseWindowsPowerShell) { $pwshPath = (Get-Process -Id $pid).Path } else { $pwshPath = "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" }
                if ($NoWait) { $ProcWaitTime = 1 } else { $ProcWaitTime = -1 }
                if ($NonElevatedSession) { $RunAsAdmin = $false } else { $RunAsAdmin = $true }
                [RunAsUser.ProcessExtensions]::StartProcessAsCurrentUser(
                    $pwshPath, "`"$pwshPath`" $pwshcommand", (Split-Path $pwshPath -Parent), $Visible, $ProcWaitTime, $RunAsAdmin)
                if ($CacheToDisk) { $null = Remove-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }
            } catch {
                Write-Error -Message "Could not execute as currently logged on user: $($_.Exception.Message)" -Exception $_.Exception
                return
            }
        }
    }
    #endregion functions

    #region prepare Invoke-Command parameters
    # export this function to remote session (so I am not dependant whether it exists there or not)
    $allFunctionDefs = "function Invoke-AsLoggedUser { ${function:Invoke-AsLoggedUser} }; function Create-VariableTextDefinition { ${function:Create-VariableTextDefinition} }; function Get-LoggedOnUser { ${function:Get-LoggedOnUser} }"

    $param = @{
        argumentList = $scriptBlock, $NoWait, $UseWindowsPowerShell, $NonElevatedSession, $Visible, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument
    }

    if ($computerName -and $computerName -notmatch "localhost|$env:COMPUTERNAME") {
        $param.computerName = $computerName
    }
    #endregion prepare Invoke-Command parameters

    #region rights checks
    $hasAdminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    $hasSystemRights = whoami /priv /fo csv | ConvertFrom-Csv | Where-Object { $_.'Privilege Name' -eq 'SeDelegateSessionUserImpersonatePrivilege' -and $_.State -eq "Enabled" }
    #HACK in remote session this detection incorrectly shows that I have rights, but than function will fail anyway
    if ((Get-Host).name -eq "ServerRemoteHost") { $hasSystemRights = $false }
    Write-Verbose "ADMIN: $hasAdminRights SYSTEM: $hasSystemRights"
    #endregion rights checks

    if ($param.computerName) {
        Write-Verbose "Will be run on remote computer $computerName"

        Invoke-Command @param -ScriptBlock {
            param ($scriptBlock, $NoWait, $UseWindowsPowerShell, $NonElevatedSession, $Visible, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument)

            foreach ($functionDef in $allFunctionDefs) {
                . ([ScriptBlock]::Create($functionDef))
            }

            # check that there is someone logged
            if ((Get-LoggedOnUser).state -notcontains "Active") {
                Write-Warning "On $env:COMPUTERNAME is no user logged in"
                return
            }

            # convert passed string back to scriptblock
            $scriptBlock = [Scriptblock]::Create($scriptBlock)

            $param = @{scriptBlock = $scriptBlock }
            if ($VerbosePreference -eq "Continue") { $param.verbose = $true }
            if ($NoWait) { $param.NoWait = $NoWait }
            if ($UseWindowsPowerShell) { $param.UseWindowsPowerShell = $UseWindowsPowerShell }
            if ($NonElevatedSession) { $param.NonElevatedSession = $NonElevatedSession }
            if ($Visible) { $param.Visible = $Visible }
            if ($CacheToDisk) { $param.CacheToDisk = $CacheToDisk }
            if ($ReturnTranscript) { $param.ReturnTranscript = $ReturnTranscript }
            if ($Argument) { $param.Argument = $Argument }

            # run again "locally" on remote computer
            Invoke-AsLoggedUser @param
        }
    } elseif (!$ComputerName -and !$hasSystemRights -and $hasAdminRights) {
        # create helper sched. task, that will under SYSTEM account run given scriptblock using Invoke-AsLoggedUser
        Write-Verbose "Running locally as ADMIN"

        # create helper script, that will be called from sched. task under SYSTEM account
        if ($VerbosePreference -eq "Continue") { $VerboseParam = "-Verbose" }
        if ($ReturnTranscript) { $ReturnTranscriptParam = "-ReturnTranscript" }
        if ($NoWait) { $NoWaitParam = "-NoWait" }
        if ($UseWindowsPowerShell) { $UseWindowsPowerShellParam = "-UseWindowsPowerShell" }
        if ($NonElevatedSession) { $NonElevatedSessionParam = "-NonElevatedSession" }
        if ($Visible) { $VisibleParam = "-Visible" }
        if ($CacheToDisk) { $CacheToDiskParam = "-CacheToDisk" }
        if ($Argument) {
            $ArgumentHashText = Create-VariableTextDefinition $Argument -returnHashItself
            $ArgumentParam = "-Argument $ArgumentHashText"
        }

        $helperScriptText = @"
# define function Invoke-AsLoggedUser
$allFunctionDefs

`$scriptBlockText = @'
$($ScriptBlock.ToString())
'@

# transform string to scriptblock
`$scriptBlock = [Scriptblock]::Create(`$scriptBlockText)

# run scriptblock under all local logged users
Invoke-AsLoggedUser -ScriptBlock `$scriptblock $VerboseParam $ReturnTranscriptParam $NoWaitParam $UseWindowsPowerShellParam $NonElevatedSessionParam $VisibleParam $CacheToDiskParam $ArgumentParam
"@

        Write-Verbose "####### HELPER SCRIPT TEXT"
        Write-Verbose $helperScriptText
        Write-Verbose "####### END"

        $tmpScript = "$env:windir\Temp\$(Get-Random).ps1"
        Write-Verbose "Creating helper script $tmpScript"
        $helperScriptText | Out-File -FilePath $tmpScript -Force -Encoding utf8

        # create helper sched. task
        $taskName = "RunAsUser_" + (Get-Random)
        Write-Verbose "Creating helper scheduled task $taskName"
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File `"$tmpScript`""
        Register-ScheduledTask -TaskName $taskName -User "NT AUTHORITY\SYSTEM" -Action $taskAction -RunLevel Highest -Settings $taskSettings -Force | Out-Null

        # start helper sched. task
        Write-Verbose "Starting helper scheduled task $taskName"
        Start-ScheduledTask $taskName

        # wait for helper sched. task finish
        while ((Get-ScheduledTask $taskName -ErrorAction silentlyContinue).state -ne "Ready") {
            Write-Warning "Waiting for task $taskName to finish"
            Start-Sleep -Milliseconds 200
        }
        if (($lastTaskResult = (Get-ScheduledTaskInfo $taskName).lastTaskResult) -ne 0) {
            Write-Error "Task failed with error $lastTaskResult"
        }

        # delete helper sched. task
        Write-Verbose "Removing helper scheduled task $taskName"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

        # delete helper script
        Write-Verbose "Removing helper script $tmpScript"
        Remove-Item $tmpScript -Force

        # read & delete transcript
        if ($ReturnTranscript) {
            # return just interesting part of transcript
            if (Test-Path $TranscriptPath) {
                $transcriptContent = (Get-Content $TranscriptPath -Raw) -Split [regex]::escape('**********************')
                # return user name, under which command was run
                $runUnder = $transcriptContent[1] -split "`n" | Where-Object { $_ -match "Username: " } | ForEach-Object { ($_ -replace "Username: ").trim() }
                Write-Warning "Command run under: $runUnder"
                # return command output
                ($transcriptContent[2] -split "`n" | Select-Object -Skip 2 | Select-Object -SkipLast 3) -join "`n"

                Remove-Item (Split-Path $TranscriptPath -Parent) -Recurse -Force
            } else {
                Write-Warning "There is no transcript, command probably failed!"
            }
        }
    } elseif (!$ComputerName -and !$hasSystemRights -and !$hasAdminRights) {
        throw "Insufficient rights (not ADMIN nor SYSTEM)"
    } elseif (!$ComputerName -and $hasSystemRights) {
        Write-Verbose "Running locally as SYSTEM"

        if ($Argument -or $ReturnTranscript) {
            # define passed variables
            if ($Argument) {
                # convert hash to variables text definition
                $VariableTextDef = Create-VariableTextDefinition $Argument
            }

            if ($ReturnTranscript) {
                # modify scriptBlock to contain creation of transcript
                #TODO pro kazdeho uzivatele samostatny transcript a pak je vsechny zobrazit
                $TranscriptStart = "Start-Transcript $TranscriptPath -Append" # append because code can run under more than one user at a time
                $TranscriptEnd = 'Stop-Transcript'
            }

            $ScriptBlockContent = ($TranscriptStart + "`n`n" + $VariableTextDef + "`n`n" + $ScriptBlock.ToString() + "`n`n" + $TranscriptStop)
            Write-Verbose "####### SCRIPTBLOCK TO RUN"
            Write-Verbose $ScriptBlockContent
            Write-Verbose "#######"
            $scriptBlock = [Scriptblock]::Create($ScriptBlockContent)
        }

        _Invoke-AsLoggedUser
    } else {
        throw "undefined"
    }
}

function Invoke-AsSystem {
    <#
    .SYNOPSIS
    Function for running specified code under SYSTEM account.

    .DESCRIPTION
    Function for running specified code under SYSTEM account.

    Helper files and sched. tasks are automatically deleted.

    .PARAMETER scriptBlock
    Scriptblock that should be run under SYSTEM account.

    .PARAMETER computerName
    Name of computer, where to run this.

    .PARAMETER returnTranscript
    Add creating of transcript to specified scriptBlock and returns its output.

    .PARAMETER cacheToDisk
    Necessity for long scriptBlocks. Content will be saved to disk and run from there.

    .PARAMETER argument
    If you need to pass some variables to the scriptBlock.
    Hashtable where keys will be names of variables and values will be, well values :)

    Example:
    [hashtable]$Argument = @{
        name = "John"
        cities = "Boston", "Prague"
        hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }}
    }

    Will in beginning of the scriptBlock define variables:
    $name = 'John'
    $cities = 'Boston', 'Prague'
    $hash = @{var1 = 'value1','value11'; var2 = @{ key ='value' }

    ! ONLY STRING, ARRAY and HASHTABLE variables are supported !

    .PARAMETER runAs
    Let you change if scriptBlock should be running under SYSTEM, LOCALSERVICE or NETWORKSERVICE account.

    Default is SYSTEM.

    .EXAMPLE
    Invoke-AsSystem {New-Item $env:TEMP\abc}

    On local computer will call given scriptblock under SYSTEM account.

    .EXAMPLE
    Invoke-AsSystem {New-Item "$env:TEMP\$name"} -computerName PC-01 -ReturnTranscript -Argument @{name = 'someFolder'} -Verbose

    On computer PC-01 will call given scriptblock under SYSTEM account i.e. will create folder 'someFolder' in C:\Windows\Temp.
    Transcript will be outputted in console too.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock] $scriptBlock,

        [string] $computerName,

        [switch] $returnTranscript,

        [hashtable] $argument,

        [ValidateSet('SYSTEM', 'NETWORKSERVICE', 'LOCALSERVICE')]
        [string] $runAs = "SYSTEM",

        [switch] $CacheToDisk
    )

    (Get-Variable runAs).Attributes.Clear()
    $runAs = "NT Authority\$runAs"

    #region prepare Invoke-Command parameters
    # export this function to remote session (so I am not dependant whether it exists there or not)
    $allFunctionDefs = "function Create-VariableTextDefinition { ${function:Create-VariableTextDefinition} }"

    $param = @{
        argumentList = $scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument
    }

    if ($computerName -and $computerName -notmatch "localhost|$env:COMPUTERNAME") {
        $param.computerName = $computerName
    } else {
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            throw "You don't have administrator rights"
        }
    }
    #endregion prepare Invoke-Command parameters

    Invoke-Command @param -ScriptBlock {
        param ($scriptBlock, $runAs, $CacheToDisk, $allFunctionDefs, $VerbosePreference, $ReturnTranscript, $Argument)

        foreach ($functionDef in $allFunctionDefs) {
            . ([ScriptBlock]::Create($functionDef))
        }

        $TranscriptPath = "$ENV:TEMP\Invoke-AsSYSTEM_$(Get-Random).log"

        if ($Argument -or $ReturnTranscript) {
            # define passed variables
            if ($Argument) {
                # convert hash to variables text definition
                $VariableTextDef = Create-VariableTextDefinition $Argument
            }

            if ($ReturnTranscript) {
                # modify scriptBlock to contain creation of transcript
                $TranscriptStart = "Start-Transcript $TranscriptPath"
                $TranscriptEnd = 'Stop-Transcript'
            }

            $ScriptBlockContent = ($TranscriptStart + "`n`n" + $VariableTextDef + "`n`n" + $ScriptBlock.ToString() + "`n`n" + $TranscriptStop)
            Write-Verbose "####### SCRIPTBLOCK TO RUN"
            Write-Verbose $ScriptBlockContent
            Write-Verbose "#######"
            $scriptBlock = [Scriptblock]::Create($ScriptBlockContent)
        }

        if ($CacheToDisk) {
            $ScriptGuid = New-Guid
            $null = New-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Value $ScriptBlock -Force
            $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -file `"$($ENV:TEMP)\$($ScriptGuid).ps1`""
        } else {
            $encodedcommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ScriptBlock))
            $pwshcommand = "-ExecutionPolicy Bypass -Window Hidden -noprofile -EncodedCommand $($encodedcommand)"
        }

        $OSLevel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
        if ($OSLevel -lt 6.2) { $MaxLength = 8190 } else { $MaxLength = 32767 }
        if ($encodedcommand.length -gt $MaxLength -and $CacheToDisk -eq $false) {
            throw "The encoded script is longer than the command line parameter limit. Please execute the script with the -CacheToDisk option."
        }

        try {
            #region create&run sched. task
            $A = New-ScheduledTaskAction -Execute "$($ENV:windir)\system32\WindowsPowerShell\v1.0\powershell.exe" -Argument $pwshcommand
            if ($runAs -match "\$") {
                # pod gMSA uctem
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType Password
            } else {
                # pod systemovym uctem
                $P = New-ScheduledTaskPrincipal -UserId $runAs -LogonType ServiceAccount
            }
            $S = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
            $taskName = "RunAsSystem_" + (Get-Random)
            try {
                $null = New-ScheduledTask -Action $A -Principal $P -Settings $S -ea Stop | Register-ScheduledTask -Force -TaskName $taskName -ea Stop
            } catch {
                if ($_ -match "No mapping between account names and security IDs was done") {
                    throw "Account $runAs doesn't exist or cannot be used on $env:COMPUTERNAME"
                } else {
                    throw "Unable to create helper scheduled task. Error was:`n$_"
                }
            }

            # run scheduled task
            Start-Sleep -Milliseconds 200
            Start-ScheduledTask $taskName

            # wait for sched. task to end
            Write-Verbose "waiting on sched. task end ..."
            $i = 0
            while (((Get-ScheduledTask $taskName -ErrorAction silentlyContinue).state -ne "Ready") -and $i -lt 500) {
                ++$i
                Start-Sleep -Milliseconds 200
            }

            # get sched. task result code
            $result = (Get-ScheduledTaskInfo $taskName).LastTaskResult

            # read & delete transcript
            if ($ReturnTranscript) {
                # return just interesting part of transcript
                if (Test-Path $TranscriptPath) {
                    $transcriptContent = (Get-Content $TranscriptPath -Raw) -Split [regex]::escape('**********************')
                    # return command output
                    ($transcriptContent[2] -split "`n" | Select-Object -Skip 2 | Select-Object -SkipLast 3) -join "`n"

                    Remove-Item $TranscriptPath -Force
                } else {
                    Write-Warning "There is no transcript, command probably failed!"
                }
            }

            if ($CacheToDisk) { $null = Remove-Item "$($ENV:TEMP)\$($ScriptGuid).ps1" -Force }

            try {
                Unregister-ScheduledTask $taskName -Confirm:$false -ea Stop
            } catch {
                throw "Unable to unregister sched. task $taskName. Please remove it manually"
            }

            if ($result -ne 0) {
                throw "Command wasn't successfully ended ($result)"
            }
            #endregion create&run sched. task
        } catch {
            throw $_.Exception
        }
    }
}

function Invoke-FileContentWatcher {
    <#
    .SYNOPSIS
    Function for monitoring file content.

    .DESCRIPTION
    Function for monitoring file content.
    Allows you to react on create of new line with specific content.

    Outputs line(s) that match searched string.

    .PARAMETER path
    Path to existing file that should be monitored.

    .PARAMETER searchString
    String that should be searched in newly added lines.

    .PARAMETER searchAsRegex
    Searched string is regex.

    .PARAMETER stopOnFirstMatch
    Switch for stopping search on first match.

    .EXAMPLE
    Invoke-FileContentWatcher -Path C:\temp\mylog.txt -searchString "Error occurred"

    Start monitoring of newly added lines in C:\temp\mylog.txt file. If some line should contain "Error occurred" string, whole line will be outputted into console.

    .EXAMPLE
    Invoke-FileContentWatcher -Path C:\temp\mylog.txt -searchString "Action finished" -stopOnFirstMatch

    Start monitoring of newly added lines in C:\temp\mylog.txt file. If some line should contain "Action finished" string, whole line will be outputted into console and function will end.
    #>

    [Alias("Watch-FileContent")]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $path,

        [Parameter(Mandatory = $true)]
        [string] $searchString,

        [switch] $searchAsRegex,

        [switch] $stopOnFirstMatch
    )

    $fileName = Split-Path $path -Leaf
    $jobName = "ContentWatcher_" + $fileName + "_" + (Get-Date).ToString('HH:mm.ss')

    $null = Start-Job -Name $jobName -ScriptBlock {
        param ($path, $searchString, $searchAsRegex)

        $gcParam = @{
            Path        = $path
            Wait        = $true
            Tail        = 0 # I am interested just in newly added lines
            ErrorAction = 'Stop'
        }

        if ($searchAsRegex) {
            Get-Content @gcParam | Where-Object { $_ -match "$searchString" }
        } else {
            Get-Content @gcParam | Where-Object { $_ -like "*$searchString*" }
        }
    } -ArgumentList $path, $searchString, $searchAsRegex

    while (1) {
        Start-Sleep -Milliseconds 300

        if ((Get-Job -Name $jobName).state -eq 'Completed') {
            $result = Get-Job -Name $jobName | Receive-Job

            Get-Job -Name $jobName | Remove-Job -Force

            throw "Watcher $jobName failed with error: $result"
        }

        if (Get-Job -Name $jobName | Receive-Job -Keep) {
            # searched string was found
            $result = Get-Job -Name $jobName | Receive-Job

            if ($stopOnFirstMatch) {
                Get-Job -Name $jobName | Remove-Job -Force

                return $result
            } else {
                $result
            }
        }
    }
}

function Invoke-FileSystemWatcher {
    <#
    .SYNOPSIS
    Function for monitoring changes made in given folder.

    .DESCRIPTION
    Function for monitoring changes made in given folder.
    Thanks to Action parameter, you can react as you wish.

    .PARAMETER PathToMonitor
    Path to folder to watch.

    .PARAMETER Filter
    How should name of file/folder to watch look like. Same syntax as for -like operator.

    Default is '*'.

    .PARAMETER IncludeSubdirectories
    Switch for monitoring also changes in subfolders.

    .PARAMETER Action
    What should happen, when change is detected. Value should be string quoted by @''@.

    Default is: @'
            $details = $event.SourceEventArgs
            $Name = $details.Name
            $FullPath = $details.FullPath
            $OldFullPath = $details.OldFullPath
            $OldName = $details.OldName
            $ChangeType = $details.ChangeType
            $Timestamp = $event.TimeGenerated
            if ($ChangeType -eq "Renamed") {
                $text = "{0} was {1} at {2} to {3}" -f $FullPath, $ChangeType, $Timestamp, $Name
            } else {
                $text = "{0} was {1} at {2}" -f $FullPath, $ChangeType, $Timestamp
            }
            Write-Host $text
    '@

    so outputting changes to console.

    .PARAMETER ChangeType
    What kind of actions should be monitored.
    Default is all i.e. "Created", "Changed", "Deleted", "Renamed"

    .PARAMETER NotifyFilter
    What kind of "sub" actions should be monitored. Can be used also to improve performance.
    More at https://docs.microsoft.com/en-us/dotnet/api/system.io.notifyfilters?view=netframework-4.8

    For example: 'FileName', 'DirectoryName', 'LastWrite'

    .EXAMPLE
    Invoke-FileSystemWatcher C:\temp "*.txt"

    Just changes to txt files in root of temp folder will be monitored.

    Just changes in name of files and folders in temp folder and its subfolders will be outputted to console and send by email.
    #>

    [CmdletBinding()]
    [Alias("Watch-FileSystem")]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                If (Test-Path -Path $_ -PathType Container) {
                    $true
                } else {
                    Throw "$_ doesn't exist or it's not a folder."
                }
            })]
        [string] $PathToMonitor
        ,
        [string] $Filter = "*"
        ,
        [switch] $IncludeSubdirectories
        ,
        [scriptblock] $Action = {
            $details = $event.SourceEventArgs
            $Name = $details.Name
            $FullPath = $details.FullPath
            $OldFullPath = $details.OldFullPath
            $OldName = $details.OldName
            $ChangeType = $details.ChangeType
            $Timestamp = $event.TimeGenerated
            if ($ChangeType -eq "Renamed") {
                $text = "{0} was {1} at {2} (previously {3})" -f $FullPath, $ChangeType, $Timestamp, $OldName
            } else {
                $text = "{0} was {1} at {2}" -f $FullPath, $ChangeType, $Timestamp
            }
            Write-Host $text
        }
        ,
        [ValidateSet("Created", "Changed", "Deleted", "Renamed")]
        [string[]] $ChangeType = ("Created", "Changed", "Deleted", "Renamed")
        ,
        [string[]] $NotifyFilter
    )

    $FileSystemWatcher = New-Object System.IO.FileSystemWatcher
    $FileSystemWatcher.Path = $PathToMonitor
    if ($IncludeSubdirectories) {
        $FileSystemWatcher.IncludeSubdirectories = $true
    }
    if ($Filter) {
        $FileSystemWatcher.Filter = $Filter
    }
    if ($NotifyFilter) {
        $NotifyFilter = $NotifyFilter -join ', '
        $FileSystemWatcher.NotifyFilter = [IO.NotifyFilters]$NotifyFilter
    }
    # Set emits events
    $FileSystemWatcher.EnableRaisingEvents = $true

    # Set event handlers
    $handlers = . {
        $changeType | ForEach-Object {
            Register-ObjectEvent -InputObject $FileSystemWatcher -EventName $_ -Action $Action -SourceIdentifier "FS$_"
        }
    }

    Write-Verbose "Watching for changes in $PathToMonitor where file/folder name like '$Filter'"

    try {
        do {
            Wait-Event -Timeout 1
        } while ($true)
    } finally {
        # End script actions + CTRL+C executes the remove event handlers
        $changeType | ForEach-Object {
            Unregister-Event -SourceIdentifier "FS$_"
        }

        # Remaining cleanup
        $handlers | Remove-Job

        $FileSystemWatcher.EnableRaisingEvents = $false
        $FileSystemWatcher.Dispose()

        Write-Warning -Message 'Event Handler completed and disabled.'
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
