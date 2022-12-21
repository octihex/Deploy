#region Setup
Set-Location $PSScriptRoot
Remove-Module PSScriptMenuGui -ErrorAction SilentlyContinue
try {
    Import-Module PSScriptMenuGui -ErrorAction Stop
}
catch {
    Write-Warning $_
    Write-Verbose 'Attempting to import from parent directory...'
    Import-Module '..\'
}
#endregion

$params = @{
    csvPath = '.\example_data.csv'
    windowTitle = 'Example with all options'
    buttonForegroundColor = 'Azure'
    iconPath = '.\pwsh7.ico'
    hideConsole = $true
    noExit = $true
    Verbose = $False
}
Show-ScriptMenuGui @params