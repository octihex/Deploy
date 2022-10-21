If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -F ($Myinvocation.MyCommand.Definition)) -WindowStyle Maximized
    Exit $LASTEXITCODE
}

If (!(Test-Path -PathType leaf -Path "C:\Program Files\Dell\DellOptimizer\DO-cli.exe"))
{
    "La detection automatique de Dell Optimizer a echoue."
    "Le script va se ferme."
    Pause
    Exit
}

Set-Location "C:\Program Files\Dell\DellOptimizer"
New-Item -ItemType "File" -Path ".\DO_Uninstall.log" -Force | Out-Null

If ((.\do-cli.exe /Get -Name=Network.State | Select-String -Pattern "Value:").Line.Split(" ")[-1] -eq "True") 
{
    .\do-cli.exe /configure -name=Network.State -value=False | Out-Null
    Out-File -FilePath ".\DO_Uninstall.log" -Append -Force -InputObject "L'option reseaux de Dell Optimizer viens d'etre desactiver." | Out-Null
}

If ((.\do-cli.exe /Get -Name=AppPerformance.State | Select-String -Pattern "Value:").Line.Split(" ")[-1] -eq "True") 
{
    .\do-cli.exe /configure -name=AppPerformance.State -value=False | Out-Null
    Out-File -FilePath ".\DO_Uninstall.log" -Append -Force -InputObject "L'option applications de Dell Optimizer viens d'etre desactiver." | Out-Null
}