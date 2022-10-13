If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -ExecutionPolicy Unrestricted -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

$host.UI.RawUI.WindowTitle = "Installation Poste - Etape 2 - MAJs Windows"

If (!(Get-InstalledModule -Name PSWindowsUpdate -ErrorAction SilentlyContinue))
{
    Write-Host -ForegroundColor Yellow -Object "Installation du module pour les MAJs Windows"
  	Install-PackageProvider -Name NuGet -Confirm:$false -Force | Out-Null
  	Install-Module -Name PSWindowsUpdate -Confirm:$False -Force | Out-Null
    Clear-Host
    Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Windows"
  	Get-WindowsUpdate -Download -AcceptAll -Install -IgnoreReboot
    Restart-Computer
}

If (!(Get-WindowsUpdate))
{
    Write-Host "Plus de MAJs détecter, Vous pouvez fermé cette fenêtre." 
    Pause
    Exit
}

Else
{
    Clear-Host
    Get-WindowsUpdate -Download -AcceptAll -Install -IgnoreReboot
    Restart-Computer
}