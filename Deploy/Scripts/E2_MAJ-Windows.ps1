#Change le nom de la fenêtre du script
$host.UI.RawUI.WindowTitle = "Installation Poste - Etape 2 - MAJs Windows"
Clear-Host

#Check si le module PSWindowsUpdate est installée
If (!(Get-InstalledModule -Name PSWindowsUpdate -ErrorAction SilentlyContinue))
{
    Write-Host -ForegroundColor Yellow -Object "Installation du module pour les MAJs Windows"
  	Install-PackageProvider -Name NuGet -Confirm:$false -Force | Out-Null
  	Install-Module -Name PSWindowsUpdate -Confirm:$False -Force | Out-Null
}

Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject MAJWindowsOK | Out-Null

#Check si il y a des MAJ 
If (Get-WindowsUpdate -NotKBArticleID KB2267602)
{
    #Install les MAJ si trouvé précédemment
    Clear-Host
    Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Windows"
    Get-WindowsUpdate -Download -AcceptAll -Install -IgnoreReboot
    Restart-Computer
}

Else 
{
    Clear-Host
    Write-Host "Plus de MAJs détecter." 
}