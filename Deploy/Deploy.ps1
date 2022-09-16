#Change le titre de la fenetre Powershell.
$host.UI.RawUI.WindowTitle = "Script installation poste CEVA"

#Verifie si le script est lancer avec des permissions administrateur.
if (!$(net session *>$null; $LASTEXITCODE -eq 0))
{
    Write-Host -ForegroundColor Yellow -Object "Ce script a besoin d'etre ouvert avec permissions d'administrateurs."
    exit
}
<#
#Renomme le poste sans avoir besoin de le redemarre.
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
$newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" 
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" 
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\Computername" -name "Computername" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\ActiveComputername" -name "Computername" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" -value  $newNamePc
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AltDefaultDomainName" -value $newNamePc
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $newNamePc

Add-Computer -DomainName ceva.net -ComputerName $env:computername -NewName $newNamePc
Clear-Host
#>
#Installe le module Powershell PSWindowsUpdate puis le suprime.
#Recherche et installe toutes les MAJ Dell disponible.
Write-Host -ForegroundColor Yellow -Object "Configuration des MAJ Windows"
Install-Module -Name PSWindowsUpdate -Confirm:$False -Force
Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Windows"
Get-WindowsUpdate -Download -AcceptAll -Install
Uninstall-Module -Name PSWindowsUpdate -Force
Clear-Host

#Recherche et installe toutes les MAJ Dell disponible
Write-Host -ForegroundColor Yellow -Object "Recherche des MAJ Dell"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -NoNewWindow -Wait
Start-Sleep -Seconds 1
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /scan -outputLog=C:\dell\logs\scan.log" -NoNewWindow -Wait
Start-Sleep -Seconds 1
Clear-Host
Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Dell"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /applyUpdates -reboot=disable -outputLog=C:\dell\logs\applyUpdates.log" -NoNewWindow -Wait
Start-Sleep -Seconds 1
Clear-Host

#Installation UEM
Write-Host -ForegroundColor Yellow -Object "Installation d'UEM"
Start-Process -FilePath "C:\Deploy\LANDesk\LANDesk.exe"
Clear-Host

#Installation Windows Defender.
Write-Host -ForegroundColor Yellow -Object "Installation de Windows Defender"
Start-Process -FilePath "C:\Deploy\Defender\WindowsDefender.cmd" -NoNewWindow -Wait
Clear-Host

#Installation Citrix.
Write-Host -ForegroundColor Yellow -Object "Installation de Citrix"
Start-Process -FilePath "C:\Deploy\Apps\CitrixWorkspaceApp.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false" -NoNewWindow -Wait
Clear-Host

#Desinstalation d'Office.
Write-Host -ForegroundColor Yellow -Object "Desinstalation d'Office generique"
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office\Office365.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office\Office15.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Clear-Host

#Installation Office.
TASKKILL /F /IM OfficeSetup.exe
Start-Process -FilePath "C:\Deploy\Office\OfficeSetup.exe"

#Installation Teams.
Write-Host -ForegroundColor Yellow -Object "Installation de Teams"
Start-Process -FilePath "C:\Deploy\Office\TeamsSetup.exe -s" -NoNewWindow -Wait

#Installation 7Zip.
Write-Host -ForegroundColor Yellow -Object "Installation de 7Zip"
Start-Process -FilePath "C:\Deploy\Apps\7zip.exe /S" -NoNewWindow -Wait

#Installation Adobe.
Write-Host -ForegroundColor Yellow -Object "Installation d'Adobe"
Start-Process -FilePath "C:\Deploy\Apps\Adobe.exe /sAll /rs /msi EULA_ACCEPT=YES" -NoNewWindow -Wait

#Installation Chrome.
Write-Host -ForegroundColor Yellow -Object "Installation de Chrome"
Start-Process -FilePath "C:\Windows\System32\MsiExec.exe /i C:\Deploy\Apps\Chrome.msi /qn" -NoNewWindow -Wait

#Ajoute TeamViewerQS et le shortcut Teams.
Copy-Item -Path "C:\Deploy\Public\*" -Destination "C:\Users\Public\Desktop" -Recurse

#Attend que l'installation d'Office soit fini.
While (Get-Process OfficeSetup -ErrorAction SilentlyContinue)
{
  Write-Host -ForegroundColor Yellow -Object "L'instalation d'Office est toujours en cours."
  Start-Sleep -Seconds 5
}

Write-Host -ForegroundColor Yellow -Object "Fermeture d'Office."
TASKKILL /F /IM OfficeC2RClient.exe

#Suprime les fichiers d'installation et redemarre le poste.
shutdown -r -t 5
Set-Location C:\
C:\Deploy\Clean.lnk