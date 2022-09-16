#Change le titre de la fenetre Powershell.
$host.UI.RawUI.WindowTitle = "Script installation poste CEVA"

#Verifie si le script est lancer avec des permissions administrateur.
if (!$(net session *>$null; $LASTEXITCODE -eq 0))
{
    Write-Host -ForegroundColor Yellow -Object "Ce script a besoin d'etre ouvert avec permissions d'administrateurs."
    exit
}

#Installe le module Powershell PSWindowsUpdate puis le suprime.
#Recherche et installe toutes les MAJ Dell disponible.
Write-Host -ForegroundColor Yellow -Object "Configuration des MAJ Windows"
Install-PackageProvider -Name NuGet -Confirm:$false -Force | Out-Null
Install-Module -Name PSWindowsUpdate -Confirm:$False -Force | Out-Null
Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Windows"
Get-WindowsUpdate -Download -AcceptAll -Install
Uninstall-Module -Name PSWindowsUpdate -Force
Clear-Host

#Recherche et installe toutes les MAJ Dell disponible
Write-Host -ForegroundColor Yellow -Object "Recherche des MAJ Dell"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -NoNewWindow -Wait
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /scan" -NoNewWindow -Wait
Clear-Host
Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Dell"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /applyUpdates -reboot=disable" -NoNewWindow -Wait
Clear-Host

#Installation UEM
Write-Host -ForegroundColor Yellow -Object "Installation d'UEM"
Start-Process -FilePath "C:\Deploy\Apps\LANDesk.exe"
Clear-Host

#Installation Windows Defender.
Write-Host -ForegroundColor Yellow -Object "Installation de Windows Defender"
Start-Process -FilePath "C:\Deploy\Apps\Defender\WindowsDefender.cmd" -NoNewWindow -Wait
Clear-Host

#Installation Citrix.
Write-Host -ForegroundColor Yellow -Object "Installation de Citrix"
Start-Process -FilePath "C:\Deploy\Apps\Citrix.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false" -NoNewWindow -Wait
Clear-Host

#Desinstalation d'Office.
Write-Host -ForegroundColor Yellow -Object "Desinstalation d'Office generique"
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Apps\Office\Office365.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Apps\Office\Office15.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Clear-Host

#Installation Office.
TASKKILL /F /IM OfficeSetup.exe
Start-Process -FilePath "C:\Deploy\Apps\Office\OfficeSetup.exe"

#Installation Teams.
Write-Host -ForegroundColor Yellow -Object "Installation de Teams"
Start-Process -FilePath "C:\Deploy\Apps\Office\TeamsSetup.exe -s" -NoNewWindow -Wait

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