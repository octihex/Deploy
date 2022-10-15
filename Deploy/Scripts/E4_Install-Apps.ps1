$Host.UI.RawUI.WindowTitle = "Installation Poste - Etape 4 - Applications"

$DeployPath = "C:\Deploy"

#Installation Adobe.
Write-Host -ForegroundColor Yellow -Object "Installation d'Adobe"
Start-Process -WindowStyle hidden -FilePath "$DeployPath\Apps\Adobe.exe" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES"

#Installation UEM
Write-Host -ForegroundColor Yellow -Object "Installation d'UEM"
Start-Process -FilePath "$DeployPath\Apps\LANDesk.exe"
Clear-Host

#Installation Windows Defender.
Write-Host -ForegroundColor Yellow -Object "Installation de Windows Defender"
Start-Process -FilePath "$DeployPath\Apps\Defender\WindowsDefender.cmd" -NoNewWindow -Wait
Clear-Host

#Installation Citrix.
Write-Host -ForegroundColor Yellow -Object "Installation de Citrix"
Start-Process -FilePath "$DeployPath\Apps\Citrix.exe" -ArgumentList "/noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false" -NoNewWindow
Clear-Host

#Desinstalation d'Office.
Write-Host -ForegroundColor Yellow -Object "Desinstalation d'Office generique"
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe" -ArgumentList "$DeployPath\Apps\Office\Office365.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe" -ArgumentList "$DeployPath\Apps\Office\Office15.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Clear-Host

#Installation Office.
TASKKILL /F /IM OfficeSetup.exe
Start-Process -FilePath "$DeployPath\Apps\Office\OfficeSetup.exe"

#Installation Teams.
Write-Host -ForegroundColor Yellow -Object "Installation de Teams"
Start-Process -FilePath "$DeployPath\Apps\Office\TeamsSetup.exe" -ArgumentList "-s" -NoNewWindow -Wait

#Installation 7Zip.
Write-Host -ForegroundColor Yellow -Object "Installation de 7Zip"
Start-Process -FilePath "$DeployPath\Apps\7zip.exe" -ArgumentList "/S" -NoNewWindow -Wait

#Installation Chrome.
Write-Host -ForegroundColor Yellow -Object "Installation de Chrome"
Start-Process -FilePath "$DeployPath\Apps\Chrome.exe" -ArgumentList "/silent /install" -NoNewWindow -Wait

#Ajoute TeamViewerQS et le shortcut Teams.
Copy-Item -Path "$DeployPath\Apps\Public\*" -Destination "C:\Users\Public\Desktop" -Recurse

#Attend que l'installation d'Office soit fini.
While (Get-Process OfficeSetup -ErrorAction SilentlyContinue)
{
    Write-Host -ForegroundColor Yellow -Object "L'instalation d'Office est toujours en cours."
    Start-Sleep -Seconds 5
}

#Configure les .PDF pour être ouvert avec Adobe
Set-Location $DeployPath\Optionnel
. .\SFTA.ps1; (Set-FTA AcroExch.Document.DC .pdf)

Write-Host -ForegroundColor Yellow -Object "Fermeture d'Office."
TASKKILL /F /IM OfficeC2RClient.exe
Restart-Computer