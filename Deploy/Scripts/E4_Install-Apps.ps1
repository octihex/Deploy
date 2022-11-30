$Host.UI.RawUI.WindowTitle = "Installation Poste - Etape 4 - Applications"

$DeployPath = "C:\Deploy"

#Installation Adobe.
#Mauvaise copie d'Adobe ?
Write-Host -ForegroundColor Yellow -Object "Installation d'Adobe"
Start-Process -FilePath "$DeployPath\Apps\Adobe.exe" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES" -WindowStyle Hidden
Clear-Host

#Installation Office.
Start-Sleep -Seconds 2
TASKKILL /F /IM OfficeSetup.exe | Out-Null
Start-Process -FilePath "$DeployPath\Apps\Office\OfficeSetup.exe" -WindowStyle Hidden

#Installation UEM
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Installation d'UEM"
Start-Process -FilePath "$DeployPath\Apps\LANDesk.exe"
Clear-Host

#Installation Windows Defender.
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Installation de Windows Defender"
Start-Process -FilePath "$DeployPath\Apps\Defender\WindowsDefender.cmd" -NoNewWindow -Wait
Clear-Host

#Installation Citrix.
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Installation de Citrix"
Start-Process -FilePath "$DeployPath\Apps\Citrix.exe" -ArgumentList "/noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false" -NoNewWindow
Clear-Host

#Desinstalation d'Office.
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Desinstalation d'Office generique"
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe" -ArgumentList "$DeployPath\Apps\Office\Office365.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe" -ArgumentList "$DeployPath\Apps\Office\Office15.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Clear-Host

#Installation Teams.
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Installation de Teams"
Start-Process -FilePath "$DeployPath\Apps\Office\TeamsSetup.exe" -ArgumentList "-s" -NoNewWindow -WindowStyle Minimized
Clear-Host

#Installation 7Zip.
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Installation de 7Zip"
Start-Process -FilePath "$DeployPath\Apps\7zip.exe" -ArgumentList "/S" -NoNewWindow -Wait
Clear-Host

#Installation Chrome.
Start-Sleep -Seconds 2
Write-Host -ForegroundColor Yellow -Object "Installation de Chrome"
Start-Process -FilePath "$DeployPath\Apps\Chrome.exe" -ArgumentList "/silent /install" -NoNewWindow -Wait -WindowStyle Minimized

#Ajoute TeamViewerQS et le shortcut Teams.
Copy-Item -Path "$DeployPath\Apps\Public\*" -Destination "C:\Users\Public\Desktop" -Recurse

#Attend que l'installation d'Office soit fini.
While (Get-Process OfficeSetup -ErrorAction SilentlyContinue)
{
    Clear-Host
    Write-Host -ForegroundColor Yellow -Object "L'instalation d'Office est toujours en cours."
    Start-Sleep -Seconds 5
}

#Configure les .PDF pour être ouvert avec Adobe
Clear-Host
Start-Sleep -Seconds 2
Set-Location $DeployPath\Scripts\Optionnel
. .\SFTA.ps1; (Set-FTA AcroExch.Document.DC .pdf)

#Désactive Dell Optimizer
Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\Optionnel\Optimizer_Disable.ps1" -NoNewWindow

Clear-Host
Write-Host -ForegroundColor Yellow -Object "Fermeture d'Office."
TASKKILL /F /IM OfficeC2RClient.exe

Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject AppsOK | Out-Null
Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject AppsOK | Out-Null
Restart-Computer