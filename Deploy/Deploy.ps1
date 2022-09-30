#Vérifie si le script est lancée avec des permissions administrateur.
<#
if (!$(net session *>$null; $LASTEXITCODE -eq 0))
{
  Write-Host -ForegroundColor Yellow -Object "Ce script a besoin d'être ouvert avec permissions d'administrateurs."
  Pause
  exit
}
#>

$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$testadmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if ($testadmin -eq $false) 
{
  Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
  exit $LASTEXITCODE
}

#Fonction d'intégration au domaine avec renommage du poste.
function Rename_PC 
{
  $host.UI.RawUI.WindowTitle = "Installation Poste - Etape 1 - Domaine"
  $newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"

  if (Select-String -InputObject $NewNamePC -Pattern liblap)
  {
    Write-Host -Object "Ajout du poste au domaine dans l'OU Laptops"
    Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
    Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
  }

  elseif (Select-String -InputObject $NewNamePC -Pattern libdes) 
  { 
    Write-Host -Object "Ajout du poste au domaine dans l'OU Desktops"
    Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
    Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
  }

  elseif (Select-String -InputObject $NewNamePC -Pattern libol) 
  { 
    Write-Host -Object "Ajout du poste au domaine dans l'OU Laptops"
    Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
    Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
  }

  elseif (Select-String -InputObject $NewNamePC -Pattern libod) 
  { 
    Write-Host -Object "Ajout du poste au domaine dans l'OU Desktops"
    Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
    Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
  }

  else 
  {
    Write-Host -Object "Ajout du poste au domaine sans OU spécifique"
    Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
    Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -Restart
  }
}

#Fonction de MAJ Windows
function MAJ_Windows 
{
  $host.UI.RawUI.WindowTitle = "Installation Poste - Etape 2 - MAJ Windows"
  #Installe le module Powershell PSWindowsUpdate et le module supplémentaire NuGet.
  Write-Host -ForegroundColor Yellow -Object "Configuration des MAJ Windows"
  Install-PackageProvider -Name NuGet -Confirm:$false -Force | Out-Null
  Install-Module -Name PSWindowsUpdate -Confirm:$False -Force | Out-Null
  #Télécharge et installe toutes les MAJ disponible ( MAJ normale et MAJ facultative )
  Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Windows"
  Get-WindowsUpdate -Download -AcceptAll -Install
  #Désinstalle le module Powershell PSWindowsUpdate
  Uninstall-Module -Name PSWindowsUpdate -Force
  Clear-Host
  Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject MAJWindowsOK | Out-Null
  Restart-Computer
}

#Fonction de MAJ Dell
function MAJ_Dell 
{
  $host.UI.RawUI.WindowTitle = "Installation Poste - Etape 3 - MAJ Dell"

  #Recherche et installe toutes les MAJ Dell disponible
  Write-Host -ForegroundColor Yellow -Object "Recherche des MAJ Dell"

  #Configure Dell Command Update et cherche les MAJ disponible
  Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -NoNewWindow -Wait
  Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/scan" -NoNewWindow -Wait
  Clear-Host

  #Installe toutes les MAJ
  Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Dell"
  Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates -reboot=disable" -NoNewWindow -Wait
  Clear-Host
  Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject MAJDellOK | Out-Null
  Restart-Computer
}

#Fonction d'installation des applications
function Install_Apps 
{
  $host.UI.RawUI.WindowTitle = "Installation Poste - Etape 4 - Applications"

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
  Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject AppsOK | Out-Null
  Restart-Computer
}

#Fonction de notoyage des fichier d'installation
function Cleaning_Install 
{
  #Demande de changer le MDP du compte CEPRT
  net user CEPRT *
  Remove-Item "C:\Users\schadour\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Deploy.lnk" | Out-Null
  Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 5
  $Cleaning_Command = "%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe Set-ExecutionPolicy -executionpolicy Restricted"
  $Cleaning_REG_PATH = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  if (!(test-path -path "$Cleaning_REG_PATH\run" | Out-Null))
  {
    New-ItemProperty -Path $Cleaning_REG_PATH -Name Run -Value $Cleaning_Command -PropertyType ExpandString
  }
  
  if (test-path -path "$Cleaning_REG_PATH\run" | Out-Null)
  {
    Set-ItemProperty -Path $Cleaning_REG_PATH -Name Run -Value $Cleaning_Command -PropertyType ExpandString
  }
  
  #Suprime les fichiers d'installation et redemarre le poste.
  shutdown -s -t 5
  Set-Location C:\
  C:\Deploy\Clean.lnk
}

if (!(Get-Content -Path C:\Deploy\Check-Install.txt -ErrorAction SilentlyContinue))
{
  Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject DebugPlaceHolder | Out-Null
  Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject DebugPlaceHolder | Out-Null
}

#Suivi d'étape de l'installation.
if ((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "AppsOK")
{
  Cleaning_Install
}
elseif ((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "MAJDellOK")
{
  Install_Apps
}
elseif ((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "MAJWindowsOK") 
{
  MAJ_Dell
}
elseif ((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "RenameOK") 
{
  MAJ_Windows
}
elseif ((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "DebugPlaceHolder") 
{
  Rename_PC
}
else
{
  Write-Host -ForegroundColor Yellow -Object "Erreur du script, Fermeture."
  Pause
  exit
}