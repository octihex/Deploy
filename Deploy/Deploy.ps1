$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$testadmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$DeployPath = "C:\Deploy"

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
    $ArrLaptops = "Libla", "Libol"
    $ArrDesktops = "Libde", "Libod"

    If ($newNamePc.Length -ge 5)
    {
        Switch ($newNamePc.Substring(0,5)) 
        {
            {$ArrLaptops -eq $_} 
            {  
                Write-Host -ForegroundColor Yellow -Object "Ajout du poste au domaine dans l'OU Laptops"
                Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
            }

            {$ArrDesktops -eq $_}
            {
                Write-Host -ForegroundColor Yellow -Object "Ajout du poste au domaine dans l'OU Desktops"
                Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
            }

            Default 
            {
                Write-Host -ForegroundColor Yellow -Object "Ajout du poste au domaine sans OU spécifique"
                Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -Restart
            }
        }
    }

    Else 
    {
        Write-Host -ForegroundColor Yellow -Object "Le nom du poste doit au moins contenir 5 characters"
        Pause
        Rename_PC
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
  	Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject MAJWindowsOK | Out-Null
  	Restart-Computer
}

#Fonction de MAJ Dell
function MAJ_Dell 
{
    $DCU_Path = "C:\Program Files (x86)\Dell\CommandUpdate"
    if (!(Test-Path -PathType leaf -Path "$DCU_Path\dcu-cli.exe"))
    {
        Start-Process -FilePath "$DeployPath\Apps\DCU_4.6.0.exe" -ArgumentList "/s /l=$DeployPath\DCU_Install_Log.txt" -NoNewWindow -Wait

        While (!$CheckInstallDCU) 
        {          
            Clear-Host
            $CheckInstallDCU = (Select-String -Path "C:\Deploy\DCU_Install_Log.txt" -Pattern 'Name of Exit Code:')
            Write-Host -ForegroundColor Yellow -Object "Installation de Dell Command Update en cours."
            Start-Sleep -Seconds 5   
        }

        if ((($CheckInstallDCU | Select-Object -First 1).Line.Split(' ')[-1]) -eq "SUCCESS") 
        {
            MAJ_Dell
        }

        Else 
        {
            #Install pas OK - faire truc
            Write-Host -ForegroundColor Yellow -Object "L'installation automatique de Dell Command Update a échoué."
            Write-Host -ForegroundColor Yellow -Object "Le script va ouvrir l'installateur manuellement mais n'aurra pas consience de sa bonne installation."
            Write-Host -ForegroundColor Yellow -Object "Veuillez entrez OK quand l'installation serra fini."
            Pause
            While ($DCUInstallOK -ne "OK") 
            {          
                Clear-Host
                $DCUInstallOK = Read-Host -Prompt "Veuillez entrez OK quand l'installation de serra fini."   
            }
            MAJ_Dell
        }
    }

  	$host.UI.RawUI.WindowTitle = "Installation Poste - Etape 3 - MAJ Dell"

  	#Recherche et installe toutes les MAJ Dell disponible
  	Write-Host -ForegroundColor Yellow -Object "Recherche des MAJ Dell"

  	#Configure Dell Command Update et cherche les MAJ disponible
  	Start-Process -FilePath "$DCU_Path\dcu-cli.exe" -ArgumentList "/configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -NoNewWindow -Wait
  	Start-Process -FilePath "$DCU_Path\dcu-cli.exe" -ArgumentList "/scan" -NoNewWindow -Wait
  	Clear-Host

  	#Installe toutes les MAJ
  	Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Dell"
  	Start-Process -FilePath "$DCU_Path\dcu-cli.exe" -ArgumentList "/applyUpdates -reboot=disable" -NoNewWindow -Wait
  	Clear-Host
  	Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject MAJConstructeursOK | Out-Null
  	Restart-Computer
}

#Fonction d'installation des applications
function Install_Apps 
{
  	$host.UI.RawUI.WindowTitle = "Installation Poste - Etape 4 - Applications"

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

  	#Installation Adobe.
  	Write-Host -ForegroundColor Yellow -Object "Installation d'Adobe"
  	Start-Process -FilePath "$DeployPath\Apps\Adobe.exe" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES" -NoNewWindow -Wait

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

  	Write-Host -ForegroundColor Yellow -Object "Fermeture d'Office."
  	TASKKILL /F /IM OfficeC2RClient.exe
  	Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject AppsOK | Out-Null
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
    	Set-ItemProperty -Path $Cleaning_REG_PATH -Name Run -Value $Cleaning_Command
  	}
  
  	#Suprime les fichiers d'installation et redemarre le poste.
  	shutdown -s -t 5
  	Set-Location C:\
  	Start-Process C:\Deploy\Cleaning.lnk
}

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

if (!(Get-Content -Path $DeployPath\Check-Install.txt -ErrorAction SilentlyContinue))
{
  	Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject DebugPlaceHolder | Out-Null
  	Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject DebugPlaceHolder | Out-Null
}

#Suivi d'étape de l'installation.

Switch ((Get-Content -Path $DeployPath\Check-Install.txt)[-1]) 
{
    {$_ -eq "AppsOK"} 
    {  
        Cleaning_Install
    }

    {$_ -eq "MAJConstructeursOK"}
    {
        Install_Apps
    }

    {$_ -eq "MAJWindowsOK"}
    {
        MAJ_Dell
    }

    {$_ -eq "RenameOK"}
    {
        MAJ_Windows
    }

    {$_ -eq "DebugPlaceHolder"}
    {
        Rename_PC
    }

    Default 
    {
        Write-Host -ForegroundColor Yellow -Object "Erreur dans l'étape du script, fermeture."
        Start-Sleep -Seconds 5
  	    exit
    }
}