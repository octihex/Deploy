Function MAJ_Dell2 
{
    $Host.UI.RawUI.WindowTitle = "Installation Poste - Etape 3 - MAJ Dell"

    If (Test-Path -PathType leaf -Path "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe")
    {
        $DCU_Path = "C:\Program Files (x86)\Dell\CommandUpdate"
    }

    If (Test-Path -PathType leaf -Path "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe")
    {
        $DCU_Path = "C:\Program Files\Dell\CommandUpdate"
    }

    If (!$DCU_Path) 
    {
        Write-Host -ForegroundColor Yellow -Object "Installation automatique de Dell Command Update en cours."
        Start-Process -FilePath "$DeployPath\Apps\DCU_4.6.0.exe" -ArgumentList "/s /l=$DeployPath\DCU_Install_Log.txt" -NoNewWindow -Wait
        Clear-Host

        While (!$CheckInstallDCU) 
        {          
            $CheckInstallDCU = (Select-String -Path "C:\Deploy\DCU_Install_Log.txt" -Pattern 'Name of Exit Code:')
            $DCUTestCountStr = "Installation de Dell Command Update en cours"
            For ($Counter = 1 ; $Counter -le 3 ; $Counter++)
            {    
                Clear-Host
                $DCUTestCountStr = "$DCUTestCountStr" + "."
                Write-Host -ForegroundColor Yellow -Object $DCUTestCountStr
                Start-Sleep 1
            }   
        }

        $ArrDCUCode = "SUCCESS", "REBOOT_REQUIRED"

        Switch (($CheckInstallDCU | Select-Object -First 1).Line.Split(' ')[-1]) 
        {
            {$ArrDCUCode -eq $_} 
            {  
                MAJ_Dell2
            }

            Default 
            {
                Write-Host -ForegroundColor Yellow -Object "L'installation automatique de Dell Command Update a échoué."
                Write-Host -ForegroundColor Yellow -Object "Le script va ouvrir l'installateur manuellement mais n'aurra pas consience de sa bonne installation."
                Pause
                Start-Process -FilePath "$DeployPath\Apps\DCU_4.6.0.exe" -ArgumentList "/l=$DeployPath\DCU_Install_Log.txt"

                While ($DCUInstallOK -ne "OK") 
                {          
                    Clear-Host
                    $DCUInstallOK = Read-Host -Prompt "Veuillez entrez OK quand l'installation de serra fini."   
                }

                MAJ_Dell2
            }
        }
    }

  	#Recherche et installe toutes les MAJ Dell disponible
  	Write-Host -ForegroundColor Yellow -Object "Recherche des MAJ Dell"

  	#Configure Dell Command Update et cherche les MAJ disponible
  	Start-Process -FilePath "$DCU_Path\dcu-cli.exe" -ArgumentList "/configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -NoNewWindow -Wait
  	Start-Process -FilePath "$DCU_Path\dcu-cli.exe" -ArgumentList "/scan" -NoNewWindow -Wait
  	Clear-Host

  	#Installe toutes les MAJ
  	Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Dell"
  	Start-Process -FilePath "$DCU_Path\dcu-cli.exe" -ArgumentList "/applyUpdates -reboot=disable" -NoNewWindow -Wait
  	#Restart-Computer
}

MAJ_Dell2