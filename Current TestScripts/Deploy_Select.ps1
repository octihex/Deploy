$DeployPath = "C:\Deploy"

#Check si le script est lancée en Admin sinon le relance avec élévation
If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -f ($Myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

Set-Location "C:\Deploy"

While ($True)
{
    #Suivi d'étape de l'installation.
    Write-Host "Renommage et Integration au Domaine | " -NoNewline; Write-Host -ForegroundColor Yellow "Etape 1"
    Write-Host "Mise a jour Windows | " -NoNewline; Write-Host -ForegroundColor Yellow "Etape 2"
    Write-Host "Mise a jour Constructeur | " -NoNewline; Write-Host -ForegroundColor Yellow "Etape 3"
    Write-Host "Installation des Applications | " -NoNewline; Write-Host -ForegroundColor Yellow "Etape 4"
    Write-Host "Verification de L'installation | " -NoNewline; Write-Host -ForegroundColor Yellow "Etape 5"
    Write-Host "Nettoyage des Fichiers sur le Poste | " -NoNewline; Write-Host -ForegroundColor Yellow "Etape 6"
    Switch (Read-Host -Prompt "Numero de l'etape ?") 
    {
        6 
        {  
            Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E6_Cleaning.ps1" -NoNewWindow -Wait
        }

        5 
        {  
            Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E5_Check.ps1" -NoNewWindow -Wait
        }

        4
        {
            Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E4_Install-Apps.ps1" -NoNewWindow -Wait
        }

        3
        {
            Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E3_MAJ-Dell.ps1" -NoNewWindow -Wait
        }

        2
        {
            Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E2_MAJ-Windows.ps1" -NoNewWindow -Wait
        }

        1
        {
            Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E1_Domain.ps1" -NoNewWindow -Wait
        }

        Default 
        {
            Write-Host -ForegroundColor Yellow -Object "Erreur dans la detection de l'étape actuelle du script, fermeture."
            Start-Sleep -Seconds 5
  	        Exit
        }
    }
}