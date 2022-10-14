$DeployPath = "C:\Deploy"

#Check si le script est lancée en Admin sinon le relance avec élévation
If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -f ($Myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

#Suivi d'étape de l'installation.
Switch (Read-Host -Prompt "Etape ?") 
{
    5 
    {  
        Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E5_Cleaning.ps1" -NoNewWindow -Wait
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