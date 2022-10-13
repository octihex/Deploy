$DeployPath = "C:\Deploy"

#Check si le script est lancée en Admin sinon le relance avec élévation
If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -f ($Myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}


If (!(Get-Content -Path $DeployPath\Check-Install.txt -ErrorAction SilentlyContinue))
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
        Start-Process -FilePath "$DeployPath\Scripts\E4_Install-Apps.ps1" -ArgumentList "-ExecutionPolicy Unrestricted" -NoNewWindow -Wait
    }

    {$_ -eq "MAJWindowsOK"}
    {
        Start-Process -FilePath "$DeployPath\Scripts\E3_MAJ-Dell.ps1" -ArgumentList "-ExecutionPolicy Unrestricted" -NoNewWindow -Wait
    }

    {$_ -eq "RenameOK"}
    {
        Start-Process -FilePath "$DeployPath\Scripts\E2_MAJ-Windows.ps1" -ArgumentList "-ExecutionPolicy Unrestricted" -NoNewWindow -Wait
    }

    {$_ -eq "DebugPlaceHolder"}
    {
        Start-Process -FilePath "$DeployPath\Scripts\E1_Domain.ps1" -ArgumentList "-ExecutionPolicy Unrestricted" -NoNewWindow -Wait
    }

    Default 
    {
        Write-Host -ForegroundColor Yellow -Object "Erreur dans la detection de l'étape actuelle du script, fermeture."
        Start-Sleep -Seconds 5
  	    Exit
    }
}