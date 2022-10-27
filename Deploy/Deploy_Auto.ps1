$DeployPath = "C:\Deploy"

If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process Powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -F ($Myinvocation.MyCommand.Definition)) -WindowStyle Maximized
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
        Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E5_Check.ps1" -NoNewWindow
    }

    {$_ -eq "MAJConstructeursOK"}
    {
        Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E4_Install-Apps.ps1" -NoNewWindow
    }

    {$_ -eq "MAJWindowsOK"}
    {
        Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E3_MAJ-Dell.ps1" -NoNewWindow
    }

    {$_ -eq "RenameOK"}
    {
        Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E2_MAJ-Windows.ps1" -NoNewWindow
    }

    {$_ -eq "DebugPlaceHolder"}
    {
        Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E1_Domain.ps1" -NoNewWindow
    }

    Default 
    {
        Write-Host -ForegroundColor Yellow -Object "Erreur dans la detection de l'etape actuelle du script, fermeture."
        Start-Sleep -Seconds 5
  	    Exit
    }
}