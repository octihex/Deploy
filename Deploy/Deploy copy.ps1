$DeployPath = "C:\Deploy"

# ---> Check si le script est lancée en Admin sinon le relance avec élévation
If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

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
        Write-Host -ForegroundColor Yellow -Object "Erreur dans la detection de l'étape actuelle du script, fermeture."
        Start-Sleep -Seconds 5
  	    Exit
    }
}