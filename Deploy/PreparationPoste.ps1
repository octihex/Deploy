$DeployPath = "C:\Deploy"

If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    If (test-path -PathType container $DeployPath)
    {
        Remove-Item $DeployPath -Force -Recurse -ErrorAction SilentlyContinue
    }

    If (!(test-path -PathType container $DeployPath))
    {
        New-Item -ItemType Directory -Path $DeployPath | Out-Null
    }

    Out-File -FilePath $DeployPath\Get_USB_Path.txt -Force -InputObject (Get-Location).Path | Out-Null

    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}" -Elevated' -f ($Myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

$USB_Folder = Get-Content -Path $DeployPath\Get_USB_Path.txt

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

Write-Host -ForegroundColor Yellow -Object "Transfert des fichiers sur le poste"
Copy-Item -Path "$USB_Folder\Deploy\*" -Destination $DeployPath -Recurse
Copy-Item -Path "$DeployPath\Deploy.lnk" -Destination "C:\Users\ceprt\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Start-Process Powershell -ArgumentList "$DeployPath\Deploy.ps1" -NoNewWindow