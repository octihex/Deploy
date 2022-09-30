$DeployPath = "C:\Deploy"
$USB_Folder = Get-Content -Path c:\Deploy\GetFolder.txt

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

Write-Host -ForegroundColor Yellow -Object "Transfert des fichiers sur le poste"
Copy-Item -Path "$USB_Folder\*" -Destination $DeployPath -Recurse
Copy-Item -Path "C:\Deploy\Deploy.lnk" -Destination "C:\Users\ceprt\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Start-Process powershell -verb runas -ArgumentList "$DeployPath\Deploy.ps1"