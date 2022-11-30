Net User Ceprt *
#Désinstalle le module Powershell PSWindowsUpdate
Uninstall-Module -Name PSWindowsUpdate -Force
Remove-Item "C:\Program Files\PackageManagement\ProviderAssemblies\nuget" -Recurse -ErrorAction SilentlyContinue
Remove-Item "C:\Users\ceprt\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Deploy.lnk" | Out-Null
Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 0 -Type String
Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 5
Set-ExecutionPolicy -ExecutionPolicy Restricted -Force
Invoke-GPUpdate

#Suprime les fichiers d'installation et redemarre le poste.
shutdown -s -t 5
Set-Location C:\
Start-Process C:\Deploy\Cleaning.lnk