$host.UI.RawUI.WindowTitle = "Script installation poste CEVA"

$newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" 
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" 
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\Computername" -name "Computername" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\ActiveComputername" -name "Computername" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" -value  $newNamePc
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AltDefaultDomainName" -value $newNamePc
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $newNamePc

function Function-RenamePc {
    $OU = Read-Host -Prompt "(1) Laptop | (2) Desktop"
    if ($OU -eq 1) {
        Add-Computer -DomainName ceva.net -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net"
        Break
    }
    if ($OU -eq 2) {
        Add-Computer -DomainName ceva.net -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net"
        Break
    }
    else {
        Function-RenamePc
    }
}

Function-RenamePc

Write-Host -Object "*** Configuration MAJ Windows ***"
#Importe le module PSWindowsUpdate sans l'installer
Import-Module -Name C:Deploy\WindowsUpdate\PSWindowsUpdate
#Copie le .dll nuget qui peux etre requis pour certaine MAJ
New-Item -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\" -Name "2.8.5.208" -ItemType "directory" | Out-Null
Copy-Item "C:\Deploy\WindowsUpdate\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll" -Destination "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208"
#Recherche et installe toutes les MAJ Windows trouve
Write-Host -Object "*** Installation MAJ Windows ***"
Get-WindowsUpdate -AcceptAll -Install
Clear-Host

#Recherche et installe toutes les MAJ Dell trouve
Write-Host -Object "*** Recherche MAJ Dell ***"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList (/configure -silent -autoSuspendBitLocker=enable -userConsent=disable) -NoNewWindow -Wait
Start-Sleep -Seconds 1
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList (/scan -outputLog=C:\dell\logs\scan.log) -NoNewWindow -Wait
Start-Sleep -Seconds 1
Clear-Host
Write-Host -Object "*** Installation MAJ Dell ***"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList (/applyUpdates -reboot=disable -outputLog=C:\dell\logs\applyUpdates.log) -NoNewWindow -Wait
Start-Sleep -Seconds 1
Clear-Host

#Installation des applications
Write-Host -Object "*** Installation de Windows Defender ***"
Start-Process -FilePath "C:\Deploy\Defender\WindowsDefender.cmd" -NoNewWindow -Wait
Clear-Host

Write-Host -Object "*** Installation Citrix ***"
Start-Process -FilePath "C:\Deploy\CitrixWorkspaceApp.exe" -ArgumentList (/noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false) -NoNewWindow -Wait
Clear-Host

Write-Host -Object "*** Installation LANDesk ***"
Start-Process -FilePath "C:\Windows\System32\MsiExec.exe" -ArgumentList (/i C:\Deploy\LANDesk.msi)
Clear-Host

Write-Host -Object "*** Desinstalation forcee du Office generique ***"
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe" -ArgumentList (C:\Deploy\Office365.vbs ALL /Quiet /NoCancel /Force /OSE) -NoNewWindow -Wait
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe" -ArgumentList (C:\Deploy\Office15.vbs ALL /Quiet /NoCancel /Force /OSE) -NoNewWindow -Wait
Clear-Host

TASKKILL /F /IM OfficeSetup.exe
Start-Process -FilePath "C:\Deploy\Office\OfficeSetup.exe"

echo *** Installation Teams ***
Start-Process -FilePath "C:\Deploy\Office\TeamsSetup.exe" -ArgumentList (-s) -NoNewWindow -Wait

echo *** Installation 7Zip ***
Start-Process -FilePath "C:\Deploy\Apps\7zip.exe" -ArgumentList (/S) -NoNewWindow -Wait

echo *** Installation Adobe ***
Start-Process -FilePath "C:\Deploy\Apps\Adobe.exe" -ArgumentList (/sAll /rs /msi EULA_ACCEPT=YES) -NoNewWindow -Wait

echo *** Installation Chrome ***
Start-Process -FilePath "C:\Windows\System32\MsiExec.exe" -ArgumentList (/i C:\Deploy\Apps\Chrome.msi /qn) -NoNewWindow -Wait

Copy-Item -Path "C:\Deploy\Public\*" -Destination "C:\Users\Public\Desktop" -Recurse

While (Get-Process OfficeSetup -ErrorAction SilentlyContinue)
{
  Write-Host -Object "*** L'instalation d'Office est toujours en cours. ***"
  Start-Sleep -Seconds 5
}
Write-Host -Object "*** Fermeture d'Office en cours. ***"
TASKKILL /F /IM OfficeC2RClient.exe

shutdown -r -t 5
cd C:\
C:\Deploy\Clean.lnk