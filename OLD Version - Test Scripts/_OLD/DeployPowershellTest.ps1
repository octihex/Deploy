$host.UI.RawUI.WindowTitle = "Script installation poste CEVA"

if (!$(net session *>$null; $LASTEXITCODE -eq 0))
{
    Write-Host -ForegroundColor Yellow -Object "Ce script a besoin d'etre ouvert avec permissions d'administrateurs"
    exit
}

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
$newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" 
Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" 
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\Computername" -name "Computername" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\ActiveComputername" -name "Computername" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" -value $newNamePc
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" -value  $newNamePc
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AltDefaultDomainName" -value $newNamePc
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $newNamePc

function RenamePc {
    $OU = Read-Host -Prompt "(1) Laptop | (2) Desktop"
    if ($OU -eq 1) {
        Add-Computer -DomainName ceva.net -ComputerName $env:computername -NewName $newNamePc -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net"
        Return 0
    }
    if ($OU -eq 2) {
        Add-Computer -DomainName ceva.net -ComputerName $env:computername -NewName $newNamePc -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net"
        Return 0
    }
    else {
        RenamePc
    }
}

RenamePc

Write-Host -ForegroundColor Yellow -Object "Configuration MAJ Windows"
#Importe le module PSWindowsUpdate sans l'installer
#Import-Module -Name C:\Deploy\WindowsUpdate\PSWindowsUpdate
Install-Module -Name PSWindowsUpdate -Confirm:$False
#Copie le .dll nuget qui peux etre requis pour certaine MAJ
#New-Item -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\" -Name "2.8.5.208" -ItemType "directory" | Out-Null
#Copy-Item "C:\Deploy\WindowsUpdate\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll" -Destination "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208"
#Recherche et installe toutes les MAJ Windows trouve
Write-Host -ForegroundColor Yellow -Object "Installation MAJ Windows"
Get-WindowsUpdate -Download -AcceptAll -Install
Uninstall-Module -Name PSWindowsUpdate -force
Clear-Host

#Recherche et installe toutes les MAJ Dell trouve
Write-Host -ForegroundColor Yellow -Object "Recherche MAJ Dell"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -NoNewWindow -Wait
Start-Sleep -Seconds 1
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /scan -outputLog=C:\dell\logs\scan.log" -NoNewWindow -Wait
Start-Sleep -Seconds 1
Clear-Host
Write-Host -ForegroundColor Yellow -Object "Installation MAJ Dell"
Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe /applyUpdates -reboot=disable -outputLog=C:\dell\logs\applyUpdates.log" -NoNewWindow -Wait
Start-Sleep -Seconds 1
Clear-Host

#Installation des applications
Write-Host -ForegroundColor Yellow -Object "Installation de Windows Defender"
Start-Process -FilePath "C:\Deploy\Defender\WindowsDefender.cmd" -NoNewWindow -Wait
Clear-Host

Write-Host -ForegroundColor Yellow -Object "Installation Citrix"
Start-Process -FilePath "C:\Deploy\CitrixWorkspaceApp.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false" -NoNewWindow -Wait
Clear-Host

Write-Host -ForegroundColor Yellow -Object "Installation LANDesk"
Start-Process -FilePath "C:\Deploy\UEM\LANDesk.exe"
Clear-Host

Write-Host -ForegroundColor Yellow -Object "Desinstalation forcee du Office generique"
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office365.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Start-Process -FilePath "C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office15.vbs ALL /Quiet /NoCancel /Force /OSE" -NoNewWindow -Wait
Clear-Host

TASKKILL /F /IM OfficeSetup.exe
Start-Process -FilePath "C:\Deploy\Office\OfficeSetup.exe"

Write-Host -ForegroundColor Yellow -Object "Installation Teams"
Start-Process -FilePath "C:\Deploy\Office\TeamsSetup.exe -s" -NoNewWindow -Wait

Write-Host -ForegroundColor Yellow -Object "Installation 7Zip"
Start-Process -FilePath "C:\Deploy\Apps\7zip.exe /S" -NoNewWindow -Wait

Write-Host -ForegroundColor Yellow -Object "Installation Adobe"
Start-Process -FilePath "C:\Deploy\Apps\Adobe.exe /sAll /rs /msi EULA_ACCEPT=YES" -NoNewWindow -Wait

Write-Host -ForegroundColor Yellow -Object "Installation Chrome"
Start-Process -FilePath "C:\Windows\System32\MsiExec.exe /i C:\Deploy\Apps\Chrome.msi /qn" -NoNewWindow -Wait

Copy-Item -Path "C:\Deploy\Public\*" -Destination "C:\Users\Public\Desktop" -Recurse

While (Get-Process OfficeSetup -ErrorAction SilentlyContinue)
{
  Write-Host -ForegroundColor Yellow -Object "L'instalation d'Office est toujours en cours."
  Start-Sleep -Seconds 5
}

Write-Host -ForegroundColor Yellow -Object "Fermeture d'Office en cours."
TASKKILL /F /IM OfficeC2RClient.exe

shutdown -r -t 5
Set-Location C:\
C:\Deploy\Clean.lnk