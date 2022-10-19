#check si dans le domaine OK
If (!((Get-CimInstance -ClassName Win32_ComputerSystem).domain -eq "ceva.net")) 
{
    "OK Domaine"
}

#check si toutes maj Windows OK
Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E2_MAJ-Windows.ps1" -NoNewWindow -Wait

#check si toutes maj Dell OK
Start-Process Powershell -ArgumentList "-ExecutionPolicy Unrestricted $DeployPath\Scripts\E3_MAJ-Dell.ps1" -NoNewWindow -Wait

#check si toutes apps OK
#Faire listing des apps a l'installation