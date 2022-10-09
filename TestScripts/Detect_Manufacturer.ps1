$Manufacturer = ((Get-CimInstance -ClassName Win32_ComputerSystem).manufacturer).Split(' ')[0]

if (Select-String -InputObject $Manufacturer -Pattern Lenovo) 
{
    Write-Host -Object "Lenovo PC"
}

elseif (Select-String -InputObject $Manufacturer -Pattern Dell) 
{
    Write-Host -Object "Dell PC"
}

else 
{
    Write-Host -Object "Nope"
}