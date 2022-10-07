foreach ($line in (Get-CimInstance -ClassName Win32_ComputerSystem).manufacturer)
{
    $Manufacturer = ($line.Split(" "))[0]
}

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