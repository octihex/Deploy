cls

function Clean 
{
  Write-Host -Object "OK"
}

Clean









<#
if (!(Get-Content -Path C:\Deploy\Check-Install.txt -ErrorAction SilentlyContinue))
{
  Write-Host -Object "NOK"
}
if (Get-Content -Path C:\Deploy\Check-Install.txt -ErrorAction SilentlyContinue)
{
  Write-Host -Object "OK"
}






if ((Get-Content -Path C:\Deploy\Check-Install.txt)[-1] -eq "test2")
{
  Write-Host -Object "test"
}
elseif ((Get-Content -Path C:\Deploy\Check-Install.txt)[-1] -eq "RenameOK") 
{
  Write-Host -Object "rename"
}
else
{

  Write-Host -Object "no"
}



$newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"

if (Select-String -InputObject $newNamePc -Pattern liblap)
{
  Write-Host -Object "1"
}
elseif (Select-String -InputObject $newNamePc -Pattern libdes) 
{ 
  Write-Host -Object "2"
}
elseif (Select-String -InputObject $newNamePc -Pattern libol) 
{ 
  Write-Host -Object "3"
}
elseif (Select-String -InputObject $newNamePc -Pattern libod) 
{ 
  Write-Host -Object "4"
}
else 
{
  Write-Host -Object "5"
}
Pause
#>
