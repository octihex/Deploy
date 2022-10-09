<#

$UserName = 'xxxx'
$Password = 'yyyy'

Function Test-ADAuthentication {
    param(
        $username,
        $password)
    
    (New-Object DirectoryServices.DirectoryEntry "",$username,$password).psbase.name -ne $null
}

Test-ADAuthentication -username $UserName -password $password

-------------------------------------------------------------------------------------------------------------

$Testvar = Get-Credential
$User = $Testvar.UserName
$Pass = $Testvar.Password


(New-Object DirectoryServices.DirectoryEntry "",$username,$password).psbase.name -ne $null

#>

#-------------------------------------------------------------------------------------------------------------

<#

$testvar = Get-Credential

try 
{ 
    Start-Process notepad.exe -Credential $testvar 
}

catch 
{ 
    ""
}

If (((Get-Process Notepad -IncludeUserName).UserName).Split('\')[-1] -eq $Testvar.UserName) 
{
    Write-Host -Object "OK"
}

If (!(((Get-Process Notepad -IncludeUserName).UserName).Split('\')[-1] -eq $Testvar.UserName)) 
{
    Write-Host -Object "NOK"
}

#>

#-------------------------------------------------------------------------------------------------------------

$Testvar = Get-Credential
New-PSDrive -Name "K" -PSProvider "FileSystem" -Root "\\FS11LIB1FR\Logiciels" -Persist -Credential $testvar
#Test si user a l'accès avec une cible fixe
Test-Path -PathType leaf -Path "\\DESKTOP-2RI7D9E\Desktop\Cemu.lnk" -ErrorAction SilentlyContinue
#Ou
test-path -PathType container K:\