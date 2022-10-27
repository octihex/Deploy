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

#------------------------------------------------------------------------------------------------------------------

function Test-ADAuthentication {
    Param(
        [Parameter(Mandatory)]
        [string]$User,
        [Parameter(Mandatory)]
        $Password,
        [Parameter(Mandatory = $false)]
        $Server,
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDOMAIN
    )
  
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    
    $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    
    $argumentList = New-Object -TypeName "System.Collections.ArrayList"
    $null = $argumentList.Add($contextType)
    $null = $argumentList.Add($Domain)
    if($null -ne $Server){
        $argumentList.Add($Server)
    }
    
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $argumentList -ErrorAction SilentlyContinue
    if ($null -eq $principalContext) {
        Write-Warning "$Domain\$User - AD Authentication failed"
    }
    
    if ($principalContext.ValidateCredentials($User, $Password)) {
        Write-Host -ForegroundColor green "$Domain\$User - AD Authentication OK"
    }
    else {
        Write-Warning "$Domain\$User - AD Authentication failed"
    }
}
#Test-ADAuthentication -User toto -Password passXX
#Test-ADAuthentication -User toto -Password passXX -Server xxx.domain.com