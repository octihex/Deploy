<#
While (!$Testvar) 
{ 
    Clear-Host
    $Testvar = (Select-String -Path "C:\Deploy\DCU_Install_Log.txt" -Pattern 'Name of Exit Code:')
    Write-Host -ForegroundColor Yellow -Object "Installation de Dell Command Update en cours."
    Start-Sleep -Seconds 5   
}

if ((($Testvar | Select-Object -First 1).Line.Split(' ')[-1]) -eq "SUCCESS") 
{
    #Install OK - faire truc
    Write-Host -ForegroundColor Yellow -Object "OK"
}

Else 
{
    #Install pas OK - faire truc
    Write-Host -ForegroundColor Yellow -Object "NOK"
}
#>

$DeployPath = "C:\Deploy"
Switch ((Get-Content -Path $DeployPath\Check-Install.txt)[-1]) 
{
    {$_ -eq "TestOK1"} 
    {  
        Write-Host -ForegroundColor Yellow -Object "OK1"
    }

    {$_ -eq "TestOK2"}
    {
        Write-Host -ForegroundColor Yellow -Object "OK2"
    }

    Default 
    {
        Write-Host -ForegroundColor Yellow -Object "Nope"
    }
}