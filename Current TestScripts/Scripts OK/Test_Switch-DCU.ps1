$CheckInstallDCU = (Select-String -Path "C:\Deploy\DCU_Install_Log.txt" -Pattern 'Name of Exit Code:')
$ArrDCUCode = "SUCCESS", "REBOOT_REQUIRED"

If (!($ArrDCUCode -eq (($CheckInstallDCU | Select-Object -First 1).Line.Split(' ')[-1])))
{
    Write-Host -ForegroundColor Yellow -Object "NOK"
}

If ($ArrDCUCode -eq (($CheckInstallDCU | Select-Object -First 1).Line.Split(' ')[-1]))
{
    Write-Host -ForegroundColor Yellow -Object "OK"
}