$DeployPath = "C:\Deploy"

Function TestFunc 
{
    Start-Process -FilePath "$DeployPath\Apps\DCU_4.6.0.exe" -ArgumentList "/s /l=$DeployPath\DCU_Install_Log.txt" -NoNewWindow -Wait
    $Testvar = (Select-String -Path "$DeployPath\DCU_Install_Log.txt" -Pattern 'Name of Exit Code:')
    if (!$Testvar) 
    { 
        Write-Host -Object "Loop"
        Start-Sleep -Seconds 5
        TestFunc
    }
    
    if ($Testvar) 
    { 
      if ((($Testvar | Select-Object -First 1).Line.Split(' ')[-1]) -eq "SUCCESS") 
      {
        Write-Host -Object "OK"
      }

        if (!((($Testvar | Select-Object -First 1).Line.Split(' ')[-1]) -eq "SUCCESS")) 
        {
            Write-Host -Object "NOK"
        }
    }
}

TestFunc
