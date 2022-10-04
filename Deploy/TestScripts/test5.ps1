Function TestFunc 
{
    $testvar = (Select-String -Path 'C:\Deploy\DCU_Install_Log.txt' -Pattern 'Name of Exit Code:')
    if (!$testvar) 
    { 
        Write-Host -Object "Loop"
        Start-Sleep -Seconds 5
        TestFunc
    }
    
    if ($testvar) 
    { 
        #$testvar = ($testvar | select-object -First 1).Line.split(' ')[-1]

        if ((($testvar | select-object -First 1).Line.split(' ')[-1]) -eq "SUCCESS") 
        {
            Write-Host -Object "OK"
        }

        if (!((($testvar | select-object -First 1).Line.split(' ')[-1]) -eq "SUCCESS")) 
        {
            Write-Host -Object "NOK"
        }
    }
}

TestFunc
