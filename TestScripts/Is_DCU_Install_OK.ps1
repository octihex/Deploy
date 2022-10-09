$DeployPath = "C:\Deploy"

Function TestFunc 
{
	$host.UI.RawUI.WindowTitle = "Installation Poste - Etape 3 - MAJ Dell"
    Clear-Host
	if (!(Test-Path -PathType leaf -Path "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe")) 
    {
        Start-Process -FilePath "$DeployPath\Apps\DCU_4.6.0.exe" -ArgumentList "/s /l=$DeployPath\DCU_Install_Log.txt" -NoNewWindow -Wait
    	$Testvar = (((Select-String -Path "$DeployPath\DCU_Install_Log.txt" -Pattern 'Name of Exit Code:') | Select-Object -First 1).Line.Split(' ')[-1])
		#Faire catch erreur avec redispatch
    	if (!$Testvar) 
    	{ 
        	Write-Host -ForegroundColor Yellow -Object "Installation de Dell Command Update en cours."
        	Start-Sleep -Seconds 5
        	TestFunc
    	}

      	if ($Testvar -eq "SUCCESS") 
      	{
        	#Install OK - faire truc
      	}

        if (!($Testvar -eq "SUCCESS"))
        {
            #Install pas OK - faire truc
        }
    }
}

TestFunc
